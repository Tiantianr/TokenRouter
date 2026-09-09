package securityaudit

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	infraerrors "github.com/TokenFlux/TokenRouter/internal/pkg/errors"
)

var ErrPromptAnalysisUnavailable = infraerrors.ServiceUnavailable(
	"prompt_audit_analysis_unavailable", "用户分析服务暂时不可用")

// AnalyzeEvent analyzes only the session attached to the selected event. It
// never broadens the query to the user's other sessions.
func (s *PromptService) AnalyzeEvent(ctx context.Context, eventID int64) (*UserAnalysis, error) {
	if s == nil || s.repo == nil {
		return nil, ErrPromptAnalysisUnavailable
	}
	session, err := s.repo.GetSessionChatRecords(ctx, eventID, maxUserAnalysisRecords)
	if err != nil {
		if errors.Is(err, ErrEventNotFound) {
			return nil, infraerrors.NotFound("prompt_audit_event_not_found", "提示词审计事件不存在")
		}
		return nil, ErrPromptAnalysisUnavailable
	}
	if session.UserID <= 0 || strings.TrimSpace(session.SessionKey) == "" || len(session.Records) == 0 {
		return nil, infraerrors.NotFound("prompt_audit_chat_records_not_found", "该会话暂无可分析的聊天记录")
	}
	analyzer, ok := s.scanner.(PromptAnalyzer)
	if !ok || analyzer == nil {
		return nil, ErrPromptAnalysisUnavailable
	}
	if s.config == nil {
		return nil, ErrPromptAnalysisUnavailable
	}
	cfg, ok := s.config.Active()
	if !ok {
		return nil, ErrPromptAnalysisUnavailable
	}
	endpoints := cfg.EnabledEndpoints()
	if len(endpoints) == 0 {
		return nil, ErrPromptAnalysisUnavailable
	}
	if s.evaluator != nil {
		select {
		case s.evaluator.global <- struct{}{}:
			defer func() { <-s.evaluator.global }()
		default:
			return nil, ErrPromptAnalysisUnavailable
		}
	}
	transcript, analyzedRecords := buildBoundedUserAnalysisTranscript(session.Records, session.SelectedRecordID)
	if strings.TrimSpace(transcript) == "" {
		return nil, infraerrors.NotFound("prompt_audit_chat_records_not_found", "该会话暂无可分析的聊天记录")
	}
	for _, endpoint := range endpoints {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var semaphore chan struct{}
		if s.evaluator != nil {
			semaphore = s.evaluator.nodeSemaphore(endpoint.ID)
			select {
			case semaphore <- struct{}{}:
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				continue
			}
		}
		timeout := time.Duration(endpoint.TimeoutMS) * time.Millisecond
		if timeout <= 0 {
			timeout = DefaultTimeoutMS * time.Millisecond
		}
		attemptCtx, cancel := context.WithTimeout(ctx, timeout)
		report, scanErr := callPromptAnalyzer(attemptCtx, analyzer, endpoint, transcript)
		cancel()
		if semaphore != nil {
			<-semaphore
		}
		if scanErr != nil || strings.TrimSpace(report) == "" {
			continue
		}
		first, last := analyzedRecords[0].CreatedAt, analyzedRecords[0].CreatedAt
		for _, record := range analyzedRecords[1:] {
			if record.CreatedAt.Before(first) {
				first = record.CreatedAt
			}
			if record.CreatedAt.After(last) {
				last = record.CreatedAt
			}
		}
		return &UserAnalysis{
			UserID: session.UserID, Username: session.Username, UserEmail: session.UserEmail,
			SessionKey: session.SessionKey, SessionSource: session.SessionSource,
			RecordCount: len(analyzedRecords), FirstRecordAt: first, LastRecordAt: last,
			GuardEndpointID: endpoint.ID, GuardEndpointName: endpoint.Name, GuardModel: endpoint.Model,
			GeneratedAt: time.Now().UTC(), Report: report,
		}, nil
	}
	return nil, ErrPromptAnalysisUnavailable
}

func callPromptAnalyzer(ctx context.Context, analyzer PromptAnalyzer, endpoint ActiveEndpoint, transcript string) (report string, err error) {
	defer func() {
		if recover() != nil {
			report = ""
			err = ErrPromptAnalysisUnavailable
		}
	}()
	return analyzer.Analyze(ctx, endpoint, transcript)
}

func buildUserAnalysisTranscript(records []UserChatRecord) string {
	transcript, _ := buildBoundedUserAnalysisTranscript(records, 0)
	return transcript
}

func buildBoundedUserAnalysisTranscript(records []UserChatRecord, selectedRecordID int64) (string, []UserChatRecord) {
	if len(records) == 0 {
		return "", nil
	}
	ordered := append([]UserChatRecord(nil), records...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].CreatedAt.Before(ordered[j].CreatedAt)
	})
	previousPrompt := ""
	for index := range ordered {
		prompt := strings.TrimSpace(ordered[index].FullPrompt)
		if ordered[index].ID != selectedRecordID && previousPrompt != "" && strings.HasPrefix(prompt, previousPrompt+"\n\n") {
			ordered[index].FullPrompt = strings.TrimSpace(strings.TrimPrefix(prompt, previousPrompt))
		}
		previousPrompt = prompt
	}
	priority := make([]UserChatRecord, 0, len(ordered))
	if selectedRecordID > 0 {
		for _, record := range ordered {
			if record.ID == selectedRecordID {
				priority = append(priority, record)
				break
			}
		}
	}
	for index := len(ordered) - 1; index >= 0; index-- {
		if selectedRecordID > 0 && ordered[index].ID == selectedRecordID {
			continue
		}
		priority = append(priority, ordered[index])
	}
	included := make([]UserChatRecord, 0, len(priority))
	remaining := maxUserAnalysisRunes
	for _, record := range priority {
		prompt := strings.TrimSpace(record.FullPrompt)
		if prompt == "" || remaining <= 0 {
			continue
		}
		header := analysisRecordHeader(record)
		headerRunes := len([]rune(header))
		if headerRunes >= remaining {
			break
		}
		prompt = trimRunesWithin(prompt, remaining-headerRunes)
		record.FullPrompt = prompt
		included = append(included, record)
		remaining -= headerRunes + len([]rune(prompt))
	}
	sort.SliceStable(included, func(i, j int) bool {
		return included[i].CreatedAt.Before(included[j].CreatedAt)
	})
	var builder strings.Builder
	for _, record := range included {
		_, _ = builder.WriteString(analysisRecordHeader(record))
		_, _ = builder.WriteString(record.FullPrompt)
	}
	return builder.String(), included
}

func analysisRecordHeader(record UserChatRecord) string {
	return "\n\n--- chat record " + strconv.FormatInt(record.ID, 10) + " at " + record.CreatedAt.UTC().Format(time.RFC3339) + " ---\n"
}

func trimRunesWithin(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	if limit == 1 {
		return "…"
	}
	return string(runes[:limit-1]) + "…"
}
