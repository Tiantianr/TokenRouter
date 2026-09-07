package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/TokenFlux/TokenRouter/internal/auditcontent"
	"github.com/TokenFlux/TokenRouter/internal/openaiwire"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

type openAIHistoryContextKey struct{}

// 从实际鉴权 Key 获取调用者，不接受入站 JSON 自报用户标识。
func getAPIKeyUserIDFromContext(c *gin.Context) int64 {
	v, _ := c.Get("api_key")
	key, _ := v.(*APIKey)
	if key == nil {
		return 0
	}
	if key.UserID == 0 && key.User != nil {
		return key.User.ID
	}
	return key.UserID
}

func isOpenAIAccountSelectionUnavailable(err error) bool {
	return err == nil || errors.Is(err, ErrNoAvailableAccounts) || errors.Is(err, ErrNoAvailableCompactAccounts)
}

// 重试不得改变原始归属；route只是当前请求写入的CAS游标，不能授权候选。
type openAIHistoryAdmission struct {
	mu              sync.Mutex
	lookupOnce      sync.Once
	service         *OpenAIGatewayService
	userID          int64
	apiKeyID        int64
	groupID         int64
	sessionHash     string
	previousID      string
	history         bool
	readOnly        bool
	oauthConsidered bool
	owner           *OpenAIConversationBinding
	route           *OpenAIConversationBinding
	err             error
	denied          map[int64]string
	responses       map[string]bool
	parents         map[int64]*Account
}

func openAIHistoryFromContext(ctx context.Context) *openAIHistoryAdmission {
	if ctx == nil {
		return nil
	}
	state, _ := ctx.Value(openAIHistoryContextKey{}).(*openAIHistoryAdmission)
	return state
}

func ContextWithOpenAIHistory(ctx, source context.Context) context.Context {
	if state := openAIHistoryFromContext(source); state != nil {
		return context.WithValue(ctx, openAIHistoryContextKey{}, state)
	}
	return ctx
}

func openAIHistoryTurnContext(ctx context.Context, hooks *OpenAIWSIngressHooks) context.Context {
	if hooks != nil && hooks.HistoryContext != nil {
		return ContextWithOpenAIHistory(ctx, hooks.HistoryContext())
	}
	return ctx
}

// 在已鉴权审核的原协议输入上分类，替换WS轮次状态，不改写原正文。
// @project-doc docs/domains/openai_history_admission.md#history_classification
func (s *OpenAIGatewayService) PrepareOpenAIHistoryRequest(c *gin.Context, protocol string, body []byte, sessionHash string, readOnly ...bool) error {
	if s == nil || c == nil || c.Request == nil {
		return ErrOpenAIHistoryUnavailable
	}
	classificationBody := body
	if protocol == ContentModerationProtocolOpenAIResponses {
		if normalized, changed := openaiwire.NormalizeCodexAutomationBootstrap(classificationBody); changed {
			classificationBody = normalized
		}
		if normalized, changed := openaiwire.NormalizeCodexDelegationBootstrap(classificationBody); changed {
			classificationBody = normalized
		}
	}
	document, err := auditcontent.Extract(protocol, classificationBody)
	if err != nil {
		return fmt.Errorf("classify conversation history: %w", err)
	}
	previousID := strings.TrimSpace(openAIRequestPayloadView(body).Get("previous_response_id").String())
	state := &openAIHistoryAdmission{
		service: s, userID: getAPIKeyUserIDFromContext(c), apiKeyID: getAPIKeyIDFromContext(c),
		groupID: getOpenAIGroupIDFromContext(c), sessionHash: sessionHash, previousID: previousID,
		history: document.HistoryBearing || document.Incomplete || previousID != "",
		denied:  make(map[int64]string), responses: make(map[string]bool), parents: make(map[int64]*Account),
	}
	state.readOnly = len(readOnly) > 0 && readOnly[0]
	c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), openAIHistoryContextKey{}, state))
	SetOpenAIHTTPResponseOwner(c, state.userID, state.apiKeyID)
	return nil
}

func (state *openAIHistoryAdmission) load(ctx context.Context) {
	state.lookupOnce.Do(func() {
		state.mu.Lock()
		defer state.mu.Unlock()
		if state.userID <= 0 || state.apiKeyID <= 0 {
			state.err = ErrOpenAIHistoryUnavailable
			return
		}
		repo := state.service.conversationBindingRepository()
		if repo == nil {
			state.err = ErrOpenAIHistoryUnavailable
			return
		}
		lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		kind, identifier := "session", state.sessionHash
		if state.previousID != "" {
			kind, identifier = "response", state.previousID
		}
		if identifier == "" {
			return
		}
		state.owner, state.err = state.service.lookupOpenAIHistoryBinding(lookupCtx, state.userID, state.groupID, kind, identifier)
		if state.err != nil {
			slog.WarnContext(ctx, "history_binding_lookup_failed", "error", state.err)
			return
		}
		if state.owner != nil && state.owner.Confirmed {
			state.history = true
		}
		if kind == "session" {
			state.route = state.owner
		}
	})
}

func (s *OpenAIGatewayService) lookupOpenAIHistoryBinding(ctx context.Context, userID, groupID int64, kind, identifier string) (*OpenAIConversationBinding, error) {
	repo := s.conversationBindingRepository()
	if repo == nil {
		return nil, ErrOpenAIHistoryUnavailable
	}
	// TokenRouter 不具备 Plus 跨组共享权限，不以短期粘性缓存补造长期归属。
	return repo.GetOpenAIConversationBinding(ctx, userID, groupID, kind, openAIConversationBindingKey(identifier))
}

func openAIHistoryCandidateFailureReason(ctx context.Context, account *Account) string {
	state := openAIHistoryFromContext(ctx)
	if state == nil || account == nil || !account.IsOpenAIOAuth() {
		return ""
	}
	state.mu.Lock()
	state.oauthConsidered = true
	state.mu.Unlock()
	state.load(ctx)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.err != nil {
		return "history_binding_lookup_failed"
	}
	policyAccount := account
	ownerID := account.ID
	if account.IsCredentialShadow() && account.ParentAccountID != nil {
		ownerID = *account.ParentAccountID
		parent := state.parents[ownerID]
		if parent == nil {
			var err error
			parent, err = state.service.accountRepo.GetByID(ctx, ownerID)
			if err != nil || parent == nil || !parent.IsOpenAIOAuth() {
				state.err = ErrOpenAIHistoryUnavailable
				return "history_binding_lookup_failed"
			}
			state.parents[ownerID] = parent
		}
		policyAccount = parent
	}
	if !state.history || !policyAccount.IsOpenAIOAuthRejectExternalHistoryEnabled() {
		return ""
	}
	if state.owner != nil && state.owner.Valid && state.owner.Confirmed && state.owner.CredentialOwnerAccountID == ownerID {
		if openAIHistoryBindingMatchesIdentity(state.owner, policyAccount) {
			return ""
		}
		// 轻量或陈旧快照不能证明凭据身份，等待或重试时重新读取母账号。
		latest, err := state.service.accountRepo.GetByID(ctx, ownerID)
		if err != nil || latest == nil {
			state.err = ErrOpenAIHistoryUnavailable
			return "history_binding_lookup_failed"
		}
		if !latest.IsOpenAIOAuthRejectExternalHistoryEnabled() || openAIHistoryBindingMatchesIdentity(state.owner, latest) {
			return ""
		}
	}
	reason := "history_owner_missing"
	if state.owner != nil && !state.owner.Confirmed {
		reason = "history_owner_unconfirmed"
	} else if state.owner != nil && state.owner.Valid {
		reason = "history_owner_mismatch"
	}
	if _, exists := state.denied[account.ID]; !exists {
		slog.InfoContext(ctx, reason, "account_id", account.ID)
		state.denied[account.ID] = reason
	}
	return reason
}

func openAIHistoryBindingMatchesIdentity(binding *OpenAIConversationBinding, account *Account) bool {
	if binding == nil || account == nil || !account.IsOpenAIOAuth() {
		return false
	}
	return binding.OAuthAccountID == account.GetCredential("chatgpt_account_id") &&
		binding.OAuthUserID == account.GetCredential("chatgpt_user_id")
}

func openAIHistorySelectionError(ctx context.Context, err error) error {
	state := openAIHistoryFromContext(ctx)
	if state == nil || !isOpenAIAccountSelectionUnavailable(err) {
		return err
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.oauthConsidered {
		return err
	}
	if state.err != nil {
		return fmt.Errorf("%w: %w", ErrOpenAIHistoryUnavailable, state.err)
	}
	if len(state.denied) > 0 {
		slog.InfoContext(ctx, "history_policy_candidates_exhausted", "filtered_accounts", len(state.denied))
		return ErrOpenAIExternalHistory
	}
	return err
}

func openAIHistoryStickyAccountID(ctx context.Context, sessionHash string) int64 {
	state := openAIHistoryFromContext(ctx)
	if state == nil {
		return 0
	}
	state.load(ctx)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.owner != nil && state.owner.Valid && state.err == nil &&
		(state.previousID == "" || state.owner.Confirmed) &&
		(state.previousID != "" || state.sessionHash == sessionHash) {
		return state.owner.AccountID
	}
	return 0
}

func (s *OpenAIGatewayService) newOpenAIHistoryBinding(ctx context.Context, state *openAIHistoryAdmission, account *Account, kind, identifier string) (*OpenAIConversationBinding, error) {
	owner := account
	if account.IsCredentialShadow() && account.ParentAccountID != nil {
		var err error
		owner, err = s.accountRepo.GetByID(ctx, *account.ParentAccountID)
		if err != nil || owner == nil || !owner.IsOpenAIOAuth() {
			return nil, ErrOpenAIHistoryUnavailable
		}
	}
	return &OpenAIConversationBinding{
		UserID: state.userID, APIKeyID: state.apiKeyID, ScopeGroupID: state.groupID,
		Type: kind, Key: openAIConversationBindingKey(identifier), AccountID: account.ID,
		CredentialOwnerAccountID: owner.ID, OAuthAccountID: owner.GetCredential("chatgpt_account_id"),
		OAuthUserID: owner.GetCredential("chatgpt_user_id"),
	}, nil
}

// 候选准入后、转发前提交长期路由，不依赖调度器尽力写入的Redis粘性。
func (s *OpenAIGatewayService) CommitOpenAIHistoryRoute(ctx context.Context, account *Account) error {
	state := openAIHistoryFromContext(ctx)
	if state == nil || account == nil || !account.IsOpenAIOAuth() {
		return nil
	}
	if reason := openAIHistoryCandidateFailureReason(ctx, account); reason != "" {
		if reason == "history_binding_lookup_failed" {
			return ErrOpenAIHistoryUnavailable
		}
		return ErrOpenAIExternalHistory
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.sessionHash == "" || state.readOnly {
		return nil
	}
	writeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	binding, err := s.newOpenAIHistoryBinding(writeCtx, state, account, "session", state.sessionHash)
	if err != nil {
		return err
	}
	repo := s.conversationBindingRepository()
	if repo == nil {
		return ErrOpenAIHistoryUnavailable
	}
	if state.route == nil && state.previousID != "" {
		state.route, err = repo.GetOpenAIConversationBinding(writeCtx, state.userID, binding.ScopeGroupID, binding.Type, binding.Key)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrOpenAIHistoryUnavailable, err)
		}
	}
	expectedRevision := int64(0)
	if state.route != nil && state.route.ScopeGroupID == binding.ScopeGroupID {
		expectedRevision = state.route.Revision
	}
	saved, err := repo.SaveOpenAIConversationBinding(writeCtx, binding, expectedRevision)
	if err != nil {
		if errors.Is(err, ErrOpenAIHistoryConflict) {
			return err
		}
		return fmt.Errorf("%w: %w", ErrOpenAIHistoryUnavailable, err)
	}
	state.route = saved
	return nil
}

// 响应ID先预占，成功终态才确认response并复核session预占，不能用创建事件授权历史。
// @project-doc docs/domains/openai_history_admission.md#reservation_confirmation
func (s *OpenAIGatewayService) persistOpenAIHistoryResponse(ctx context.Context, account *Account, responseID string, confirmed ...bool) error {
	state := openAIHistoryFromContext(ctx)
	responseID = strings.TrimSpace(responseID)
	if state == nil || state.readOnly || account == nil || !account.IsOpenAIOAuth() || responseID == "" {
		return nil
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	key := fmt.Sprintf("%d:%s", account.ID, responseID)
	confirm := len(confirmed) > 0 && confirmed[0] && strings.HasPrefix(responseID, "resp_")
	if wasConfirmed, exists := state.responses[key]; exists && (wasConfirmed || !confirm) {
		return nil
	}
	writeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	binding, err := s.newOpenAIHistoryBinding(writeCtx, state, account, "response", responseID)
	if err != nil {
		return err
	}
	repo := s.conversationBindingRepository()
	if repo == nil {
		return ErrOpenAIHistoryUnavailable
	}
	binding.Confirmed = confirm
	if _, err := repo.SaveOpenAIConversationBinding(writeCtx, binding, 0); err != nil {
		slog.WarnContext(ctx, "history_binding_write_failed", "account_id", account.ID, "error", err)
		return fmt.Errorf("%w: %w", ErrOpenAIHistoryUnavailable, err)
	}
	if confirm && state.sessionHash != "" {
		// 只确认当前预占；延迟响应不能确认已切到另一账号或身份的新预占。
		if state.route == nil || state.route.AccountID != account.ID ||
			state.route.CredentialOwnerAccountID != binding.CredentialOwnerAccountID ||
			state.route.OAuthAccountID != binding.OAuthAccountID || state.route.OAuthUserID != binding.OAuthUserID {
			return ErrOpenAIHistoryConflict
		}
		reservation := *state.route
		reservation.Confirmed = true
		saved, err := repo.SaveOpenAIConversationBinding(writeCtx, &reservation, reservation.Revision)
		if err != nil {
			if errors.Is(err, ErrOpenAIHistoryConflict) {
				return err
			}
			return fmt.Errorf("%w: %w", ErrOpenAIHistoryUnavailable, err)
		}
		state.route = saved
	}
	state.responses[key] = confirm
	return nil
}

func (s *OpenAIGatewayService) persistOpenAIHistoryResponsePayload(ctx context.Context, account *Account, payload []byte) error {
	if openAIHistoryFromContext(ctx) == nil || account == nil || !account.IsOpenAIOAuth() {
		return nil
	}
	if !bodyHasSSEFraming(payload) {
		return s.persistOpenAIHistoryResponse(ctx, account, extractOpenAIResponseIDFromJSONBytes(payload), openAIHistoryResponseCompleted(payload))
	}
	var bindErr error
	forEachOpenAISSEFrame(string(payload), func(_ string, data []byte) {
		if bindErr == nil {
			bindErr = s.persistOpenAIHistoryResponsePayload(ctx, account, data)
		}
	})
	return bindErr
}

// 仅成功完成的Response对象或完成事件可以确认，创建事件和部分输出不构成证据。
func openAIHistoryResponseCompleted(payload []byte) bool {
	if !gjson.ValidBytes(payload) {
		return false
	}
	root := gjson.ParseBytes(payload)
	response := root
	kind := root.Get("type").String()
	if kind != "" {
		if kind != "response.completed" && kind != "response.done" {
			return false
		}
		response = root.Get("response")
	}
	if !strings.HasPrefix(response.Get("id").String(), "resp_") || root.Get("error").Exists() && root.Get("error").Type != gjson.Null {
		return false
	}
	if err := response.Get("error"); err.Exists() && err.Type != gjson.Null {
		return false
	}
	status := response.Get("status")
	if status.Exists() {
		return status.Type == gjson.String && status.String() == "completed"
	}
	return kind == "response.completed" || kind == "response.done"
}

// 每轮复查当前持久配置，包括不会调用普通BeforeTurn的WS透传模式。
func (s *OpenAIGatewayService) ValidateOpenAIHistoryTurn(ctx context.Context, account *Account) error {
	state := openAIHistoryFromContext(ctx)
	if state == nil || account == nil || !account.IsOpenAIOAuth() {
		return nil
	}
	latest, err := s.accountRepo.GetByID(ctx, account.ID)
	if err != nil || latest == nil {
		return ErrOpenAIHistoryUnavailable
	}
	if latest.IsCredentialShadow() && latest.ParentAccountID != nil {
		state.mu.Lock()
		delete(state.parents, *latest.ParentAccountID)
		state.mu.Unlock()
	}
	return s.CommitOpenAIHistoryRoute(ctx, latest)
}
