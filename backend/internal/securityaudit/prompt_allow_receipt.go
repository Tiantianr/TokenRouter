package securityaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const allowReceiptOperationTimeout = 75 * time.Millisecond
const allowReceiptSchemaVersion = 2

var allowReceiptUserMediaMarker = regexp.MustCompile(`(?i)\[images:([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\]`)

type allowReceiptPolicy struct {
	SchemaVersion int                    `json:"schema_version"`
	ConfigVersion int64                  `json:"config_version"`
	Scanners      []string               `json:"scanners"`
	Endpoints     []allowReceiptEndpoint `json:"endpoints"`
}

type allowReceiptEndpoint struct {
	ID         string `json:"id"`
	Protocol   string `json:"protocol"`
	Model      string `json:"model"`
	TimeoutMS  int    `json:"timeout_ms"`
	InputLimit int    `json:"input_limit"`
}

type allowReceiptCommit struct {
	ConfigVersion int64
	Snapshot      PromptSnapshot
}

func prepareAllowReceipts(ctx context.Context, store AllowReceiptStore, metrics Metrics, cfg ActiveConfig, snapshot *PromptSnapshot, trustedKeys []string, bypass bool) {
	if snapshot == nil || len(snapshot.ReviewSegments) == 0 {
		return
	}
	trusted := make(map[string]struct{}, len(trustedKeys))
	for _, key := range trustedKeys {
		if validAllowReceiptKey(key) {
			trusted[key] = struct{}{}
		}
	}
	keys := make([]string, len(snapshot.ReviewSegments))
	hits := make([]bool, len(keys))
	lookupIndexes := make([]int, 0, len(keys))
	lookupKeys := make([]string, 0, len(keys))
	reuseCurrent := cfg.EffectiveMode() == ModeBlocking
	for index, segment := range snapshot.ReviewSegments {
		keys[index] = buildAllowReceiptKey(cfg, segment.Source, segment.Text)
		if bypass || keys[index] == "" || snapshot.UserID <= 0 {
			continue
		}
		if _, ok := trusted[keys[index]]; ok {
			hits[index] = true
			continue
		}
		if store == nil || (segment.CurrentUser && !reuseCurrent) {
			continue
		}
		lookupIndexes = append(lookupIndexes, index)
		lookupKeys = append(lookupKeys, keys[index])
	}
	var err error
	if len(lookupKeys) > 0 {
		lookupCtx, cancel := context.WithTimeout(ctx, allowReceiptOperationTimeout)
		var lookupHits []bool
		lookupHits, err = store.ReceiptsAllowed(lookupCtx, snapshot.UserID, lookupKeys)
		cancel()
		if err == nil && len(lookupHits) != len(lookupKeys) {
			err = context.Canceled
		}
		if err == nil {
			for index, hit := range lookupHits {
				hits[lookupIndexes[index]] = hit
			}
		}
	}
	status := "miss"
	if err != nil {
		status = "error"
		if metrics != nil {
			metrics.IncAllowReceiptError()
		}
		logAllowReceiptFailure(*snapshot, "lookup", "allow_receipt_lookup_failed")
	}
	missedSegments := make([]PromptReviewSegment, 0, len(keys))
	missedKeys := make([]string, 0, len(keys))
	hitCount := 0
	for index, hit := range hits {
		if hit {
			hitCount++
			if metrics != nil {
				metrics.IncAllowReceiptHit()
			}
			continue
		}
		missedSegments = append(missedSegments, snapshot.ReviewSegments[index])
		if keys[index] != "" {
			missedKeys = append(missedKeys, keys[index])
		}
		if !bypass && err == nil && store != nil && metrics != nil {
			metrics.IncAllowReceiptMiss()
		}
	}
	if bypass {
		status = "bypassed"
	} else if err == nil {
		switch {
		case hitCount == len(keys):
			status = "hit"
		case hitCount > 0:
			status = "partial_hit"
		}
	}
	snapshot.AllowReceiptKeys = missedKeys
	snapshot.AllowReceiptHitCount = hitCount
	applyAllowReceiptSelection(snapshot, missedSegments)
	updateCompleteContextAllowReceipts(snapshot, status, hitCount, len(missedSegments))
}

func storeAllowReceipts(ctx context.Context, store AllowReceiptStore, metrics Metrics, cfg ActiveConfig, snapshot PromptSnapshot) {
	if store == nil || snapshot.UserID <= 0 || len(snapshot.AllowReceiptKeys) == 0 {
		return
	}
	ttlSeconds := cfg.AllowReceiptTTLSeconds
	if ttlSeconds <= 0 {
		ttlSeconds = DefaultAllowReceiptTTLSeconds
	}
	ttl := time.Duration(ttlSeconds) * time.Second
	storeCtx, cancel := context.WithTimeout(ctx, allowReceiptOperationTimeout)
	err := store.StoreAllowReceipts(storeCtx, snapshot.UserID, snapshot.AllowReceiptKeys, ttl)
	cancel()
	if err != nil {
		if metrics != nil {
			metrics.IncAllowReceiptError()
		}
		logAllowReceiptFailure(snapshot, "store", "allow_receipt_store_failed")
		return
	}
	if metrics != nil {
		for range snapshot.AllowReceiptKeys {
			metrics.IncAllowReceiptWrite()
		}
	}
}

func buildAllowReceiptKey(cfg ActiveConfig, source, text string) string {
	if cfg.ConfigVersion < 1 || strings.TrimSpace(source) == "" || strings.TrimSpace(text) == "" {
		return ""
	}
	policy := allowReceiptPolicy{
		SchemaVersion: allowReceiptSchemaVersion,
		ConfigVersion: cfg.ConfigVersion,
		Scanners:      append([]string(nil), cfg.Scanners...),
		Endpoints:     make([]allowReceiptEndpoint, 0, len(cfg.Endpoints)),
	}
	for _, endpoint := range cfg.Endpoints {
		if !endpoint.Enabled {
			continue
		}
		policy.Endpoints = append(policy.Endpoints, allowReceiptEndpoint{
			ID: endpoint.ID, Protocol: endpoint.Protocol, Model: endpoint.Model,
			TimeoutMS: endpoint.TimeoutMS, InputLimit: endpoint.InputLimit,
		})
	}
	raw, err := json.Marshal(struct {
		Policy  allowReceiptPolicy `json:"policy"`
		Source  string             `json:"source"`
		Content string             `json:"content"`
	}{policy, source, normalizeAllowReceiptText(source, text)})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func normalizeAllowReceiptText(source, text string) string {
	if source != "user" {
		return text
	}
	return allowReceiptUserMediaMarker.ReplaceAllString(text, "[images]")
}

func applyAllowReceiptSelection(snapshot *PromptSnapshot, segments []PromptReviewSegment) {
	if snapshot == nil {
		return
	}
	texts := make([]string, 0, len(segments))
	messageCount := 0
	for _, segment := range segments {
		texts = append(texts, reviewSegmentParts(segment)...)
		messageCount += segment.Count
	}
	snapshot.ScanText, _ = buildPrioritizedScanText(texts)
	snapshot.FullPrompt = FullPromptFromScanText(snapshot.ScanText)
	digest := sha256.Sum256([]byte(snapshot.FullPrompt))
	snapshot.PromptHash = hex.EncodeToString(digest[:])
	snapshot.RedactedPreview = BuildPromptPreview(snapshot.FullPrompt, DefaultPromptPreviewMaxRunes)
	snapshot.PromptLength = utf8.RuneCountInString(snapshot.FullPrompt)
	snapshot.MessageCount = messageCount
	snapshot.FullPromptTruncated = false
}

func updateCompleteContextAllowReceipts(snapshot *PromptSnapshot, status string, hits, misses int) {
	if snapshot == nil || strings.TrimSpace(snapshot.CompleteContext) == "" {
		return
	}
	var payload completePromptContext
	if json.Unmarshal([]byte(snapshot.CompleteContext), &payload) != nil {
		return
	}
	payload.GuardInput = snapshot.FullPrompt
	payload.AllowReceiptStatus = status
	payload.AllowReceiptHits = hits
	payload.AllowReceiptMisses = misses
	raw, err := json.Marshal(payload)
	if err != nil {
		return
	}
	snapshot.CompleteContext = string(raw)
	digest := sha256.Sum256(raw)
	snapshot.FullContextHash = hex.EncodeToString(digest[:])
	snapshot.FullContextBytes = len(raw)
}

func logAllowReceiptFailure(snapshot PromptSnapshot, operation, code string) {
	LogWarn(EventAllowReceiptFailed, mergeLogFields(snapshotLogFields(snapshot), map[string]any{
		"action": operation, "status": "failed", "error_code": code, "error_kind": "audit_dependency",
	}))
}
