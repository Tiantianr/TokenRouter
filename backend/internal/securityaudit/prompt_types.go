package securityaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

const (
	SettingKeyPromptAuditConfig        = "prompt_audit_config"
	SettingKeyPromptAuditPassRetention = "prompt_audit_pass_retention"
	SettingKeyRiskControl              = "risk_control_enabled"

	ConfigInvalidationChannel        = "sub2api:prompt_guard:config:invalidate"
	PassRetentionInvalidationChannel = "sub2api:prompt_audit:pass_retention:invalidate"
	PayloadKeyPrefix                 = "sub2api:prompt_audit:payload:"
	DeepReviewStateKeyPrefix         = "sub2api:prompt_audit:deep_required:user:"
	DeepReviewClaimKeyPrefix         = "sub2api:prompt_audit:deep_claim:user:"
	AllowReceiptKeyPrefix            = "sub2api:prompt_audit:allow_receipt:user:"

	ErrorCodeBlocked               = "prompt_guard_blocked"
	ErrorCodeUnavailable           = "prompt_guard_unavailable"
	ErrorCodeInvalidResponse       = "prompt_guard_invalid_response"
	ErrorCodeExtractionFailed      = "prompt_guard_content_extraction_failed"
	ErrorCodeConfigConflict        = "prompt_audit_config_conflict"
	ErrorCodeConfigUnavailable     = "prompt_audit_config_unavailable"
	ErrorCodeEncryptionKeyRequired = "prompt_audit_encryption_key_required"
	ErrorCodeRequiresEnabled       = "prompt_guard_requires_audit_enabled"
	ErrorCodeDeepReviewRequired    = "prompt_guard_deep_review_required"
	ErrorCodeDeepReviewState       = "prompt_guard_deep_review_state_unavailable"

	DefaultGuardModel = "sileader/qwen3guard:0.6b"
)

type Mode string

const (
	ModeOff       Mode = "off"
	ModeAsync     Mode = "async_audit"
	ModeAsyncDeep Mode = "async_deep"
	ModeBlocking  Mode = "blocking"
)

type ReviewModules struct {
	System          bool `json:"system"`
	Assistant       bool `json:"assistant"`
	Reasoning       bool `json:"reasoning"`
	PromptVariables bool `json:"prompt_variables"`
	ToolDefinitions bool `json:"tool_definitions"`
	ToolCalls       bool `json:"tool_calls"`
	ToolOutputs     bool `json:"tool_outputs"`
}

func DefaultBlockingReviewModules() ReviewModules {
	return ReviewModules{System: true, PromptVariables: true, ToolDefinitions: true}
}

func DefaultDeepReviewModules() ReviewModules {
	return ReviewModules{
		System: true, Assistant: true, Reasoning: true, PromptVariables: true,
		ToolDefinitions: true, ToolCalls: true, ToolOutputs: true,
	}
}

type DecisionKind string

const (
	DecisionAllow       DecisionKind = "allow"
	DecisionFlag        DecisionKind = "flag"
	DecisionBlock       DecisionKind = "block"
	DecisionUnavailable DecisionKind = "unavailable"
	DecisionInvalid     DecisionKind = "invalid"
)

type EventDecision string

const (
	EventPass     EventDecision = "pass"
	EventFlag     EventDecision = "flag"
	EventCritical EventDecision = "critical"
	EventFailed   EventDecision = "failed"
)

type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
	RiskUnknown  RiskLevel = "unknown"
)

type Action string

const (
	ActionAllow Action = "Allow"
	ActionWarn  Action = "Warn"
	ActionBlock Action = "Block"
	ActionError Action = "Error"
)

type Request struct {
	// 保留实际行为用户与账务所属用户的区别，避免团队请求归因到付款人。
	BillingUserID int64
	TeamID        *int64
	RequestID     string
	ClientIP      string
	UserID        int64
	Username      string
	UserEmail     string
	APIKeyID      int64
	APIKeyName    string
	GroupID       *int64
	GroupName     string
	Provider      string
	Endpoint      string
	Protocol      string
	Model         string
	Body          []byte
	Stage         string
	SessionKey    string
	SessionSource string

	PromptTextAuthority     bool
	BlockingExemptAtRequest bool
	AllowReceiptKeys        []string
	AllowReceiptWrite       bool
	SuppressReceiptWrite    bool

	promptPolicyResolved      bool
	promptPolicyConfigVersion int64
	promptPolicyApplies       bool
	promptPolicyExempt        bool
}

func (r Request) Clone() Request {
	r.TeamID = cloneInt64Ptr(r.TeamID)
	r.Body = append([]byte(nil), r.Body...)
	r.AllowReceiptKeys = append([]string(nil), r.AllowReceiptKeys...)
	if r.GroupID != nil {
		id := *r.GroupID
		r.GroupID = &id
	}
	return r
}

type PromptSnapshot struct {
	RequestID               string `json:"request_id"`
	ClientIP                string `json:"client_ip"`
	UserID                  int64  `json:"user_id"`
	UsernameSnapshot        string `json:"username"`
	UserEmailSnapshot       string `json:"user_email"`
	APIKeyID                int64  `json:"api_key_id"`
	APIKeyNameSnapshot      string `json:"api_key_name"`
	GroupID                 *int64 `json:"group_id,omitempty"`
	GroupName               string `json:"group_name"`
	Provider                string `json:"provider"`
	Endpoint                string `json:"endpoint"`
	Protocol                string `json:"protocol"`
	Model                   string `json:"model"`
	PromptHash              string `json:"prompt_hash"`
	RedactedPreview         string `json:"redacted_preview"`
	FullPrompt              string `json:"full_prompt"`
	FullPromptTruncated     bool   `json:"full_prompt_truncated"`
	PromptLength            int    `json:"prompt_length"`
	MessageCount            int    `json:"message_count"`
	Stage                   string `json:"stage"`
	BlockingExemptAtRequest bool   `json:"blocking_exempt_at_request"`
	SessionKey              string `json:"session_key,omitempty"`
	SessionSource           string `json:"session_source,omitempty"`
	ChatRecordID            int64  `json:"chat_record_id,omitempty"`

	ScanText  string `json:"-"`
	BodyBytes int    `json:"-"`

	CompleteContext         string `json:"-"`
	FullContextCiphertext   string `json:"-"`
	FullContextHash         string `json:"-"`
	FullContextBytes        int    `json:"-"`
	FullContextSegmentCount int    `json:"-"`

	ReviewSegments       []PromptReviewSegment `json:"-"`
	AllowReceiptKeys     []string              `json:"-"`
	AllowReceiptHitCount int                   `json:"-"`
	AllowReceiptWrite    bool                  `json:"-"`
}

type PromptReviewSegment struct {
	Source       string
	Text         string
	Parts        []string
	CombineParts bool
	CurrentUser  bool
	Count        int
}

func (s PromptSnapshot) Redacted() PromptSnapshot {
	s.ScanText = ""
	s.CompleteContext = ""
	s.ReviewSegments = nil
	s.AllowReceiptKeys = nil
	s.AllowReceiptHitCount = 0
	return s
}

type NormalizedResult struct {
	Decision          EventDecision      `json:"decision"`
	RiskLevel         RiskLevel          `json:"risk_level"`
	Action            Action             `json:"action"`
	Safety            string             `json:"safety"`
	Categories        []string           `json:"categories"`
	MatchedScanners   []string           `json:"matched_scanners"`
	ScannerScores     map[string]float64 `json:"scanner_scores"`
	ScannerEvidence   map[string]string  `json:"scanner_evidence"`
	ScannerBackend    string             `json:"scanner_backend"`
	ScannerVersion    string             `json:"scanner_version"`
	GuardEndpointID   string             `json:"guard_endpoint_id"`
	GuardEndpointName string             `json:"guard_endpoint_name"`
	GuardModel        string             `json:"guard_model"`
	PolicyID          string             `json:"policy_id"`
	PolicyVersion     int                `json:"policy_version"`
	ChunkTotal        int                `json:"chunk_total"`
	InputLimit        int                `json:"input_limit"`
	MatchedChunkIndex int                `json:"matched_chunk_index"`
	LatencyMS         int                `json:"latency_ms"`
	UnknownCategories []string           `json:"unknown_categories,omitempty"`
}

type PromptDecision struct {
	Kind                    DecisionKind      `json:"kind"`
	ErrorCode               string            `json:"error_code,omitempty"`
	Result                  *NormalizedResult `json:"result,omitempty"`
	AllowNextStage          bool              `json:"allow_next_stage"`
	DeepReviewed            bool              `json:"-"`
	AllowReceiptKeys        []string          `json:"-"`
	FailureAllowed          bool              `json:"-"`
	AsyncAuditHandled       bool              `json:"-"`
	BlockingExemptAtRequest bool              `json:"-"`
	allowReceipt            *allowReceiptCommit
}

type LegacyDecision struct {
	Allowed    bool   `json:"allowed"`
	Blocked    bool   `json:"blocked"`
	Flagged    bool   `json:"flagged"`
	Message    string `json:"message"`
	StatusCode int    `json:"status_code"`
	ErrorCode  string `json:"error_code"`
	Action     string `json:"action"`
}

type Decision struct {
	Kind           DecisionKind    `json:"kind"`
	HTTPStatus     int             `json:"http_status"`
	ErrorCode      string          `json:"error_code,omitempty"`
	ClientMessage  string          `json:"client_message,omitempty"`
	Legacy         *LegacyDecision `json:"legacy,omitempty"`
	Prompt         *PromptDecision `json:"prompt,omitempty"`
	AllowNextStage bool            `json:"allow_next_stage"`
}

type IssueSummary struct {
	Category      string  `json:"category"`
	ScannerID     string  `json:"scanner_id"`
	Title         string  `json:"title"`
	Description   string  `json:"description"`
	Severity      string  `json:"severity"`
	SeverityLabel string  `json:"severity_label"`
	Action        string  `json:"action"`
	ActionLabel   string  `json:"action_label"`
	Code          string  `json:"code"`
	Score         float64 `json:"score"`
	Evidence      string  `json:"evidence"`
	EvidenceHash  string  `json:"evidence_hash"`
	StartRune     *int    `json:"start_rune,omitempty"`
	EndRune       *int    `json:"end_rune,omitempty"`
}

type ProbeResult struct {
	OK           bool      `json:"ok"`
	Status       string    `json:"status"`
	ErrorCode    string    `json:"error_code,omitempty"`
	Message      string    `json:"message"`
	LatencyMS    int       `json:"latency_ms"`
	HTTPStatus   int       `json:"http_status"`
	Retryable    bool      `json:"retryable"`
	CheckedAt    time.Time `json:"checked_at"`
	TokenApplied bool      `json:"token_applied"`
}

type GuardMetricsSnapshot struct {
	Total          int64 `json:"total"`
	Allowed        int64 `json:"allowed"`
	Flagged        int64 `json:"flagged"`
	Blocked        int64 `json:"blocked"`
	Unavailable    int64 `json:"unavailable"`
	Invalid        int64 `json:"invalid"`
	Timeouts       int64 `json:"timeouts"`
	Failovers      int64 `json:"failovers"`
	BulkheadFull   int64 `json:"bulkhead_full"`
	RecordFailed   int64 `json:"record_failed"`
	FailureAllowed int64 `json:"failure_allowed"`
	LatencyCount   int64 `json:"latency_count"`
	LatencyAvgMS   int64 `json:"latency_avg_ms"`
	LatencyP50MS   int64 `json:"latency_p50_ms"`
	LatencyP95MS   int64 `json:"latency_p95_ms"`
	LatencyP99MS   int64 `json:"latency_p99_ms"`
	LatencyMaxMS   int64 `json:"latency_max_ms"`
}

type AuditMetricsSnapshot struct {
	Enqueued              int64 `json:"enqueued"`
	Dropped               int64 `json:"dropped"`
	ExtractionAttempted   int64 `json:"extraction_attempted"`
	ExtractionSucceeded   int64 `json:"extraction_succeeded"`
	ExtractionEmpty       int64 `json:"extraction_empty"`
	ExtractionFailed      int64 `json:"extraction_failed"`
	AllowReceiptHits      int64 `json:"allow_receipt_hits"`
	AllowReceiptMisses    int64 `json:"allow_receipt_misses"`
	AllowReceiptWrites    int64 `json:"allow_receipt_writes"`
	AllowReceiptErrors    int64 `json:"allow_receipt_errors"`
	RecoveryRequiredSync  int64 `json:"recovery_required_sync"`
	RecoveryRequiredAsync int64 `json:"recovery_required_async"`
	RecoveryCleared       int64 `json:"recovery_cleared"`
	RecoveryRetained      int64 `json:"recovery_retained"`
	RecoveryErrors        int64 `json:"recovery_errors"`
}

type ExtractionOutcome string

const (
	ExtractionSucceeded ExtractionOutcome = "succeeded"
	ExtractionEmpty     ExtractionOutcome = "empty"
	ExtractionFailed    ExtractionOutcome = "failed"
)

type QueueStats struct {
	Staging    int64 `json:"staging"`
	Queued     int64 `json:"queued"`
	Processing int64 `json:"processing"`
	Retry      int64 `json:"retry"`
	Done       int64 `json:"done"`
	Failed     int64 `json:"failed"`
	Active     int64 `json:"active"`
}

type RuntimeSnapshot struct {
	ProcessStatus         string                 `json:"process_status"`
	EffectiveMode         Mode                   `json:"effective_mode"`
	ExpectedConfigVersion int64                  `json:"expected_config_version"`
	ActiveConfigVersion   int64                  `json:"active_config_version"`
	ConfigLoadedAt        *time.Time             `json:"config_loaded_at,omitempty"`
	ConfigLoadError       string                 `json:"config_load_error,omitempty"`
	WorkerTotal           int                    `json:"worker_total"`
	WorkerActive          int64                  `json:"worker_active"`
	WorkerHeartbeatAt     *time.Time             `json:"worker_heartbeat_at,omitempty"`
	QueueCapacity         int                    `json:"queue_capacity"`
	Queue                 QueueStats             `json:"queue"`
	ProcessedTotal        int64                  `json:"processed_total"`
	FailedTotal           int64                  `json:"failed_total"`
	EnqueuedTotal         int64                  `json:"enqueued_total"`
	DroppedTotal          int64                  `json:"dropped_total"`
	ExtractionAttempted   int64                  `json:"extraction_attempted"`
	ExtractionSucceeded   int64                  `json:"extraction_succeeded"`
	ExtractionEmpty       int64                  `json:"extraction_empty"`
	ExtractionFailed      int64                  `json:"extraction_failed"`
	AllowReceiptHits      int64                  `json:"allow_receipt_hits"`
	AllowReceiptMisses    int64                  `json:"allow_receipt_misses"`
	AllowReceiptWrites    int64                  `json:"allow_receipt_writes"`
	AllowReceiptErrors    int64                  `json:"allow_receipt_errors"`
	RecoveryRequiredSync  int64                  `json:"recovery_required_sync"`
	RecoveryRequiredAsync int64                  `json:"recovery_required_async"`
	RecoveryCleared       int64                  `json:"recovery_cleared"`
	RecoveryRetained      int64                  `json:"recovery_retained"`
	RecoveryErrors        int64                  `json:"recovery_errors"`
	LastProcessedAt       *time.Time             `json:"last_processed_at,omitempty"`
	LastErrorAt           *time.Time             `json:"last_error_at,omitempty"`
	LastErrorCode         string                 `json:"last_error_code,omitempty"`
	LastErrorMessage      string                 `json:"last_error_message,omitempty"`
	DatabaseStatus        string                 `json:"database_status"`
	RedisStatus           string                 `json:"redis_status"`
	Endpoints             map[string]ProbeResult `json:"endpoints"`
	GuardMetrics          GuardMetricsSnapshot   `json:"guard_metrics"`
}

type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

type Metrics interface {
	Snapshot() GuardMetricsSnapshot
	AuditSnapshot() AuditMetricsSnapshot
	Observe(kind DecisionKind, latency time.Duration)
	ObservePoolOutcome(kind DecisionKind)
	IncEnqueued()
	IncDropped()
	ObserveExtraction(outcome ExtractionOutcome)
	IncTimeout()
	IncFailover()
	IncBulkheadFull()
	IncRecordFailed()
	IncFailureAllowed()
	IncAllowReceiptHit()
	IncAllowReceiptMiss()
	IncAllowReceiptWrite()
	IncAllowReceiptError()
	IncRecoveryRequired(mode Mode)
	IncRecoveryCleared()
	IncRecoveryRetained()
	IncRecoveryError()
}

type PromptScanner interface {
	Scan(ctx context.Context, endpoint ActiveEndpoint, chunk string, enabledScanners []string) (*NormalizedResult, error)
}

// PromptAnalyzer is intentionally separate from PromptScanner. Existing
// scanner test doubles only implement the strict Guard classification API;
// interactive administrator analysis is an explicit, non-hot-path capability.
type PromptAnalyzer interface {
	Analyze(ctx context.Context, endpoint ActiveEndpoint, transcript string) (string, error)
}

type UserChatRecord struct {
	ID                  int64
	SessionKey          string
	SessionSource       string
	ContentHash         string
	FullPrompt          string
	FullPromptTruncated bool
	CreatedAt           time.Time
}

type UserChatSession struct {
	UserID           int64
	Username         string
	UserEmail        string
	SessionKey       string
	SessionSource    string
	SelectedRecordID int64
	Records          []UserChatRecord
}

type UserAnalysis struct {
	UserID            int64     `json:"user_id"`
	Username          string    `json:"username"`
	UserEmail         string    `json:"user_email"`
	SessionKey        string    `json:"session_key"`
	SessionSource     string    `json:"session_source"`
	RecordCount       int       `json:"record_count"`
	FirstRecordAt     time.Time `json:"first_record_at"`
	LastRecordAt      time.Time `json:"last_record_at"`
	GuardEndpointID   string    `json:"guard_endpoint_id"`
	GuardEndpointName string    `json:"guard_endpoint_name"`
	GuardModel        string    `json:"guard_model"`
	GeneratedAt       time.Time `json:"generated_at"`
	Report            string    `json:"report"`
}

const (
	DefaultChatRetention   = 7 * 24 * time.Hour
	maxUserAnalysisRecords = 200
	maxUserAnalysisRunes   = 120000
)

// HashSessionKey produces an opaque, user-scoped session key. Raw client
// session identifiers can contain account or workspace information and must
// not be copied into Prompt Audit rows or administrator responses.
func HashSessionKey(userID int64, protocol, source, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	digest := sha256.Sum256([]byte("sub2api:prompt-audit-session:v1:" + strconv.FormatInt(userID, 10) + ":" + strings.TrimSpace(protocol) + ":" + strings.TrimSpace(source) + ":" + raw))
	return hex.EncodeToString(digest[:])
}
