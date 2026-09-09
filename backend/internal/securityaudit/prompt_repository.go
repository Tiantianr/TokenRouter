package securityaudit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	promptAuditAdmissionLockKey     int64 = 579147893221901921
	promptAuditConfigLockKey        int64 = 579147893221901922
	promptAuditPassRetentionLockKey int64 = 579147893221901923
)

var (
	ErrQueueFull            = errors.New("prompt audit queue full")
	ErrQueueAdmissionBusy   = errors.New("prompt audit queue admission busy")
	ErrLeaseLost            = errors.New("prompt audit worker lease lost")
	ErrEventNotFound        = errors.New("prompt audit event not found")
	ErrEventContextNotFound = errors.New("prompt audit event context not found")
)

type Job struct {
	ID                  int64
	Snapshot            PromptSnapshot
	ExecutionMode       Mode
	ConfigVersion       int64
	Status              string
	Attempts            int
	MaxAttempts         int
	ClaimVersion        int64
	NextAttemptAt       time.Time
	ProcessingStartedAt *time.Time
	ProcessedAt         *time.Time
	LastErrorCode       string
	LastErrorMessage    string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

type Event struct {
	ID                   int64              `json:"id"`
	JobID                int64              `json:"job_id"`
	Snapshot             PromptSnapshot     `json:"snapshot"`
	ExecutionMode        Mode               `json:"execution_mode"`
	Decision             EventDecision      `json:"decision"`
	RiskLevel            RiskLevel          `json:"risk_level"`
	Action               Action             `json:"action"`
	Categories           []string           `json:"categories"`
	MatchedScanners      []string           `json:"matched_scanners"`
	ScannerScores        map[string]float64 `json:"scanner_scores"`
	ScannerEvidence      map[string]string  `json:"scanner_evidence"`
	ScannerBackend       string             `json:"scanner_backend"`
	ScannerVersion       string             `json:"scanner_version"`
	GuardEndpointID      string             `json:"guard_endpoint_id"`
	GuardEndpointName    string             `json:"guard_endpoint_name"`
	GuardModel           string             `json:"guard_model"`
	PolicyID             string             `json:"policy_id"`
	PolicyVersion        int                `json:"policy_version"`
	ConfigVersion        int64              `json:"config_version"`
	ChunkTotal           int                `json:"chunk_total"`
	QueueDelayMS         *int               `json:"queue_delay_ms"`
	InputLimit           *int               `json:"input_limit"`
	MatchedChunkIndex    *int               `json:"matched_chunk_index"`
	LatencyMS            int                `json:"latency_ms"`
	ErrorCode            string             `json:"error_code,omitempty"`
	ErrorMessage         string             `json:"error_message,omitempty"`
	IssueSummaries       []IssueSummary     `json:"issue_summaries"`
	CreatedAt            time.Time          `json:"created_at"`
	FullContextAvailable bool               `json:"full_context_available"`
}

type JobRepository interface {
	CreateStagingWithCapacity(ctx context.Context, snapshot PromptSnapshot, mode Mode, configVersion int64, maxAttempts, capacity int) (*Job, error)
	PublishQueued(ctx context.Context, jobID int64) error
	MarkStagingFailed(ctx context.Context, jobID int64, code, message string) error
	ClaimNextJob(ctx context.Context, now time.Time) (*Job, bool, error)
	RefreshLease(ctx context.Context, jobID, claimVersion int64, now time.Time) error
	Complete(ctx context.Context, job *Job, result *NormalizedResult, retainPassEvidence bool) (*Event, error)
	Retry(ctx context.Context, jobID, claimVersion int64, next time.Time, code, message string) error
	Fail(ctx context.Context, jobID, claimVersion int64, code, message string) error
	ReclaimStale(ctx context.Context, stagingBefore, processingBefore time.Time, limit int) (int64, error)
	QueueStats(ctx context.Context) (QueueStats, error)
	RecordBlocking(ctx context.Context, snapshot PromptSnapshot, configVersion int64, result *NormalizedResult, retainPassEvidence bool) (*Event, error)
	RecordFailureEvent(ctx context.Context, job *Job, code string) (*Event, error)
}

type PostgreSQLRepository struct {
	db    *sql.DB
	clock Clock
}

func NewPostgreSQLRepository(db *sql.DB) *PostgreSQLRepository {
	return &PostgreSQLRepository{db: db, clock: realClock{}}
}

func (r *PostgreSQLRepository) CreateStagingWithCapacity(ctx context.Context, snapshot PromptSnapshot, mode Mode, configVersion int64, maxAttempts, capacity int) (*Job, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("prompt audit database unavailable")
	}
	if mode != ModeAsync && mode != ModeAsyncDeep {
		return nil, errors.New("prompt audit queue execution mode invalid")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var locked bool
	if err := tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock($1)`, promptAuditAdmissionLockKey).Scan(&locked); err != nil {
		return nil, err
	}
	if !locked {
		return nil, ErrQueueAdmissionBusy
	}
	var active int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM prompt_audit_jobs
		WHERE status IN ('staging','queued','processing','retry')`).Scan(&active); err != nil {
		return nil, err
	}
	if capacity <= 0 || active >= capacity {
		return nil, ErrQueueFull
	}
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	job, err := insertJob(ctx, tx, snapshot.Redacted(), mode, configVersion, "staging", maxAttempts)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return job, nil
}

func (r *PostgreSQLRepository) PublishQueued(ctx context.Context, jobID int64) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE prompt_audit_jobs SET status='queued', next_attempt_at=NOW(), updated_at=NOW()
		WHERE id=$1 AND status='staging'`, jobID)
	return requireOneRow(result, err, ErrLeaseLost)
}

func (r *PostgreSQLRepository) MarkStagingFailed(ctx context.Context, jobID int64, code, _ string) error {
	code, message := sanitizeStoredError(code)
	result, err := r.db.ExecContext(ctx, `
		UPDATE prompt_audit_jobs
		SET status='failed', processed_at=NOW(), updated_at=NOW(), last_error_code=$2, last_error_message=$3
		WHERE id=$1 AND status='staging'`, jobID, code, message)
	return requireOneRow(result, err, ErrLeaseLost)
}

func (r *PostgreSQLRepository) ClaimNextJob(ctx context.Context, now time.Time) (*Job, bool, error) {
	row := r.db.QueryRowContext(ctx, `
		WITH candidate AS (
			SELECT id FROM prompt_audit_jobs
			WHERE status IN ('queued','retry') AND next_attempt_at <= $1
			ORDER BY next_attempt_at, id
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE prompt_audit_jobs AS j
		SET status='processing', attempts=j.attempts+1, claim_version=j.claim_version+1,
			processing_started_at=$1, updated_at=$1
		FROM candidate
		WHERE j.id=candidate.id
		RETURNING `+jobColumns("j"), now.UTC())
	job, err := scanJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	return job, err == nil, err
}

func (r *PostgreSQLRepository) RefreshLease(ctx context.Context, jobID, claimVersion int64, now time.Time) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE prompt_audit_jobs SET processing_started_at=$3, updated_at=$3
		WHERE id=$1 AND status='processing' AND claim_version=$2`, jobID, claimVersion, now.UTC())
	return requireOneRow(result, err, ErrLeaseLost)
}

func (r *PostgreSQLRepository) Complete(ctx context.Context, job *Job, result *NormalizedResult, retainPassEvidence bool) (*Event, error) {
	if job == nil || result == nil {
		return nil, errors.New("prompt audit completion requires job and result")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	updateResult, err := tx.ExecContext(ctx, `
		UPDATE prompt_audit_jobs SET status='done', processed_at=NOW(), updated_at=NOW(),
			last_error_code='', last_error_message=''
		WHERE id=$1 AND status='processing' AND claim_version=$2`, job.ID, job.ClaimVersion)
	if err := requireOneRow(updateResult, err, ErrLeaseLost); err != nil {
		return nil, err
	}
	event, err := insertEvent(ctx, tx, job.ID, job.Snapshot.Redacted(), job.ExecutionMode, job.ConfigVersion,
		queueDelayMilliseconds(job), result, shouldRetainPromptAuditEvidence(result.Decision, retainPassEvidence))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return event, nil
}

func (r *PostgreSQLRepository) Retry(ctx context.Context, jobID, claimVersion int64, next time.Time, code, _ string) error {
	code, message := sanitizeStoredError(code)
	result, err := r.db.ExecContext(ctx, `
		UPDATE prompt_audit_jobs SET status='retry', next_attempt_at=$3, processing_started_at=NULL,
			updated_at=NOW(), last_error_code=$4, last_error_message=$5
		WHERE id=$1 AND status='processing' AND claim_version=$2`,
		jobID, claimVersion, next.UTC(), code, message)
	return requireOneRow(result, err, ErrLeaseLost)
}

func (r *PostgreSQLRepository) Fail(ctx context.Context, jobID, claimVersion int64, code, _ string) error {
	code, message := sanitizeStoredError(code)
	result, err := r.db.ExecContext(ctx, `
		UPDATE prompt_audit_jobs SET status='failed', processed_at=NOW(), processing_started_at=NULL,
			updated_at=NOW(), last_error_code=$3, last_error_message=$4
		WHERE id=$1 AND status='processing' AND claim_version=$2`,
		jobID, claimVersion, code, message)
	return requireOneRow(result, err, ErrLeaseLost)
}

func (r *PostgreSQLRepository) ReclaimStale(ctx context.Context, stagingBefore, processingBefore time.Time, limit int) (int64, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	result, err := r.db.ExecContext(ctx, `
		WITH stale AS (
			SELECT id FROM prompt_audit_jobs
			WHERE (status='staging' AND updated_at < $1)
			   OR (status='processing' AND processing_started_at < $2)
			ORDER BY updated_at, id FOR UPDATE SKIP LOCKED LIMIT $3
		)
		UPDATE prompt_audit_jobs AS j
		SET status=CASE
			WHEN j.status='staging' THEN 'failed'
			WHEN j.attempts < j.max_attempts THEN 'retry'
			ELSE 'failed' END,
			next_attempt_at=CASE WHEN j.status='processing' AND j.attempts < j.max_attempts THEN NOW() ELSE j.next_attempt_at END,
			processing_started_at=NULL,
			processed_at=CASE WHEN j.status='staging' OR j.attempts >= j.max_attempts THEN NOW() ELSE NULL END,
			last_error_code=CASE WHEN j.status='staging' THEN 'staging_timeout' ELSE 'processing_lease_expired' END,
			last_error_message='', updated_at=NOW()
		FROM stale WHERE j.id=stale.id`, stagingBefore.UTC(), processingBefore.UTC(), limit)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (r *PostgreSQLRepository) QueueStats(ctx context.Context) (QueueStats, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM prompt_audit_jobs GROUP BY status`)
	if err != nil {
		return QueueStats{}, err
	}
	defer func() { _ = rows.Close() }()
	var stats QueueStats
	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			return QueueStats{}, err
		}
		switch status {
		case "staging":
			stats.Staging = count
		case "queued":
			stats.Queued = count
		case "processing":
			stats.Processing = count
		case "retry":
			stats.Retry = count
		case "done":
			stats.Done = count
		case "failed":
			stats.Failed = count
		}
	}
	stats.Active = stats.Staging + stats.Queued + stats.Processing + stats.Retry
	return stats, rows.Err()
}

func (r *PostgreSQLRepository) RecordBlockingFailure(ctx context.Context, snapshot PromptSnapshot, configVersion int64, code string) (*Event, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("prompt audit database unavailable")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	job, err := insertJob(ctx, tx, snapshot.Redacted(), ModeBlocking, configVersion, "failed", 1)
	if err != nil {
		return nil, err
	}
	code, message := sanitizeStoredError(code)
	result, err := tx.ExecContext(ctx, `
		UPDATE prompt_audit_jobs SET attempts=1,last_error_code=$2,last_error_message=$3,updated_at=NOW()
		WHERE id=$1`, job.ID, code, message)
	if err := requireOneRow(result, err, ErrLeaseLost); err != nil {
		return nil, err
	}
	event, err := insertFailureEvent(ctx, tx, job, code)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return event, nil
}

func (r *PostgreSQLRepository) RecordFailureEvent(ctx context.Context, job *Job, code string) (*Event, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("prompt audit database unavailable")
	}
	if job == nil || job.ID <= 0 {
		return nil, errors.New("prompt audit failure event requires job")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var status string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM prompt_audit_jobs WHERE id=$1 FOR UPDATE`, job.ID).Scan(&status); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrLeaseLost
	} else if err != nil {
		return nil, err
	}
	if status != "failed" {
		return nil, ErrLeaseLost
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM prompt_audit_events WHERE job_id=$1)`, job.ID).Scan(&exists); err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrLeaseLost
	}
	event, err := insertFailureEvent(ctx, tx, job, code)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return event, nil
}

func (r *PostgreSQLRepository) RecordBlocking(ctx context.Context, snapshot PromptSnapshot, configVersion int64, result *NormalizedResult, retainPassEvidence bool) (*Event, error) {
	if result == nil {
		return nil, errors.New("prompt guard result required")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	job, err := insertJob(ctx, tx, snapshot.Redacted(), ModeBlocking, configVersion, "done", 1)
	if err != nil {
		return nil, err
	}
	event, err := insertEvent(ctx, tx, job.ID, snapshot.Redacted(), ModeBlocking, configVersion, 0, result,
		shouldRetainPromptAuditEvidence(result.Decision, retainPassEvidence))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return event, nil
}

// Risk evidence is mandatory; Pass evidence follows the user retention policy.
func shouldRetainPromptAuditEvidence(decision EventDecision, retainPassEvidence bool) bool {
	return decision != EventPass || retainPassEvidence
}

func queueDelayMilliseconds(job *Job) int {
	if job == nil || job.ProcessingStartedAt == nil || !job.ProcessingStartedAt.After(job.CreatedAt) {
		return 0
	}
	return int(job.ProcessingStartedAt.Sub(job.CreatedAt).Milliseconds())
}

type sqlQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func insertJob(ctx context.Context, queryer sqlQueryer, snapshot PromptSnapshot, mode Mode, configVersion int64, status string, maxAttempts int) (*Job, error) {
	processedExpr := "NULL"
	if status == "done" || status == "failed" {
		processedExpr = "NOW()"
	}
	row := queryer.QueryRowContext(ctx, `
		INSERT INTO prompt_audit_jobs (
			request_id,user_id,username_snapshot,user_email_snapshot,api_key_id,api_key_name_snapshot,
			group_id,group_name,provider,endpoint,protocol,model,prompt_hash,redacted_preview,
			prompt_length,message_count,stage,execution_mode,config_version,status,max_attempts,client_ip,processed_at,
			blocking_exempt_at_request,session_key,session_source
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,`+processedExpr+`,$23,$24,$25)
		RETURNING `+jobColumns("prompt_audit_jobs"),
		snapshot.RequestID, nullableID(snapshot.UserID), snapshot.UsernameSnapshot, snapshot.UserEmailSnapshot,
		nullableID(snapshot.APIKeyID), snapshot.APIKeyNameSnapshot, snapshot.GroupID, snapshot.GroupName,
		snapshot.Provider, snapshot.Endpoint, snapshot.Protocol, snapshot.Model, snapshot.PromptHash,
		snapshot.RedactedPreview, snapshot.PromptLength, snapshot.MessageCount, normalizeStage(snapshot.Stage),
		string(mode), configVersion, status, maxAttempts, snapshot.ClientIP, snapshot.BlockingExemptAtRequest,
		snapshot.SessionKey, snapshot.SessionSource)
	return scanJob(row)
}

func insertFailureEvent(ctx context.Context, queryer sqlQueryer, job *Job, code string) (*Event, error) {
	if job == nil {
		return nil, errors.New("prompt audit failure event requires job")
	}
	code, message := sanitizeStoredError(code)
	snapshot := failureEventSnapshot(job.Snapshot)
	row := queryer.QueryRowContext(ctx, `
		INSERT INTO prompt_audit_events (
			job_id,request_id,user_id,username_snapshot,user_email_snapshot,api_key_id,api_key_name_snapshot,
			group_id,group_name,provider,endpoint,protocol,model,prompt_hash,redacted_preview,stage,
			decision,risk_level,action,categories,matched_scanners,scanner_scores,scanner_evidence,
			scanner_backend,scanner_version,guard_endpoint_id,policy_id,policy_version,config_version,chunk_total,latency_ms,
			full_prompt,client_ip,prompt_length,message_count,execution_mode,queue_delay_ms,input_limit,matched_chunk_index,
			full_prompt_truncated,guard_endpoint_name,guard_model,error_code,error_message,blocking_exempt_at_request,
			session_key,session_source,chat_record_id
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,
			$20::jsonb,$21::jsonb,$22::jsonb,$23::jsonb,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,
			$36,$37,$38,$39,$40,$41,$42,$43,$44,$45,$46,$47,NULL)
		RETURNING `+eventDetailColumns("prompt_audit_events"),
		job.ID, snapshot.RequestID, nullableID(snapshot.UserID), snapshot.UsernameSnapshot, snapshot.UserEmailSnapshot,
		nullableID(snapshot.APIKeyID), snapshot.APIKeyNameSnapshot, snapshot.GroupID, snapshot.GroupName,
		snapshot.Provider, snapshot.Endpoint, snapshot.Protocol, snapshot.Model, snapshot.PromptHash,
		snapshot.RedactedPreview, normalizeStage(snapshot.Stage), string(EventFailed), string(RiskUnknown), string(ActionError),
		[]byte("[]"), []byte("[]"), []byte("{}"), []byte("{}"), "qwen3guard-openai", "",
		"", "priority", 0, job.ConfigVersion, 0, 0,
		"", snapshot.ClientIP, snapshot.PromptLength, snapshot.MessageCount, string(job.ExecutionMode), queueDelayMilliseconds(job),
		nil, nil, snapshot.FullPromptTruncated, "", "", code, message, snapshot.BlockingExemptAtRequest,
		snapshot.SessionKey, snapshot.SessionSource)
	return scanEvent(row, true)
}

func failureEventSnapshot(snapshot PromptSnapshot) PromptSnapshot {
	snapshot = snapshot.Redacted()
	snapshot.FullPrompt = ""
	snapshot.FullPromptTruncated = snapshot.PromptLength > 0
	snapshot.FullContextCiphertext = ""
	snapshot.FullContextHash = ""
	snapshot.FullContextBytes = 0
	snapshot.FullContextSegmentCount = 0
	return snapshot
}

func insertEvent(ctx context.Context, queryer sqlQueryer, jobID int64, snapshot PromptSnapshot, executionMode Mode, configVersion int64, queueDelayMS int, result *NormalizedResult, retainEvidence bool) (*Event, error) {
	categories, _ := json.Marshal(result.Categories)
	matched, _ := json.Marshal(result.MatchedScanners)
	scores, _ := json.Marshal(result.ScannerScores)
	evidence := make(map[string]string, len(result.ScannerEvidence))
	for key, value := range result.ScannerEvidence {
		evidence[key] = RedactPreview(value, 160)
	}
	evidenceJSON, _ := json.Marshal(evidence)
	fullPromptTruncated := snapshot.PromptLength > 0
	if retainEvidence {
		fullPromptTruncated = snapshot.FullPromptTruncated
	}
	row := queryer.QueryRowContext(ctx, `
		INSERT INTO prompt_audit_events (
			job_id,request_id,user_id,username_snapshot,user_email_snapshot,api_key_id,api_key_name_snapshot,
			group_id,group_name,provider,endpoint,protocol,model,prompt_hash,redacted_preview,stage,
			decision,risk_level,action,categories,matched_scanners,scanner_scores,scanner_evidence,
			scanner_backend,scanner_version,guard_endpoint_id,policy_id,policy_version,config_version,chunk_total,latency_ms,
			full_prompt,client_ip,prompt_length,message_count,execution_mode,queue_delay_ms,input_limit,matched_chunk_index,
			full_prompt_truncated,guard_endpoint_name,guard_model,blocking_exempt_at_request,
			session_key,session_source,chat_record_id
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,
			$20::jsonb,$21::jsonb,$22::jsonb,$23::jsonb,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,
			$36,$37,$38,$39,$40,$41,$42,$43,$44,$45,NULL)
		RETURNING `+eventDetailColumns("prompt_audit_events"),
		jobID, snapshot.RequestID, nullableID(snapshot.UserID), snapshot.UsernameSnapshot, snapshot.UserEmailSnapshot,
		nullableID(snapshot.APIKeyID), snapshot.APIKeyNameSnapshot, snapshot.GroupID, snapshot.GroupName,
		snapshot.Provider, snapshot.Endpoint, snapshot.Protocol, snapshot.Model, snapshot.PromptHash,
		snapshot.RedactedPreview, normalizeStage(snapshot.Stage), string(result.Decision), string(result.RiskLevel),
		string(result.Action), categories, matched, scores, evidenceJSON, result.ScannerBackend, result.ScannerVersion,
		result.GuardEndpointID, result.PolicyID, result.PolicyVersion, configVersion, result.ChunkTotal, result.LatencyMS,
		"", snapshot.ClientIP, snapshot.PromptLength, snapshot.MessageCount, string(executionMode), queueDelayMS,
		nullablePositiveInt(result.InputLimit), nullablePositiveInt(result.MatchedChunkIndex), fullPromptTruncated,
		result.GuardEndpointName, result.GuardModel, snapshot.BlockingExemptAtRequest,
		snapshot.SessionKey, snapshot.SessionSource)
	event, err := scanEvent(row, true)
	if err != nil {
		return nil, err
	}
	// The existing retainEvidence flag is decision-oriented: it is true for all
	// risk findings and for Pass evidence selected by the retention policy. Those
	// records remain indefinite; an unselected Pass receives the ordinary window.
	chatRecordID, err := upsertChatRecord(ctx, queryer, snapshot, retainEvidence)
	if err != nil {
		return nil, err
	}
	if chatRecordID > 0 {
		if _, err := queryer.ExecContext(ctx, `UPDATE prompt_audit_events SET chat_record_id=$2 WHERE id=$1`, event.ID, chatRecordID); err != nil {
			return nil, err
		}
		event.Snapshot.ChatRecordID = chatRecordID
		event.Snapshot.FullPrompt = snapshot.FullPrompt
		event.FullContextAvailable = snapshot.FullContextCiphertext != ""
	}
	return event, nil
}

func upsertChatRecord(ctx context.Context, queryer sqlQueryer, snapshot PromptSnapshot, retainEvidence bool) (int64, error) {
	if snapshot.UserID <= 0 || strings.TrimSpace(snapshot.SessionKey) == "" || strings.TrimSpace(snapshot.FullPrompt) == "" {
		return 0, nil
	}
	if snapshot.FullContextCiphertext == "" && snapshot.FullContextHash == "" {
		return 0, nil
	}
	digest := sha256.Sum256([]byte(snapshot.FullPrompt + "\x00" + snapshot.FullContextHash))
	contentHash := hex.EncodeToString(digest[:])
	var retentionValue any = time.Now().UTC().Add(DefaultChatRetention)
	if retainEvidence {
		retentionValue = nil
	}
	var sessionID int64
	if err := queryer.QueryRowContext(ctx, `
		INSERT INTO prompt_audit_sessions (user_id,session_key,session_source,first_seen_at,last_seen_at)
		VALUES ($1,$2,$3,NOW(),NOW())
		ON CONFLICT (user_id,session_key) DO UPDATE SET
			last_seen_at=NOW(),
			session_source=CASE WHEN prompt_audit_sessions.session_source='' THEN EXCLUDED.session_source ELSE prompt_audit_sessions.session_source END
		RETURNING id`, snapshot.UserID, snapshot.SessionKey, snapshot.SessionSource).Scan(&sessionID); err != nil {
		return 0, err
	}
	var recordID int64
	err := queryer.QueryRowContext(ctx, `
		INSERT INTO prompt_audit_chat_records (
			session_id,content_hash,full_prompt,full_prompt_truncated,context_ciphertext,context_sha256,
			context_bytes,segment_count,retention_until,created_at
		) VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),$7,$8,$9,NOW())
		ON CONFLICT (session_id,content_hash) DO UPDATE SET
			retention_until=CASE
				WHEN EXCLUDED.retention_until IS NULL THEN NULL
				WHEN prompt_audit_chat_records.retention_until IS NULL THEN NULL
				ELSE GREATEST(prompt_audit_chat_records.retention_until, EXCLUDED.retention_until)
			END
		RETURNING id`, sessionID, contentHash, snapshot.FullPrompt, snapshot.FullPromptTruncated,
		snapshot.FullContextCiphertext, snapshot.FullContextHash, snapshot.FullContextBytes, snapshot.FullContextSegmentCount, retentionValue).Scan(&recordID)
	return recordID, err
}

type rowScanner interface{ Scan(...any) error }

func scanJob(row rowScanner) (*Job, error) {
	job := &Job{}
	var userID, apiKeyID, groupID sql.NullInt64
	var processingStarted, processed sql.NullTime
	err := row.Scan(
		&job.ID, &job.Snapshot.RequestID, &userID, &job.Snapshot.UsernameSnapshot, &job.Snapshot.UserEmailSnapshot,
		&apiKeyID, &job.Snapshot.APIKeyNameSnapshot, &groupID, &job.Snapshot.GroupName, &job.Snapshot.Provider,
		&job.Snapshot.Endpoint, &job.Snapshot.Protocol, &job.Snapshot.Model, &job.Snapshot.PromptHash,
		&job.Snapshot.RedactedPreview, &job.Snapshot.PromptLength, &job.Snapshot.MessageCount, &job.Snapshot.Stage,
		&job.ExecutionMode, &job.ConfigVersion, &job.Status, &job.Attempts, &job.MaxAttempts, &job.ClaimVersion,
		&job.NextAttemptAt, &processingStarted, &processed, &job.LastErrorCode, &job.LastErrorMessage,
		&job.CreatedAt, &job.UpdatedAt, &job.Snapshot.ClientIP, &job.Snapshot.BlockingExemptAtRequest,
		&job.Snapshot.SessionKey, &job.Snapshot.SessionSource,
	)
	if err != nil {
		return nil, err
	}
	job.Snapshot.UserID = nullableInt64Value(userID)
	job.Snapshot.APIKeyID = nullableInt64Value(apiKeyID)
	job.Snapshot.GroupID = nullableInt64Ptr(groupID)
	if processingStarted.Valid {
		value := processingStarted.Time
		job.ProcessingStartedAt = &value
	}
	if processed.Valid {
		value := processed.Time
		job.ProcessedAt = &value
	}
	return job, nil
}

func jobColumns(alias string) string {
	return fmt.Sprintf(`%[1]s.id,%[1]s.request_id,%[1]s.user_id,%[1]s.username_snapshot,%[1]s.user_email_snapshot,
		%[1]s.api_key_id,%[1]s.api_key_name_snapshot,%[1]s.group_id,%[1]s.group_name,%[1]s.provider,
		%[1]s.endpoint,%[1]s.protocol,%[1]s.model,%[1]s.prompt_hash,%[1]s.redacted_preview,
		%[1]s.prompt_length,%[1]s.message_count,%[1]s.stage,%[1]s.execution_mode,%[1]s.config_version,%[1]s.status,
		%[1]s.attempts,%[1]s.max_attempts,%[1]s.claim_version,%[1]s.next_attempt_at,
		%[1]s.processing_started_at,%[1]s.processed_at,%[1]s.last_error_code,%[1]s.last_error_message,
		%[1]s.created_at,%[1]s.updated_at,%[1]s.client_ip,%[1]s.blocking_exempt_at_request,
		%[1]s.session_key,%[1]s.session_source`, alias)
}

func normalizeStage(stage string) string {
	stage = strings.TrimSpace(stage)
	if stage == "" {
		return "http"
	}
	return stage
}

func requireOneRow(result sql.Result, err error, missing error) error {
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return missing
	}
	return nil
}

func nullableID(value int64) any {
	if value <= 0 {
		return nil
	}
	return value
}

func nullablePositiveInt(value int) any {
	if value <= 0 {
		return nil
	}
	return value
}

func nullableInt64Value(value sql.NullInt64) int64 {
	if !value.Valid {
		return 0
	}
	return value.Int64
}

func nullableInt64Ptr(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	result := value.Int64
	return &result
}
