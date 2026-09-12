package securityaudit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

const promptAuditPostgresTestEnv = "PROMPT_AUDIT_TEST_POSTGRES_DSN"

func openPromptAuditIntegrationDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv(promptAuditPostgresTestEnv))
	if dsn == "" {
		t.Skip(promptAuditPostgresTestEnv + " is not set")
	}
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	db.SetMaxOpenConns(16)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, db.PingContext(ctx))
	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS users (id BIGSERIAL PRIMARY KEY);
		CREATE TABLE IF NOT EXISTS groups (id BIGSERIAL PRIMARY KEY);
		CREATE TABLE IF NOT EXISTS api_keys (id BIGSERIAL PRIMARY KEY);
		CREATE TABLE IF NOT EXISTS settings (
			key VARCHAR(255) PRIMARY KEY,
			value TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
	`)
	require.NoError(t, err)
	for _, name := range []string{"268_prompt_audit.sql"} {
		migration, err := os.ReadFile(filepath.Join("..", "..", "migrations", name))
		require.NoError(t, err)
		// The migration runner can retry an interrupted deployment; the migration
		// must therefore be safe to execute more than once.
		_, err = db.ExecContext(ctx, string(migration))
		require.NoError(t, err)
		_, err = db.ExecContext(ctx, string(migration))
		require.NoError(t, err)
	}
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	resetPromptAuditIntegrationDB(t, db)
	return db
}

func TestPromptAuditAsyncDeepExecutionModePersistsAndFilters(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	snapshot := integrationSnapshot("deep")
	snapshot.BlockingExemptAtRequest = true
	snapshot.UserID = insertIdentity(t, db, "users")
	snapshot.APIKeyID = insertIdentity(t, db, "api_keys")
	groupID := insertIdentity(t, db, "groups")
	snapshot.GroupID = &groupID

	job, err := repo.CreateStagingWithCapacity(ctx, snapshot, ModeAsyncDeep, 1, 3, 10)
	require.NoError(t, err)
	require.Equal(t, ModeAsyncDeep, job.ExecutionMode)
	require.True(t, job.Snapshot.BlockingExemptAtRequest)
	require.NoError(t, repo.PublishQueued(ctx, job.ID))
	claimed, ok, err := repo.ClaimNextJob(ctx, time.Now().UTC().Add(time.Second))
	require.NoError(t, err)
	require.True(t, ok)
	require.True(t, claimed.Snapshot.BlockingExemptAtRequest)
	event, err := repo.Complete(ctx, claimed, integrationResult(EventCritical), false)
	require.NoError(t, err)
	require.Equal(t, ModeAsyncDeep, event.ExecutionMode)
	require.True(t, event.Snapshot.BlockingExemptAtRequest)

	page, err := repo.ListEvents(ctx, EventFilter{ExecutionMode: string(ModeAsyncDeep)}, 1, 20)
	require.NoError(t, err)
	require.Equal(t, int64(1), page.Total)
	require.Len(t, page.Items, 1)
	require.Equal(t, ModeAsyncDeep, page.Items[0].ExecutionMode)
	require.True(t, page.Items[0].Snapshot.BlockingExemptAtRequest)
	blockingPage, err := repo.ListEvents(ctx, EventFilter{ExecutionMode: string(ModeBlocking)}, 1, 20)
	require.NoError(t, err)
	require.Zero(t, blockingPage.Total)
}

func TestPromptAuditSessionContentDeduplicatesAndExpiresIndependently(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	userID := insertIdentity(t, db, "users")
	snapshot := integrationSnapshot("session")
	snapshot.UserID = userID
	snapshot.SessionKey = HashSessionKey(userID, snapshot.Protocol, "header:session-id", "stable-session")
	snapshot.SessionSource = "client_session"
	snapshot.FullPrompt = "same complete prompt"
	snapshot.FullContextCiphertext = "encrypted-context"
	snapshot.FullContextHash = "context-hash"
	first, err := repo.RecordBlocking(ctx, snapshot, 1, integrationResult(EventPass), false)
	require.NoError(t, err)
	secondSnapshot := snapshot
	secondSnapshot.RequestID = "request-session-second"
	second, err := repo.RecordBlocking(ctx, secondSnapshot, 1, integrationResult(EventPass), false)
	require.NoError(t, err)

	var count int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM prompt_audit_chat_records`).Scan(&count))
	require.Equal(t, 1, count)
	require.Equal(t, first.Snapshot.ChatRecordID, second.Snapshot.ChatRecordID)
	start, end := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	preview, err := repo.PreviewDelete(ctx, EventFilter{RequestID: first.Snapshot.RequestID, StartAt: &start, EndAt: &end})
	require.NoError(t, err)
	require.Equal(t, int64(1), preview.MatchedCount)
	require.Zero(t, preview.MatchedContextCount)
	require.Zero(t, preview.EstimatedReclaimableBytes)

	detail, err := repo.GetEvent(ctx, first.ID)
	require.NoError(t, err)
	require.Equal(t, "same complete prompt", detail.Snapshot.FullPrompt)
	require.True(t, detail.FullContextAvailable)

	_, err = db.ExecContext(ctx, `UPDATE prompt_audit_chat_records SET retention_until=NOW()-INTERVAL '1 minute'`)
	require.NoError(t, err)
	deleted, err := repo.DeleteExpiredChatRecords(ctx, time.Now().UTC(), 100)
	require.NoError(t, err)
	require.EqualValues(t, 1, deleted)
	require.NoError(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM prompt_audit_events`).Scan(&count))
	require.Equal(t, 2, count)

	session, err := repo.GetSessionChatRecords(ctx, first.ID, 20)
	require.NoError(t, err)
	require.Empty(t, session.Records)
}

func TestPromptAuditChatCapacityDeletesOldestContentAndKeepsEvents(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	userID := insertIdentity(t, db, "users")

	oldSnapshot := integrationSnapshot("capacity-old")
	oldSnapshot.UserID = userID
	oldSnapshot.SessionKey = HashSessionKey(userID, oldSnapshot.Protocol, "header:session-id", "capacity-old")
	oldSnapshot.SessionSource = "client_session"
	oldSnapshot.FullPrompt = strings.Repeat("o", 100)
	oldEvent, err := repo.RecordBlocking(ctx, oldSnapshot, 1, integrationResult(EventCritical), false)
	require.NoError(t, err)
	require.NotZero(t, oldEvent.Snapshot.ChatRecordID)

	newSnapshot := integrationSnapshot("capacity-new")
	newSnapshot.UserID = userID
	newSnapshot.SessionKey = HashSessionKey(userID, newSnapshot.Protocol, "header:session-id", "capacity-new")
	newSnapshot.SessionSource = "client_session"
	newSnapshot.FullPrompt = strings.Repeat("n", 30)
	newEvent, err := repo.RecordBlocking(ctx, newSnapshot, 1, integrationResult(EventCritical), false)
	require.NoError(t, err)
	require.NotZero(t, newEvent.Snapshot.ChatRecordID)
	_, err = db.ExecContext(ctx, `UPDATE prompt_audit_chat_records SET created_at=CASE WHEN id=$1 THEN NOW()-INTERVAL '2 minutes' ELSE NOW() END WHERE id IN ($1,$2)`, oldEvent.Snapshot.ChatRecordID, newEvent.Snapshot.ChatRecordID)
	require.NoError(t, err)

	deleted, remaining, err := repo.DeleteOldestChatRecordsToLimit(ctx, 50, 100)
	require.NoError(t, err)
	require.EqualValues(t, 1, deleted)
	require.LessOrEqual(t, remaining, int64(50))
	var eventCount, contentCount int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM prompt_audit_events`).Scan(&eventCount))
	require.NoError(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM prompt_audit_chat_records`).Scan(&contentCount))
	require.Equal(t, 2, eventCount)
	require.Equal(t, 1, contentCount)
	var oldExists bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM prompt_audit_chat_records WHERE id=$1)`, oldEvent.Snapshot.ChatRecordID).Scan(&oldExists))
	require.False(t, oldExists)
}

func TestPromptAuditRiskChatContentUsesIndefiniteRetention(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	userID := insertIdentity(t, db, "users")
	snapshot := integrationSnapshot("risk-retention")
	snapshot.UserID = userID
	snapshot.SessionKey = HashSessionKey(userID, snapshot.Protocol, "header:session-id", "risk-retention")
	snapshot.SessionSource = "client_session"
	snapshot.FullPrompt = "risk evidence must remain available"
	snapshot.FullContextCiphertext = "encrypted-risk-context"
	snapshot.FullContextHash = "risk-context-hash"
	_, err := repo.RecordBlocking(ctx, snapshot, 1, integrationResult(EventCritical), false)
	require.NoError(t, err)

	var retentionUntil sql.NullTime
	require.NoError(t, db.QueryRowContext(ctx, `SELECT retention_until FROM prompt_audit_chat_records`).Scan(&retentionUntil))
	require.False(t, retentionUntil.Valid)
	deleted, err := repo.DeleteExpiredChatRecords(ctx, time.Now().UTC().Add(365*24*time.Hour), 100)
	require.NoError(t, err)
	require.Zero(t, deleted)
}

func TestPromptAuditAnalysisUsesOnlySelectedSession(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	userID := insertIdentity(t, db, "users")
	var received struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewDecoder(request.Body).Decode(&received)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"choices":[{"message":{"content":"风险等级：低"}}]}`))
	}))
	defer server.Close()

	makeEvent := func(sessionID, prompt string) *Event {
		snapshot := integrationSnapshot(sessionID)
		snapshot.UserID = userID
		snapshot.SessionKey = HashSessionKey(userID, snapshot.Protocol, "header:session-id", sessionID)
		snapshot.SessionSource = "client_session"
		snapshot.FullPrompt = prompt
		snapshot.FullContextCiphertext = "context-" + sessionID
		snapshot.FullContextHash = "hash-" + sessionID
		event, err := repo.RecordBlocking(ctx, snapshot, 1, integrationResult(EventPass), false)
		require.NoError(t, err)
		return event
	}
	selected := makeEvent("selected", "selected-session-content")
	_ = makeEvent("other", "other-session-content")

	service := &PromptService{
		config: &fakeConfigStore{active: true, cfg: ActiveConfig{ConfigVersion: 1, Endpoints: []ActiveEndpoint{{
			ID: "analysis-node", Name: "Analysis node", BaseURL: server.URL, Model: "analysis-model", TimeoutMS: 1000, Enabled: true,
		}}}},
		repo: repo, scanner: NewOpenAICompatibleScanner(), clock: realClock{},
	}
	analysis, err := service.AnalyzeEvent(ctx, selected.ID)
	require.NoError(t, err)
	require.Equal(t, 1, analysis.RecordCount)
	require.Equal(t, selected.Snapshot.SessionKey, analysis.SessionKey)
	require.Contains(t, analysis.Report, "风险等级")
	require.Len(t, received.Messages, 2)
	require.Contains(t, received.Messages[1].Content, "selected-session-content")
	require.NotContains(t, received.Messages[1].Content, "other-session-content")
}

func TestPromptAuditReadsLegacyWriterRowsAfterSessionMigration(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	userID := insertIdentity(t, db, "users")
	var jobID, eventID int64
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO prompt_audit_jobs DEFAULT VALUES RETURNING id`).Scan(&jobID))
	require.NoError(t, db.QueryRowContext(ctx, `
		INSERT INTO prompt_audit_events (job_id,user_id,request_id,protocol,full_prompt)
		VALUES ($1,$2,'legacy-writer-request','openai_responses','legacy writer prompt') RETURNING id`,
		jobID, userID).Scan(&eventID))
	_, err := db.ExecContext(ctx, `
		INSERT INTO prompt_audit_event_contexts (event_id,context_ciphertext,context_sha256,context_bytes,segment_count)
		VALUES ($1,'legacy-context','legacy-hash',14,1)`, eventID)
	require.NoError(t, err)

	detail, err := repo.GetEvent(ctx, eventID)
	require.NoError(t, err)
	require.Equal(t, "legacy writer prompt", detail.Snapshot.FullPrompt)
	require.True(t, detail.FullContextAvailable)
	contextRecord, err := repo.GetEventContext(ctx, eventID)
	require.NoError(t, err)
	require.Equal(t, "legacy-context", contextRecord.Ciphertext)
	session, err := repo.GetSessionChatRecords(ctx, eventID, 20)
	require.NoError(t, err)
	require.Equal(t, "legacy_event", session.SessionSource)
	require.Len(t, session.Records, 1)
	require.Equal(t, "legacy writer prompt", session.Records[0].FullPrompt)
}

func resetPromptAuditIntegrationDB(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`TRUNCATE TABLE prompt_audit_events, prompt_audit_jobs, api_keys, users, groups, settings RESTART IDENTITY CASCADE`)
	require.NoError(t, err)
}

func insertIdentity(t *testing.T, db *sql.DB, table string) int64 {
	t.Helper()
	var id int64
	require.NoError(t, db.QueryRow(`INSERT INTO `+table+` DEFAULT VALUES RETURNING id`).Scan(&id))
	return id
}

func integrationSnapshot(seed string) PromptSnapshot {
	return PromptSnapshot{
		RequestID: "request-" + seed, ClientIP: "203.0.113.42", UsernameSnapshot: "user-" + seed,
		UserEmailSnapshot: "user-" + seed + "@example.test", APIKeyNameSnapshot: "key-" + seed,
		GroupName: "group-" + seed, Provider: "openai", Endpoint: "/v1/chat/completions",
		Protocol: "openai_chat", Model: "gpt-test", PromptHash: strings.Repeat(seed[:1], 64),
		RedactedPreview: "redacted-" + seed, PromptLength: len([]rune(seed)), MessageCount: 1,
	}
}

func integrationResult(decision EventDecision) *NormalizedResult {
	result := &NormalizedResult{
		Decision: decision, RiskLevel: RiskLow, Action: ActionAllow, Safety: "Safe",
		Categories: []string{}, MatchedScanners: []string{}, ScannerScores: map[string]float64{},
		ScannerEvidence: map[string]string{}, ScannerBackend: "qwen3guard-openai",
		ScannerVersion: "test", GuardEndpointID: "guard-1", GuardEndpointName: "Primary Guard", GuardModel: "guard-model", PolicyID: "priority",
		PolicyVersion: 1, ChunkTotal: 1, InputLimit: 500000, LatencyMS: 2,
	}
	if decision != EventPass {
		result.RiskLevel = RiskCritical
		result.Action = ActionBlock
		result.Safety = "Unsafe"
		result.Categories = []string{"pii"}
		result.MatchedScanners = []string{"pii"}
		result.ScannerScores["pii"] = 1
		result.ScannerEvidence["pii"] = "redacted evidence"
		result.MatchedChunkIndex = 1
	}
	return result
}

func TestPromptAuditMigrationSchemaAndLeakageGate(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	ctx := context.Background()

	rows, err := db.QueryContext(ctx, `SELECT table_name, column_name FROM information_schema.columns
		WHERE table_schema='public' AND table_name IN ('prompt_audit_jobs','prompt_audit_events')`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	forbidden := []string{"raw_prompt", "raw_request", "payload", "token", "authorization", "credential", "ciphertext"}
	columns := map[string]bool{}
	for rows.Next() {
		var tableName, columnName string
		require.NoError(t, rows.Scan(&tableName, &columnName))
		columns[tableName+"."+columnName] = true
		lower := strings.ToLower(columnName)
		for _, word := range forbidden {
			require.NotContainsf(t, lower, word, "%s.%s is a forbidden raw/credential column", tableName, columnName)
		}
	}
	require.NoError(t, rows.Err())
	for _, column := range []string{
		"prompt_audit_jobs.client_ip",
		"prompt_audit_events.client_ip",
		"prompt_audit_events.prompt_length",
		"prompt_audit_events.message_count",
		"prompt_audit_events.execution_mode",
		"prompt_audit_events.queue_delay_ms",
		"prompt_audit_events.input_limit",
		"prompt_audit_events.matched_chunk_index",
		"prompt_audit_events.full_prompt_truncated",
		"prompt_audit_events.guard_endpoint_name",
		"prompt_audit_events.guard_model",
		"prompt_audit_jobs.blocking_exempt_at_request",
		"prompt_audit_events.blocking_exempt_at_request",
	} {
		require.Truef(t, columns[column], "missing column %s", column)
	}

	indexRows, err := db.QueryContext(ctx, `SELECT indexname FROM pg_indexes
		WHERE schemaname='public' AND tablename IN ('prompt_audit_jobs','prompt_audit_events')`)
	require.NoError(t, err)
	defer func() { _ = indexRows.Close() }()
	indexes := map[string]bool{}
	for indexRows.Next() {
		var name string
		require.NoError(t, indexRows.Scan(&name))
		indexes[name] = true
	}
	for _, name := range []string{
		"idx_prompt_audit_jobs_schedule", "idx_prompt_audit_jobs_request", "idx_prompt_audit_jobs_user_created",
		"idx_prompt_audit_jobs_api_key_created", "idx_prompt_audit_jobs_group_created", "idx_prompt_audit_jobs_prompt_hash",
		"idx_prompt_audit_jobs_created", "idx_prompt_audit_events_job", "idx_prompt_audit_events_request",
		"idx_prompt_audit_events_decision_created", "idx_prompt_audit_events_risk_created",
		"idx_prompt_audit_events_user_created", "idx_prompt_audit_events_api_key_created",
		"idx_prompt_audit_events_group_created", "idx_prompt_audit_events_prompt_hash", "idx_prompt_audit_events_created",
		"idx_prompt_audit_events_client_ip_created",
	} {
		require.Truef(t, indexes[name], "missing index %s", name)
	}

	_, err = db.ExecContext(ctx, `INSERT INTO prompt_audit_jobs(status) VALUES ('unknown')`)
	require.Error(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO prompt_audit_jobs(prompt_length) VALUES (-1)`)
	require.Error(t, err)
	var jobID int64
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO prompt_audit_jobs DEFAULT VALUES RETURNING id`).Scan(&jobID))
	_, err = db.ExecContext(ctx, `INSERT INTO prompt_audit_events(job_id,chunk_total) VALUES ($1,-1)`, jobID)
	require.Error(t, err)
}

func TestPromptAuditGuardNodeMigrationLeavesLegacyModelForAPIFallback(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	ctx := context.Background()
	var jobID int64
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO prompt_audit_jobs DEFAULT VALUES RETURNING id`).Scan(&jobID))
	var eventID int64
	require.NoError(t, db.QueryRowContext(ctx, `
		INSERT INTO prompt_audit_events(job_id,scanner_backend,scanner_version,guard_endpoint_id)
		VALUES ($1,'qwen3guard-openai','legacy-guard-model','legacy-node') RETURNING id`, jobID).Scan(&eventID))

	migration, err := os.ReadFile(filepath.Join("..", "..", "migrations", "268_prompt_audit.sql"))
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, string(migration))
	require.NoError(t, err)

	var name, model, scannerVersion string
	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT guard_endpoint_name,guard_model,scanner_version FROM prompt_audit_events WHERE id=$1`, eventID).Scan(&name, &model, &scannerVersion))
	require.Empty(t, name)
	require.Empty(t, model)
	require.Equal(t, "legacy-guard-model", scannerVersion)
}

func TestPromptAuditObservabilityMigrationBackfillsHistoricalTruncation(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	ctx := context.Background()
	var jobID int64
	require.NoError(t, db.QueryRowContext(ctx, `
		INSERT INTO prompt_audit_jobs(prompt_length,message_count,execution_mode,client_ip)
		VALUES (70000,2,'blocking','203.0.113.42') RETURNING id`).Scan(&jobID))
	var eventID int64
	retained := strings.Repeat("x", 65536) + "…"
	require.NoError(t, db.QueryRowContext(ctx, `
		INSERT INTO prompt_audit_events(job_id,full_prompt)
		VALUES ($1,$2) RETURNING id`, jobID, retained).Scan(&eventID))

	migration, err := os.ReadFile(filepath.Join("..", "..", "migrations", "268_prompt_audit.sql"))
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, string(migration))
	require.NoError(t, err)

	var promptLength, messageCount int
	var executionMode, clientIP string
	var queueDelay, inputLimit, matchedChunk sql.NullInt64
	var truncated bool
	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT prompt_length,message_count,execution_mode,client_ip,queue_delay_ms,input_limit,
		       matched_chunk_index,full_prompt_truncated
		FROM prompt_audit_events WHERE id=$1`, eventID).Scan(
		&promptLength, &messageCount, &executionMode, &clientIP, &queueDelay, &inputLimit, &matchedChunk, &truncated,
	))
	require.Equal(t, 70000, promptLength)
	require.Equal(t, 2, messageCount)
	require.Equal(t, "blocking", executionMode)
	require.Equal(t, "203.0.113.42", clientIP)
	require.False(t, queueDelay.Valid)
	require.False(t, inputLimit.Valid)
	require.False(t, matchedChunk.Valid)
	require.True(t, truncated)
}

func TestPromptAuditDatabaseKeepsLightweightPassWithoutFullEvidence(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()

	lightweight := integrationSnapshot("lightweight")
	lightweight.FullPrompt = "unselected full prompt must not persist"
	lightweight.PromptLength = len([]rune(lightweight.FullPrompt))
	lightweight.FullContextCiphertext = "unselected encrypted context must not persist"
	lightweight.FullContextHash = strings.Repeat("a", 64)
	lightweight.FullContextBytes = 99
	lightweight.FullContextSegmentCount = 2
	event, err := repo.RecordBlocking(ctx, lightweight.Redacted(), 1, integrationResult(EventPass), false)
	require.NoError(t, err)
	require.NotNil(t, event)
	require.Equal(t, EventPass, event.Decision)
	require.Empty(t, event.Snapshot.FullPrompt)
	require.True(t, event.Snapshot.FullPromptTruncated)
	require.False(t, event.FullContextAvailable)

	detail, err := repo.GetEvent(ctx, event.ID)
	require.NoError(t, err)
	require.Equal(t, lightweight.RedactedPreview, detail.Snapshot.RedactedPreview)
	require.Empty(t, detail.Snapshot.FullPrompt)
	require.True(t, detail.Snapshot.FullPromptTruncated)
	require.False(t, detail.FullContextAvailable)
	_, err = repo.GetEventContext(ctx, event.ID)
	require.ErrorIs(t, err, ErrEventContextNotFound)

	selected := integrationSnapshot("selected")
	// 当前证据归属于真实用户和会话，不能用无用户的旧夹具验证留存。
	selected.UserID = insertIdentity(t, db, "users")
	selected.SessionKey = HashSessionKey(selected.UserID, selected.Protocol, "request_id_fallback", selected.RequestID)
	selected.FullPrompt = "selected full prompt"
	selected.PromptLength = len([]rune(selected.FullPrompt))
	selected.FullContextCiphertext = "selected encrypted context"
	selected.FullContextHash = strings.Repeat("b", 64)
	selected.FullContextBytes = 88
	selected.FullContextSegmentCount = 1
	selectedEvent, err := repo.RecordBlocking(ctx, selected.Redacted(), 1, integrationResult(EventPass), true)
	require.NoError(t, err)
	require.Equal(t, selected.FullPrompt, selectedEvent.Snapshot.FullPrompt)
	require.True(t, selectedEvent.FullContextAvailable)

	page, err := repo.ListEvents(ctx, EventFilter{}, 1, 20)
	require.NoError(t, err)
	require.Equal(t, int64(2), page.Total)
}

func TestPromptAuditFailureEventsPersistSafeReasonsAndTerminalAsyncFailure(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	const canary = "RAW_GUARD_RESPONSE_AND_PROMPT_CANARY"

	blocking := integrationSnapshot("blocking-failure")
	blocking.FullPrompt = "complete prompt " + canary
	blocking.FullContextCiphertext = "encrypted-context-" + canary
	blockingEvent, err := repo.RecordBlockingFailure(ctx, blocking, 7, ErrorCodeUnavailable)
	require.NoError(t, err)
	require.Equal(t, EventFailed, blockingEvent.Decision)
	require.Equal(t, RiskUnknown, blockingEvent.RiskLevel)
	require.Equal(t, ActionError, blockingEvent.Action)
	require.Equal(t, ErrorCodeUnavailable, blockingEvent.ErrorCode)
	require.Equal(t, stableErrorMessage(ErrorCodeUnavailable), blockingEvent.ErrorMessage)
	require.Empty(t, blockingEvent.Snapshot.FullPrompt)
	require.False(t, blockingEvent.FullContextAvailable)
	_, err = repo.GetEventContext(ctx, blockingEvent.ID)
	require.ErrorIs(t, err, ErrEventContextNotFound)

	var blockingRow, jobRow string
	require.NoError(t, db.QueryRow(`SELECT row_to_json(e)::text FROM prompt_audit_events e WHERE id=$1`, blockingEvent.ID).Scan(&blockingRow))
	require.NoError(t, db.QueryRow(`SELECT row_to_json(j)::text FROM prompt_audit_jobs j WHERE id=$1`, blockingEvent.JobID).Scan(&jobRow))
	require.NotContains(t, blockingRow, canary)
	require.NotContains(t, jobRow, canary)

	page, err := repo.ListEvents(ctx, EventFilter{Decision: string(EventFailed), Keyword: "dependency"}, 1, 20)
	require.NoError(t, err)
	require.Equal(t, int64(1), page.Total)
	require.Len(t, page.Items, 1)

	async := integrationSnapshot("async-failure")
	job, err := repo.CreateStagingWithCapacity(ctx, async, ModeAsync, 7, 2, 10)
	require.NoError(t, err)
	require.NoError(t, repo.PublishQueued(ctx, job.ID))
	claimed, ok, err := repo.ClaimNextJob(ctx, time.Now().Add(time.Second))
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, repo.Retry(ctx, claimed.ID, claimed.ClaimVersion, time.Now().Add(-time.Second), ErrorCodeUnavailable, "raw retry message"))

	page, err = repo.ListEvents(ctx, EventFilter{Decision: string(EventFailed)}, 1, 20)
	require.NoError(t, err)
	require.Equal(t, int64(1), page.Total, "retry must not create a failure event")

	claimed, ok, err = repo.ClaimNextJob(ctx, time.Now().Add(time.Second))
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, repo.Fail(ctx, claimed.ID, claimed.ClaimVersion, ErrorCodeInvalidResponse, "raw failure message"))
	asyncEvent, err := repo.RecordFailureEvent(ctx, claimed, ErrorCodeInvalidResponse)
	require.NoError(t, err)
	require.Equal(t, EventFailed, asyncEvent.Decision)
	require.Equal(t, ErrorCodeInvalidResponse, asyncEvent.ErrorCode)
	require.Equal(t, stableErrorMessage(ErrorCodeInvalidResponse), asyncEvent.ErrorMessage)
	_, err = repo.RecordFailureEvent(ctx, claimed, ErrorCodeInvalidResponse)
	require.ErrorIs(t, err, ErrLeaseLost)

	deleted, err := repo.DeleteEvent(ctx, asyncEvent.ID)
	require.NoError(t, err)
	require.Equal(t, int64(1), deleted.DeletedEvents)
	require.Equal(t, int64(1), deleted.DeletedJobs)
	var remaining int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM prompt_audit_jobs WHERE id=$1`, claimed.ID).Scan(&remaining))
	require.Zero(t, remaining)
}

func TestPromptServicePersistsBlockingFailureEventsWithoutChangingDecision(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)

	run := func(t *testing.T, requestID string, scanErr *GuardError) (*PromptDecision, *Event, error) {
		t.Helper()
		metrics := NewAtomicMetrics()
		state := newFakeAllowReceiptPayload()
		cfg := ActiveConfig{
			RiskControlEnabled: true, Enabled: true, BlockingEnabled: true,
			AllGroups: true, ConfigVersion: 7,
			Scanners: AllScannerIDs,
			Endpoints: []ActiveEndpoint{{
				ID: "guard-1", Name: "Primary Guard", Model: "guard-model",
				Enabled: true, TimeoutMS: 1000, InputLimit: 4096,
			}},
		}
		service := &PromptService{
			config: &fakeConfigStore{active: true, cfg: cfg}, repo: repo,
			evaluator: newGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
				return nil, scanErr
			}), repo, metrics, 2, 2),
			state: state, receipts: state, metrics: metrics, background: context.Background(),
		}
		decision, err := service.Evaluate(context.Background(), Request{
			RequestID: requestID, Provider: "openai", Endpoint: "/v1/responses",
			Protocol: "openai_responses", Model: "gpt-test",
			Body: []byte(`{"input":"review this request"}`),
		})
		service.enqueueWG.Wait()
		page, listErr := repo.ListEvents(context.Background(), EventFilter{RequestID: requestID, Decision: string(EventFailed)}, 1, 20)
		require.NoError(t, listErr)
		require.Equal(t, int64(1), page.Total)
		require.Len(t, page.Items, 1)
		return decision, page.Items[0], err
	}

	t.Run("eligible outage is allowed and recorded", func(t *testing.T) {
		decision, event, err := run(t, "failure-allowed", &GuardError{
			Code: ErrorCodeUnavailable, Retryable: true,
		})
		require.NoError(t, err)
		require.NotNil(t, decision)
		require.True(t, decision.FailureAllowed)
		require.Equal(t, ErrorCodeUnavailable, event.ErrorCode)
		require.Equal(t, stableErrorMessage(ErrorCodeUnavailable), event.ErrorMessage)
	})

	t.Run("invalid response remains blocked and recorded", func(t *testing.T) {
		decision, event, err := run(t, "failure-blocked", &GuardError{
			Code: ErrorCodeInvalidResponse,
		})
		require.Nil(t, decision)
		require.Error(t, err)
		require.Equal(t, ErrorCodeInvalidResponse, event.ErrorCode)
		require.Equal(t, stableErrorMessage(ErrorCodeInvalidResponse), event.ErrorMessage)
	})
}

func TestPromptAuditDatabasePersistsFullPromptInChatRecordsOnly(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	const promptCanary = "PROMPT_AUDIT_CANARY_SECRET_DO_NOT_PERSIST"
	promptText := strings.Repeat("长", 70000) + promptCanary
	userID := insertIdentity(t, db, "users")
	body, err := json.Marshal(map[string]any{"messages": []map[string]string{{"role": "user", "content": promptText}}})
	require.NoError(t, err)
	request := Request{
		RequestID: "canary-request", ClientIP: "203.0.113.42", Provider: "openai",
		Endpoint: "/v1/chat/completions", Protocol: "openai_chat", Model: "gpt-test", Stage: "http", UserID: userID,
		Body: body,
	}
	snapshot, err := ExtractPromptSnapshot(request)
	require.NoError(t, err)
	snapshot.FullContextCiphertext = "encrypted-complete-context"
	snapshot.FullContextHash = strings.Repeat("a", 64)
	snapshot.FullContextBytes = 1234
	snapshot.FullContextSegmentCount = 2
	require.NotContains(t, snapshot.RedactedPreview, promptCanary)
	// 完整证据不等于列表摘要，完整文本仅在管理员详情路径展示。
	require.Equal(t, promptText, snapshot.FullPrompt)
	require.False(t, snapshot.FullPromptTruncated)
	event, err := repo.RecordBlocking(ctx, snapshot.Redacted(), 1, integrationResult(EventCritical), true)
	require.NoError(t, err)
	// The event response resolves retained content from the chat record; the
	// event table and transient job row never contain the canary.
	adminJSON, err := json.Marshal(event)
	require.NoError(t, err)
	require.Contains(t, string(adminJSON), promptCanary)
	require.NotContains(t, event.Snapshot.RedactedPreview, promptCanary)
	require.Equal(t, promptText, event.Snapshot.FullPrompt)
	require.Equal(t, "203.0.113.42", event.Snapshot.ClientIP)
	require.Equal(t, ModeBlocking, event.ExecutionMode)
	require.NotNil(t, event.QueueDelayMS)
	require.Zero(t, *event.QueueDelayMS)
	require.NotNil(t, event.InputLimit)
	require.Equal(t, 500000, *event.InputLimit)
	require.NotNil(t, event.MatchedChunkIndex)
	require.Equal(t, 1, *event.MatchedChunkIndex)
	require.Equal(t, "Primary Guard", event.GuardEndpointName)
	require.Equal(t, "guard-model", event.GuardModel)
	require.False(t, event.Snapshot.FullPromptTruncated)
	require.True(t, event.FullContextAvailable)

	var storedFullPrompt string
	require.NoError(t, db.QueryRow(`SELECT full_prompt FROM prompt_audit_events WHERE id=$1`, event.ID).Scan(&storedFullPrompt))
	require.Empty(t, storedFullPrompt)
	var storedChatPrompt string
	require.NoError(t, db.QueryRow(`SELECT full_prompt FROM prompt_audit_chat_records WHERE id=$1`, event.Snapshot.ChatRecordID).Scan(&storedChatPrompt))
	require.Contains(t, storedChatPrompt, promptCanary)

	detail, err := repo.GetEvent(ctx, event.ID)
	require.NoError(t, err)
	require.Contains(t, detail.Snapshot.FullPrompt, promptCanary)
	require.True(t, detail.FullContextAvailable)
	contextRecord, err := repo.GetEventContext(ctx, event.ID)
	require.NoError(t, err)
	require.Equal(t, "encrypted-complete-context", contextRecord.Ciphertext)
	require.Equal(t, strings.Repeat("a", 64), contextRecord.SHA256)

	var jobJSON string
	require.NoError(t, db.QueryRow(`SELECT row_to_json(j)::text FROM prompt_audit_jobs j WHERE id=$1`, event.JobID).Scan(&jobJSON))
	require.NotContains(t, jobJSON, promptCanary)

	failureSnapshot := integrationSnapshot("error")
	failureSnapshot.BlockingExemptAtRequest = true
	failedJob, err := repo.CreateStagingWithCapacity(ctx, failureSnapshot, ModeAsyncDeep, 1, 3, 10)
	require.NoError(t, err)
	const errorCanary = "GUARD_RAW_RESPONSE_CANARY_SECRET"
	require.NoError(t, repo.MarkStagingFailed(ctx, failedJob.ID, "payload_store_failed", "raw guard body: "+errorCanary))
	var code, message string
	require.NoError(t, db.QueryRow(`SELECT last_error_code,last_error_message FROM prompt_audit_jobs WHERE id=$1`, failedJob.ID).Scan(&code, &message))
	require.Equal(t, "payload_store_failed", code)
	require.Equal(t, stableErrorMessage(code), message)
	require.NotContains(t, message, errorCanary)
	require.LessOrEqual(t, len([]rune(message)), 160)
	failureEvent, err := repo.RecordFailureEvent(ctx, failedJob, code)
	require.NoError(t, err)
	require.Equal(t, EventFailed, failureEvent.Decision)
	require.True(t, failureEvent.Snapshot.BlockingExemptAtRequest)
	failureDetail, err := repo.GetEvent(ctx, failureEvent.ID)
	require.NoError(t, err)
	require.True(t, failureDetail.Snapshot.BlockingExemptAtRequest)

	_, err = repo.DeleteEvent(ctx, event.ID)
	require.NoError(t, err)
	_, err = repo.GetEventContext(ctx, event.ID)
	require.ErrorIs(t, err, ErrEventContextNotFound)
}

func TestPromptAuditRepositoryAdmissionClaimFencingAndEventTransaction(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()

	start := make(chan struct{})
	type admissionResult struct {
		job *Job
		err error
	}
	results := make(chan admissionResult, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			job, err := repo.CreateStagingWithCapacity(ctx, integrationSnapshot(string(rune('a'+index))), ModeAsync, 1, 3, 1)
			results <- admissionResult{job: job, err: err}
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	var accepted *Job
	rejected := 0
	for result := range results {
		if result.err == nil {
			require.Nil(t, accepted)
			accepted = result.job
			continue
		}
		require.True(t, errors.Is(result.err, ErrQueueFull) || errors.Is(result.err, ErrQueueAdmissionBusy))
		rejected++
	}
	require.NotNil(t, accepted)
	require.Equal(t, 1, rejected)
	stats, err := repo.QueueStats(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), stats.Active)
	require.NoError(t, repo.PublishQueued(ctx, accepted.ID))

	claimStart := make(chan struct{})
	claims := make(chan *Job, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-claimStart
			job, claimed, claimErr := repo.ClaimNextJob(ctx, time.Now().Add(time.Second))
			require.NoError(t, claimErr)
			if claimed {
				claims <- job
			}
		}()
	}
	close(claimStart)
	wg.Wait()
	close(claims)
	claimedJobs := make([]*Job, 0, 1)
	for job := range claims {
		claimedJobs = append(claimedJobs, job)
	}
	require.Len(t, claimedJobs, 1)
	firstClaim := claimedJobs[0]
	require.Equal(t, int64(1), firstClaim.ClaimVersion)

	reclaimed, err := repo.ReclaimStale(ctx, time.Now().Add(time.Hour), time.Now().Add(time.Hour), 10)
	require.NoError(t, err)
	require.Equal(t, int64(1), reclaimed)
	secondClaim, claimed, err := repo.ClaimNextJob(ctx, time.Now().Add(time.Second))
	require.NoError(t, err)
	require.True(t, claimed)
	require.Greater(t, secondClaim.ClaimVersion, firstClaim.ClaimVersion)
	require.ErrorIs(t, repo.RefreshLease(ctx, firstClaim.ID, firstClaim.ClaimVersion, time.Now()), ErrLeaseLost)
	_, err = repo.Complete(ctx, firstClaim, integrationResult(EventCritical), true)
	require.ErrorIs(t, err, ErrLeaseLost)

	event, err := repo.Complete(ctx, secondClaim, integrationResult(EventCritical), true)
	require.NoError(t, err)
	require.NotNil(t, event)
	require.NotNil(t, event.QueueDelayMS)
	require.GreaterOrEqual(t, *event.QueueDelayMS, 0)
	require.Equal(t, ModeAsync, event.ExecutionMode)
	var status string
	var eventCount int
	require.NoError(t, db.QueryRow(`SELECT status FROM prompt_audit_jobs WHERE id=$1`, secondClaim.ID).Scan(&status))
	require.Equal(t, "done", status)
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM prompt_audit_events WHERE job_id=$1`, secondClaim.ID).Scan(&eventCount))
	require.Equal(t, 1, eventCount)

	staging, err := repo.CreateStagingWithCapacity(ctx, integrationSnapshot("stale"), ModeAsync, 1, 3, 10)
	require.NoError(t, err)
	reclaimed, err = repo.ReclaimStale(ctx, time.Now().Add(time.Hour), time.Now().Add(time.Hour), 10)
	require.NoError(t, err)
	require.Equal(t, int64(1), reclaimed)
	require.NoError(t, db.QueryRow(`SELECT status FROM prompt_audit_jobs WHERE id=$1`, staging.ID).Scan(&status))
	require.Equal(t, "failed", status)
}

func TestPromptAuditRepositoryForeignKeysFiltersAndStableIdentitySnapshots(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	userID := insertIdentity(t, db, "users")
	apiKeyID := insertIdentity(t, db, "api_keys")
	groupID := insertIdentity(t, db, "groups")
	snapshot := integrationSnapshot("identity")
	snapshot.UserID, snapshot.APIKeyID, snapshot.GroupID = userID, apiKeyID, &groupID
	event, err := repo.RecordBlocking(ctx, snapshot, 7, integrationResult(EventCritical), true)
	require.NoError(t, err)
	require.NotNil(t, event)

	start, end := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	page, err := repo.ListEvents(ctx, EventFilter{
		Decision: string(EventCritical), RiskLevel: string(RiskCritical), Endpoint: snapshot.Endpoint,
		GroupID: &groupID, UserID: &userID, APIKeyID: &apiKeyID, RequestID: snapshot.RequestID,
		ClientIP: snapshot.ClientIP, PromptHash: snapshot.PromptHash, Keyword: snapshot.UsernameSnapshot, StartAt: &start, EndAt: &end,
	}, 1, 10)
	require.NoError(t, err)
	require.Equal(t, int64(1), page.Total)
	require.Len(t, page.Items, 1)
	require.NotEmpty(t, page.Items[0].IssueSummaries)
	require.Equal(t, snapshot.UsernameSnapshot, page.Items[0].Snapshot.UsernameSnapshot)
	require.Equal(t, snapshot.UserEmailSnapshot, page.Items[0].Snapshot.UserEmailSnapshot)
	require.Equal(t, snapshot.APIKeyNameSnapshot, page.Items[0].Snapshot.APIKeyNameSnapshot)
	require.Equal(t, snapshot.ClientIP, page.Items[0].Snapshot.ClientIP)

	_, err = db.Exec(`DELETE FROM users WHERE id=$1`, userID)
	require.NoError(t, err)
	_, err = db.Exec(`DELETE FROM api_keys WHERE id=$1`, apiKeyID)
	require.NoError(t, err)
	_, err = db.Exec(`DELETE FROM groups WHERE id=$1`, groupID)
	require.NoError(t, err)
	stored, err := repo.GetEvent(ctx, event.ID)
	require.NoError(t, err)
	require.Zero(t, stored.Snapshot.UserID)
	require.Zero(t, stored.Snapshot.APIKeyID)
	require.Nil(t, stored.Snapshot.GroupID)
	require.Equal(t, snapshot.UsernameSnapshot, stored.Snapshot.UsernameSnapshot)
	require.Equal(t, snapshot.UserEmailSnapshot, stored.Snapshot.UserEmailSnapshot)
	require.Equal(t, snapshot.APIKeyNameSnapshot, stored.Snapshot.APIKeyNameSnapshot)

	_, err = db.Exec(`DELETE FROM prompt_audit_jobs WHERE id=$1`, event.JobID)
	require.NoError(t, err)
	_, err = repo.GetEvent(ctx, event.ID)
	require.ErrorIs(t, err, ErrEventNotFound)
}

func TestPromptAuditRepositoryHighWaterAndSafeDeletion(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	userID := insertIdentity(t, db, "users")
	firstSnapshot := integrationSnapshot("first")
	firstSnapshot.UserID = userID
	firstSnapshot.SessionKey = HashSessionKey(userID, firstSnapshot.Protocol, "header:session-id", "highwater-first")
	firstSnapshot.SessionSource = "client_session"
	firstSnapshot.FullPrompt = "first full prompt"
	firstSnapshot.FullContextCiphertext = strings.Repeat("a", 4096)
	firstSnapshot.FullContextHash = strings.Repeat("1", 64)
	firstSnapshot.FullContextBytes = 4096
	firstSnapshot.FullContextSegmentCount = 2
	first, err := repo.RecordBlocking(ctx, firstSnapshot, 1, integrationResult(EventCritical), true)
	require.NoError(t, err)
	secondSnapshot := integrationSnapshot("second")
	secondSnapshot.UserID = userID
	secondSnapshot.SessionKey = firstSnapshot.SessionKey
	secondSnapshot.SessionSource = firstSnapshot.SessionSource
	secondSnapshot.FullPrompt = "second full prompt"
	secondSnapshot.FullContextCiphertext = strings.Repeat("b", 2048)
	secondSnapshot.FullContextHash = strings.Repeat("2", 64)
	secondSnapshot.FullContextBytes = 2048
	secondSnapshot.FullContextSegmentCount = 1
	second, err := repo.RecordBlocking(ctx, secondSnapshot, 1, integrationResult(EventCritical), true)
	require.NoError(t, err)
	start, end := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	filter := EventFilter{Decision: string(EventCritical), StartAt: &start, EndAt: &end}
	preview, err := repo.PreviewDelete(ctx, filter)
	require.NoError(t, err)
	require.Equal(t, int64(2), preview.MatchedCount)
	require.Equal(t, int64(2), preview.MatchedContextCount)
	require.Positive(t, preview.EstimatedReclaimableBytes)
	require.Equal(t, second.ID, preview.SnapshotMaxID)
	require.Equal(t, FilterHash(preview.FilterSummary, preview.SnapshotMaxID), preview.FilterHash)

	newer, err := repo.RecordBlocking(ctx, integrationSnapshot("newer"), 1, integrationResult(EventCritical), true)
	require.NoError(t, err)
	result, err := repo.DeleteEventsByFilter(ctx, filter, preview.SnapshotMaxID, 1)
	require.NoError(t, err)
	require.Equal(t, int64(2), result.DeletedEvents)
	require.Equal(t, int64(2), result.DeletedJobs)
	_, err = repo.GetEvent(ctx, first.ID)
	require.ErrorIs(t, err, ErrEventNotFound)
	_, err = repo.GetEvent(ctx, second.ID)
	require.ErrorIs(t, err, ErrEventNotFound)
	_, err = repo.GetEvent(ctx, newer.ID)
	require.NoError(t, err, "an event created after preview must survive high-water deletion")

	processingEvent, err := repo.RecordBlocking(ctx, integrationSnapshot("processing"), 1, integrationResult(EventCritical), true)
	require.NoError(t, err)
	_, err = db.Exec(`UPDATE prompt_audit_jobs SET status='processing' WHERE id=$1`, processingEvent.JobID)
	require.NoError(t, err)
	deleteResult, err := repo.DeleteEvent(ctx, processingEvent.ID)
	require.NoError(t, err)
	require.Equal(t, int64(1), deleteResult.DeletedEvents)
	require.Zero(t, deleteResult.DeletedJobs)
	var remaining int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM prompt_audit_jobs WHERE id=$1`, processingEvent.JobID).Scan(&remaining))
	require.Equal(t, 1, remaining, "processing jobs must not be deleted as orphans")

	batchOne, err := repo.RecordBlocking(ctx, integrationSnapshot("batch-one"), 1, integrationResult(EventCritical), true)
	require.NoError(t, err)
	batchTwo, err := repo.RecordBlocking(ctx, integrationSnapshot("batch-two"), 1, integrationResult(EventCritical), true)
	require.NoError(t, err)
	ids := []int64{batchTwo.ID, batchOne.ID, batchOne.ID}
	sort.Slice(ids, func(i, j int) bool { return ids[i] > ids[j] })
	batchResult, err := repo.DeleteEventsByIDs(ctx, ids)
	require.NoError(t, err)
	require.Equal(t, int64(2), batchResult.DeletedEvents)
}

func TestPromptAuditServiceConfirmationKeepsPostPreviewEventsAndConcurrentDeletesAreSafe(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()
	start, end := now.Add(-time.Hour), now.Add(time.Hour)
	filter := EventFilter{Decision: string(EventCritical), StartAt: &start, EndAt: &end}

	for i := 0; i < 12; i++ {
		_, err := repo.RecordBlocking(ctx, integrationSnapshot(fmt.Sprintf("event-%02d", i)), 1, integrationResult(EventCritical), true)
		require.NoError(t, err)
	}
	service := &PromptService{
		config: &fakeConfigStore{}, repo: repo, payload: NewRedisPayloadStore(nil), clock: fixedClock{now: now},
	}
	preview, err := service.PreviewDelete(ctx, filter, 77)
	require.NoError(t, err)
	require.Equal(t, int64(12), preview.MatchedCount)

	newer, err := repo.RecordBlocking(ctx, integrationSnapshot("post-preview"), 1, integrationResult(EventCritical), true)
	require.NoError(t, err)
	result, err := service.DeleteByFilter(ctx, DeleteByFilterRequest{
		Filter: filter, SnapshotMaxID: preview.SnapshotMaxID, FilterHash: preview.FilterHash,
		ConfirmationToken: preview.ConfirmationToken, Confirm: true,
	}, 77)
	require.NoError(t, err)
	require.Equal(t, int64(12), result.DeletedEvents)
	_, err = repo.GetEvent(ctx, newer.ID)
	require.NoError(t, err, "events created after delete-preview must survive")

	resetPromptAuditIntegrationDB(t, db)
	for i := 0; i < 24; i++ {
		_, err := repo.RecordBlocking(ctx, integrationSnapshot(fmt.Sprintf("race-%02d", i)), 1, integrationResult(EventCritical), true)
		require.NoError(t, err)
	}
	preview, err = repo.PreviewDelete(ctx, filter)
	require.NoError(t, err)

	type deleteOutcome struct {
		result *DeleteResult
		err    error
	}
	outcomes := make(chan deleteOutcome, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			deleted, deleteErr := repo.DeleteEventsByFilter(ctx, filter, preview.SnapshotMaxID, 1)
			outcomes <- deleteOutcome{result: deleted, err: deleteErr}
		}()
	}
	wg.Wait()
	close(outcomes)
	var deletedTotal int64
	for outcome := range outcomes {
		require.NoError(t, outcome.err)
		require.NotNil(t, outcome.result)
		deletedTotal += outcome.result.DeletedEvents
	}
	require.Equal(t, int64(24), deletedTotal, "concurrent deleters must neither double-count nor strand matching events")
	remaining, err := repo.ListEvents(ctx, filter, 1, 100)
	require.NoError(t, err)
	require.Zero(t, remaining.Total)
}
