package securityaudit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
)

type EventFilter struct {
	SessionID     *int64     `json:"session_id,omitempty"`
	Decision      string     `json:"decision,omitempty"`
	RiskLevel     string     `json:"risk_level,omitempty"`
	ExecutionMode string     `json:"execution_mode,omitempty"`
	Endpoint      string     `json:"endpoint,omitempty"`
	GroupID       *int64     `json:"group_id,omitempty"`
	UserID        *int64     `json:"user_id,omitempty"`
	APIKeyID      *int64     `json:"api_key_id,omitempty"`
	RequestID     string     `json:"request_id,omitempty"`
	ClientIP      string     `json:"client_ip,omitempty"`
	PromptHash    string     `json:"prompt_hash,omitempty"`
	Keyword       string     `json:"keyword,omitempty"`
	StartAt       *time.Time `json:"start_at,omitempty"`
	EndAt         *time.Time `json:"end_at,omitempty"`
}

type EventPage struct {
	Items    []*Event `json:"items"`
	Total    int64    `json:"total"`
	Page     int      `json:"page"`
	PageSize int      `json:"page_size"`
	Pages    int      `json:"pages"`
}

type DeletePreview struct {
	MatchedCount              int64       `json:"matched_count"`
	MatchedContextCount       int64       `json:"matched_context_count"`
	EstimatedReclaimableBytes int64       `json:"estimated_reclaimable_bytes"`
	FilterSummary             EventFilter `json:"filter_summary"`
	SnapshotMaxID             int64       `json:"snapshot_max_id"`
	FilterHash                string      `json:"filter_hash"`
	ConfirmationToken         string      `json:"confirmation_token,omitempty"`
	ExpiresAt                 time.Time   `json:"expires_at,omitempty"`
}

type DeleteResult struct {
	DeletedEvents int64   `json:"deleted_events"`
	DeletedJobs   int64   `json:"deleted_jobs"`
	JobIDs        []int64 `json:"-"`
}

type EventRepository interface {
	ListEvents(ctx context.Context, filter EventFilter, page, pageSize int) (*EventPage, error)
	GetEvent(ctx context.Context, id int64) (*Event, error)
	GetSessionChatRecords(ctx context.Context, eventID int64, limit int) (*UserChatSession, error)
	DeleteExpiredChatRecords(ctx context.Context, now time.Time, limit int) (int64, error)
	DeleteOrphanChatRecords(ctx context.Context, limit int) (int64, error)
	DeleteEvent(ctx context.Context, id int64) (*DeleteResult, error)
	DeleteEventsByIDs(ctx context.Context, ids []int64) (*DeleteResult, error)
	PreviewDelete(ctx context.Context, filter EventFilter) (*DeletePreview, error)
	DeleteEventsByFilter(ctx context.Context, filter EventFilter, snapshotMaxID int64, batchSize int) (*DeleteResult, error)
}

func (r *PostgreSQLRepository) ListEvents(ctx context.Context, filter EventFilter, page, pageSize int) (*EventPage, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	where, args := buildEventWhere(filter, 1)
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM prompt_audit_events e`+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	queryArgs := append([]any(nil), args...)
	limitIndex := len(queryArgs) + 1
	queryArgs = append(queryArgs, pageSize, (page-1)*pageSize)
	rows, err := r.db.QueryContext(ctx, `SELECT `+eventColumns("e")+`,EXISTS(SELECT 1 FROM prompt_audit_chat_records c WHERE c.id=e.chat_record_id AND NULLIF(c.context_ciphertext,'') IS NOT NULL AND (c.retention_until IS NULL OR c.retention_until>NOW())) FROM prompt_audit_events e`+where+
		fmt.Sprintf(` ORDER BY e.created_at DESC, e.id DESC LIMIT $%d OFFSET $%d`, limitIndex, limitIndex+1), queryArgs...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	items := make([]*Event, 0, pageSize)
	for rows.Next() {
		event, err := scanEvent(rows, false, true)
		if err != nil {
			return nil, err
		}
		items = append(items, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	pages := 0
	if total > 0 {
		pages = int((total + int64(pageSize) - 1) / int64(pageSize))
	}
	return &EventPage{Items: items, Total: total, Page: page, PageSize: pageSize, Pages: pages}, nil
}

func (r *PostgreSQLRepository) GetEvent(ctx context.Context, id int64) (*Event, error) {
	event, err := scanEvent(r.db.QueryRowContext(ctx, `SELECT `+eventDetailColumnsWithChat("e")+` FROM prompt_audit_events e
		LEFT JOIN prompt_audit_chat_records c ON c.id=e.chat_record_id AND (c.retention_until IS NULL OR c.retention_until>NOW()) WHERE e.id=$1`, id), true)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEventNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := r.db.QueryRowContext(ctx, `SELECT
		EXISTS(SELECT 1 FROM prompt_audit_events e
		JOIN prompt_audit_chat_records c ON c.id=e.chat_record_id
		WHERE e.id=$1 AND NULLIF(c.context_ciphertext, '') IS NOT NULL AND (c.retention_until IS NULL OR c.retention_until>NOW()))
		OR EXISTS(SELECT 1 FROM prompt_audit_event_contexts c WHERE c.event_id=$1)`, id).Scan(&event.FullContextAvailable); err != nil {
		return nil, err
	}
	return event, nil
}

func (r *PostgreSQLRepository) GetSessionChatRecords(ctx context.Context, eventID int64, limit int) (*UserChatSession, error) {
	if eventID <= 0 {
		return nil, ErrEventNotFound
	}
	if limit < 1 || limit > maxUserAnalysisRecords {
		limit = maxUserAnalysisRecords
	}
	session := &UserChatSession{}
	var userID, selectedRecordID sql.NullInt64
	var legacyPrompt, protocol string
	var eventCreatedAt time.Time
	if err := r.db.QueryRowContext(ctx, `
		SELECT user_id,username_snapshot,user_email_snapshot,session_key,session_source,
		       chat_record_id,full_prompt,protocol,created_at
		FROM prompt_audit_events WHERE id=$1`, eventID).Scan(
		&userID, &session.Username, &session.UserEmail, &session.SessionKey, &session.SessionSource,
		&selectedRecordID, &legacyPrompt, &protocol, &eventCreatedAt); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEventNotFound
	} else if err != nil {
		return nil, err
	}
	session.UserID = nullableInt64Value(userID)
	session.SelectedRecordID = nullableInt64Value(selectedRecordID)
	if session.UserID <= 0 || strings.TrimSpace(session.SessionKey) == "" {
		if session.UserID > 0 && strings.TrimSpace(legacyPrompt) != "" {
			session.SessionSource = "legacy_event"
			session.SessionKey = HashSessionKey(session.UserID, protocol, session.SessionSource, strconv.FormatInt(eventID, 10))
			session.Records = []UserChatRecord{{
				SessionKey: session.SessionKey, SessionSource: session.SessionSource,
				FullPrompt: legacyPrompt, CreatedAt: eventCreatedAt,
			}}
		}
		return session, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT c.id, c.content_hash, c.full_prompt,
		       c.full_prompt_truncated, c.created_at
		FROM prompt_audit_chat_records c
		JOIN prompt_audit_sessions s ON s.id=c.session_id
		WHERE s.user_id=$1 AND s.session_key=$2 AND (c.retention_until IS NULL OR c.retention_until>NOW())
		ORDER BY (c.id=$3) DESC, c.created_at DESC, c.id DESC LIMIT $4`,
		session.UserID, session.SessionKey, session.SelectedRecordID, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	session.Records = make([]UserChatRecord, 0, limit)
	for rows.Next() {
		var record UserChatRecord
		if err := rows.Scan(&record.ID, &record.ContentHash,
			&record.FullPrompt, &record.FullPromptTruncated, &record.CreatedAt); err != nil {
			return nil, err
		}
		record.SessionKey = session.SessionKey
		record.SessionSource = session.SessionSource
		session.Records = append(session.Records, record)
	}
	return session, rows.Err()
}

func (r *PostgreSQLRepository) DeleteExpiredChatRecords(ctx context.Context, now time.Time, limit int) (int64, error) {
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	result, err := r.db.ExecContext(ctx, `
		WITH expired AS (
			SELECT id FROM prompt_audit_chat_records
			WHERE retention_until IS NOT NULL AND retention_until <= $1
			ORDER BY retention_until, id LIMIT $2 FOR UPDATE SKIP LOCKED
		)
		DELETE FROM prompt_audit_chat_records c USING expired e WHERE c.id=e.id`, now.UTC(), limit)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (r *PostgreSQLRepository) DeleteOrphanChatRecords(ctx context.Context, limit int) (int64, error) {
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	result, err := r.db.ExecContext(ctx, `
		WITH orphaned AS (
			SELECT c.id FROM prompt_audit_chat_records c
			WHERE NOT EXISTS (SELECT 1 FROM prompt_audit_events e WHERE e.chat_record_id=c.id)
			ORDER BY c.id LIMIT $1 FOR UPDATE SKIP LOCKED
		)
		DELETE FROM prompt_audit_chat_records c USING orphaned o WHERE c.id=o.id`, limit)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// @project-doc docs/domains/prompt_audit.md#chat_content_capacity
// DeleteOldestChatRecordsToLimit 删除最老的完整聊天正文，直到逻辑正文大小不超过上限。
// 事件元数据保留，chat_record_id 允许成为悬空引用；这与备份排除正文表的契约一致。
func (r *PostgreSQLRepository) DeleteOldestChatRecordsToLimit(ctx context.Context, maxBytes int64, limit int) (deleted int64, remainingBytes int64, err error) {
	if maxBytes <= 0 {
		return 0, 0, nil
	}
	if limit < 1 || limit > 1000 {
		limit = 500
	}
	result, err := r.db.ExecContext(ctx, `
		WITH stats AS (
			SELECT COALESCE(SUM(pg_column_size(full_prompt) + COALESCE(pg_column_size(context_ciphertext), 0)), 0)::bigint AS bytes
			FROM prompt_audit_chat_records
		), ranked AS (
			SELECT id, created_at,
			       ROW_NUMBER() OVER (ORDER BY created_at, id) AS row_number,
			       SUM(pg_column_size(full_prompt) + COALESCE(pg_column_size(context_ciphertext), 0))
			           OVER (ORDER BY created_at, id ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS cumulative_bytes
			FROM prompt_audit_chat_records
		), victims AS (
			SELECT ranked.id
			FROM ranked CROSS JOIN stats
			WHERE stats.bytes > $1
			  AND (ranked.row_number = 1 OR ranked.cumulative_bytes <= stats.bytes - $1)
			ORDER BY ranked.created_at, ranked.id
			LIMIT $2
		)
		DELETE FROM prompt_audit_chat_records c
		USING victims
		WHERE c.id = victims.id`, maxBytes, limit)
	if err != nil {
		return 0, 0, err
	}
	deleted, err = result.RowsAffected()
	if err != nil {
		return 0, 0, err
	}
	if err := r.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(pg_column_size(full_prompt) + COALESCE(pg_column_size(context_ciphertext), 0)), 0)::bigint
		FROM prompt_audit_chat_records`).Scan(&remainingBytes); err != nil {
		return deleted, 0, err
	}
	return deleted, remainingBytes, nil
}

type eventContextRecord struct {
	Ciphertext string
	SHA256     string
}

func (r *PostgreSQLRepository) GetEventContext(ctx context.Context, id int64) (eventContextRecord, error) {
	var result eventContextRecord
	err := r.db.QueryRowContext(ctx, `
		SELECT context_ciphertext,context_sha256 FROM (
			SELECT c.context_ciphertext,c.context_sha256,1 AS priority
			FROM prompt_audit_events e
			JOIN prompt_audit_chat_records c ON c.id=e.chat_record_id
			WHERE e.id=$1 AND NULLIF(c.context_ciphertext, '') IS NOT NULL AND (c.retention_until IS NULL OR c.retention_until>NOW())
			UNION ALL
			SELECT c.context_ciphertext,c.context_sha256,2 AS priority
			FROM prompt_audit_event_contexts c WHERE c.event_id=$1
		) available ORDER BY priority LIMIT 1`, id).Scan(&result.Ciphertext, &result.SHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return eventContextRecord{}, ErrEventContextNotFound
	}
	return result, err
}

func (r *PostgreSQLRepository) DeleteEvent(ctx context.Context, id int64) (*DeleteResult, error) {
	return r.DeleteEventsByIDs(ctx, []int64{id})
}

func (r *PostgreSQLRepository) DeleteEventsByIDs(ctx context.Context, ids []int64) (*DeleteResult, error) {
	ids = canonicalInt64s(ids)
	if len(ids) == 0 {
		return &DeleteResult{}, nil
	}
	if len(ids) > 500 {
		return nil, errors.New("prompt audit delete batch exceeds 500 events")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `DELETE FROM prompt_audit_events WHERE id=ANY($1) RETURNING job_id`, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	jobIDs, err := scanReturnedJobIDs(rows)
	if err != nil {
		return nil, err
	}
	if _, err := deleteOrphanChatRecordsTx(ctx, tx, 1000); err != nil {
		return nil, err
	}
	deletedJobs, err := deleteOrphanJobs(ctx, tx, jobIDs)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &DeleteResult{DeletedEvents: int64(len(jobIDs)), DeletedJobs: deletedJobs, JobIDs: canonicalInt64s(jobIDs)}, nil
}

func (r *PostgreSQLRepository) PreviewDelete(ctx context.Context, filter EventFilter) (*DeletePreview, error) {
	if err := validateDeleteFilter(filter); err != nil {
		return nil, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	where, args := buildEventWhere(filter, 1)
	var count, contextCount, estimatedBytes, maxID int64
	if err := tx.QueryRowContext(ctx, `
		WITH matched AS (
			SELECT e.id, e.chat_record_id FROM prompt_audit_events e`+where+`
		), chat AS (
			SELECT DISTINCT c.id, c.full_prompt, c.context_ciphertext
			FROM prompt_audit_chat_records c
			JOIN matched m ON m.chat_record_id=c.id
			WHERE NOT EXISTS (
				SELECT 1 FROM prompt_audit_events other
				WHERE other.chat_record_id=c.id
				  AND NOT EXISTS (SELECT 1 FROM matched selected WHERE selected.id=other.id)
			)
		)
		SELECT
			(SELECT COUNT(*) FROM matched),
			(SELECT COALESCE(MAX(id),0) FROM matched),
			(SELECT COUNT(*) FROM chat),
			(SELECT COALESCE(SUM(pg_column_size(full_prompt) + COALESCE(pg_column_size(context_ciphertext),0)),0) FROM chat)`,
		args...).Scan(&count, &maxID, &contextCount, &estimatedBytes); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	canonical := canonicalEventFilter(filter)
	return &DeletePreview{
		MatchedCount: count, MatchedContextCount: contextCount, EstimatedReclaimableBytes: estimatedBytes,
		FilterSummary: canonical, SnapshotMaxID: maxID, FilterHash: FilterHash(canonical, maxID),
	}, nil
}

func (r *PostgreSQLRepository) DeleteEventsByFilter(ctx context.Context, filter EventFilter, snapshotMaxID int64, batchSize int) (*DeleteResult, error) {
	if err := validateDeleteFilter(filter); err != nil {
		return nil, err
	}
	if snapshotMaxID <= 0 {
		return &DeleteResult{}, nil
	}
	if batchSize < 1 || batchSize > 1000 {
		batchSize = 200
	}
	total := &DeleteResult{}
	jobSet := map[int64]struct{}{}
	for {
		tx, err := r.db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		where, args := buildEventWhere(filter, 1)
		maxIndex := len(args) + 1
		limitIndex := maxIndex + 1
		args = append(args, snapshotMaxID, batchSize)
		rows, err := tx.QueryContext(ctx, `
			WITH selected AS (
				SELECT e.id FROM prompt_audit_events e`+where+
			fmt.Sprintf(` AND e.id <= $%d ORDER BY e.id LIMIT $%d FOR UPDATE SKIP LOCKED`, maxIndex, limitIndex)+`
			), deleted AS (
				DELETE FROM prompt_audit_events e USING selected s WHERE e.id=s.id RETURNING e.job_id
			) SELECT job_id FROM deleted`, args...)
		if err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		jobIDs, err := scanReturnedJobIDs(rows)
		if err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		if _, err := deleteOrphanChatRecordsTx(ctx, tx, batchSize); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		deletedJobs, err := deleteOrphanJobs(ctx, tx, jobIDs)
		if err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		total.DeletedEvents += int64(len(jobIDs))
		total.DeletedJobs += deletedJobs
		for _, id := range jobIDs {
			jobSet[id] = struct{}{}
		}
		if len(jobIDs) < batchSize {
			break
		}
	}
	for id := range jobSet {
		total.JobIDs = append(total.JobIDs, id)
	}
	total.JobIDs = canonicalInt64s(total.JobIDs)
	return total, nil
}

func FilterHash(filter EventFilter, snapshotMaxID int64) string {
	payload := struct {
		Filter        EventFilter `json:"filter"`
		SnapshotMaxID int64       `json:"snapshot_max_id"`
	}{canonicalEventFilter(filter), snapshotMaxID}
	raw, _ := json.Marshal(payload)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func validateDeleteFilter(filter EventFilter) error {
	if filter.StartAt == nil || filter.EndAt == nil || !filter.StartAt.Before(*filter.EndAt) {
		return errors.New("prompt audit filter delete requires a valid explicit time range")
	}
	if strings.TrimSpace(filter.ClientIP) != "" && normalizePromptClientIP(filter.ClientIP) == "" {
		return errors.New("prompt audit filter contains an invalid client IP")
	}
	return nil
}

func canonicalEventFilter(filter EventFilter) EventFilter {
	filter.Decision = strings.TrimSpace(strings.ToLower(filter.Decision))
	filter.RiskLevel = strings.TrimSpace(strings.ToLower(filter.RiskLevel))
	filter.ExecutionMode = strings.TrimSpace(strings.ToLower(filter.ExecutionMode))
	filter.Endpoint = strings.TrimSpace(filter.Endpoint)
	filter.RequestID = strings.TrimSpace(filter.RequestID)
	if normalized := normalizePromptClientIP(filter.ClientIP); normalized != "" {
		filter.ClientIP = normalized
	} else {
		filter.ClientIP = strings.TrimSpace(filter.ClientIP)
	}
	filter.PromptHash = strings.ToLower(strings.TrimSpace(filter.PromptHash))
	filter.Keyword = strings.TrimSpace(filter.Keyword)
	if filter.StartAt != nil {
		value := filter.StartAt.UTC()
		filter.StartAt = &value
	}
	if filter.EndAt != nil {
		value := filter.EndAt.UTC()
		filter.EndAt = &value
	}
	return filter
}

func buildEventWhere(filter EventFilter, firstIndex int) (string, []any) {
	filter = canonicalEventFilter(filter)
	clauses := []string{" WHERE TRUE"}
	args := make([]any, 0, 12)
	add := func(clause string, value any) {
		clauses = append(clauses, fmt.Sprintf(clause, firstIndex+len(args)))
		args = append(args, value)
	}
	if filter.Decision != "" {
		add(" AND e.decision=$%d", filter.Decision)
	}
	if filter.RiskLevel != "" {
		add(" AND e.risk_level=$%d", filter.RiskLevel)
	}
	if filter.ExecutionMode != "" {
		add(" AND e.execution_mode=$%d", filter.ExecutionMode)
	}
	if filter.Endpoint != "" {
		add(" AND e.endpoint=$%d", filter.Endpoint)
	}
	if filter.GroupID != nil {
		add(" AND e.group_id=$%d", *filter.GroupID)
	}
	if filter.UserID != nil {
		add(" AND e.user_id=$%d", *filter.UserID)
	}
	if filter.SessionID != nil {
		add(" AND EXISTS (SELECT 1 FROM prompt_audit_sessions s WHERE s.id=$%d AND s.user_id=e.user_id AND s.session_key=e.session_key)", *filter.SessionID)
	}
	if filter.APIKeyID != nil {
		add(" AND e.api_key_id=$%d", *filter.APIKeyID)
	}
	if filter.RequestID != "" {
		add(" AND e.request_id=$%d", filter.RequestID)
	}
	if filter.ClientIP != "" {
		add(" AND e.client_ip=$%d", filter.ClientIP)
	}
	if filter.PromptHash != "" {
		add(" AND e.prompt_hash=$%d", filter.PromptHash)
	}
	if filter.Keyword != "" {
		add(` AND (e.request_id ILIKE $%d OR e.client_ip ILIKE $%d OR e.prompt_hash ILIKE $%d OR e.redacted_preview ILIKE $%d
			OR e.username_snapshot ILIKE $%d OR e.user_email_snapshot ILIKE $%d OR e.api_key_name_snapshot ILIKE $%d
			OR e.error_code ILIKE $%d OR e.error_message ILIKE $%d)`, "%"+TrimRunes(filter.Keyword, 128)+"%")
		// The clause has several placeholders but add only supplied one. Rebuild it with one shared placeholder.
		clauses[len(clauses)-1] = fmt.Sprintf(` AND (e.request_id ILIKE $%[1]d OR e.client_ip ILIKE $%[1]d OR e.prompt_hash ILIKE $%[1]d OR e.redacted_preview ILIKE $%[1]d
			OR e.username_snapshot ILIKE $%[1]d OR e.user_email_snapshot ILIKE $%[1]d OR e.api_key_name_snapshot ILIKE $%[1]d
			OR e.error_code ILIKE $%[1]d OR e.error_message ILIKE $%[1]d)`, firstIndex+len(args)-1)
	}
	if filter.StartAt != nil {
		add(" AND e.created_at >= $%d", filter.StartAt.UTC())
	}
	if filter.EndAt != nil {
		add(" AND e.created_at <= $%d", filter.EndAt.UTC())
	}
	return strings.Join(clauses, ""), args
}

func eventColumns(alias string) string {
	return fmt.Sprintf(`%[1]s.id,%[1]s.job_id,%[1]s.request_id,%[1]s.user_id,%[1]s.username_snapshot,
		%[1]s.user_email_snapshot,%[1]s.api_key_id,%[1]s.api_key_name_snapshot,%[1]s.group_id,%[1]s.group_name,
		%[1]s.provider,%[1]s.endpoint,%[1]s.protocol,%[1]s.model,%[1]s.prompt_hash,%[1]s.redacted_preview,
		%[1]s.stage,%[1]s.decision,%[1]s.risk_level,%[1]s.action,%[1]s.categories,%[1]s.matched_scanners,
		%[1]s.scanner_scores,%[1]s.scanner_evidence,%[1]s.scanner_backend,%[1]s.scanner_version,
			%[1]s.guard_endpoint_id,%[1]s.guard_endpoint_name,%[1]s.guard_model,%[1]s.policy_id,%[1]s.policy_version,%[1]s.config_version,
		%[1]s.chunk_total,%[1]s.latency_ms,%[1]s.created_at,%[1]s.client_ip,%[1]s.prompt_length,
		%[1]s.message_count,%[1]s.execution_mode,%[1]s.queue_delay_ms,%[1]s.input_limit,
		%[1]s.matched_chunk_index,%[1]s.full_prompt_truncated,%[1]s.error_code,%[1]s.error_message,
		%[1]s.blocking_exempt_at_request,%[1]s.session_key,%[1]s.session_source,%[1]s.chat_record_id`, alias)
}

// eventDetailColumns includes the legacy full_prompt column for INSERT ...
// RETURNING compatibility. New writes keep that column empty; retained content
// is loaded from prompt_audit_chat_records instead.
func eventDetailColumns(alias string) string {
	return eventColumns(alias) + fmt.Sprintf(",%[1]s.full_prompt", alias)
}

func eventDetailColumnsWithChat(alias string) string {
	return eventColumns(alias) + fmt.Sprintf(",COALESCE(NULLIF(c.full_prompt,''),%[1]s.full_prompt,'')", alias)
}

func scanEvent(row rowScanner, withFullPrompt ...bool) (*Event, error) {
	event := &Event{}
	var userID, apiKeyID, groupID, chatRecordID sql.NullInt64
	var queueDelayMS, inputLimit, matchedChunkIndex sql.NullInt64
	var categories, matched, scores, evidence []byte
	dest := []any{&event.ID, &event.JobID, &event.Snapshot.RequestID, &userID,
		&event.Snapshot.UsernameSnapshot, &event.Snapshot.UserEmailSnapshot, &apiKeyID,
		&event.Snapshot.APIKeyNameSnapshot, &groupID, &event.Snapshot.GroupName,
		&event.Snapshot.Provider, &event.Snapshot.Endpoint, &event.Snapshot.Protocol, &event.Snapshot.Model,
		&event.Snapshot.PromptHash, &event.Snapshot.RedactedPreview, &event.Snapshot.Stage, &event.Decision,
		&event.RiskLevel, &event.Action, &categories, &matched, &scores, &evidence, &event.ScannerBackend,
		&event.ScannerVersion, &event.GuardEndpointID, &event.GuardEndpointName, &event.GuardModel, &event.PolicyID, &event.PolicyVersion,
		&event.ConfigVersion, &event.ChunkTotal, &event.LatencyMS, &event.CreatedAt, &event.Snapshot.ClientIP,
		&event.Snapshot.PromptLength, &event.Snapshot.MessageCount, &event.ExecutionMode, &queueDelayMS,
		&inputLimit, &matchedChunkIndex, &event.Snapshot.FullPromptTruncated,
		&event.ErrorCode, &event.ErrorMessage, &event.Snapshot.BlockingExemptAtRequest,
		&event.Snapshot.SessionKey, &event.Snapshot.SessionSource, &chatRecordID}
	if len(withFullPrompt) > 0 && withFullPrompt[0] {
		dest = append(dest, &event.Snapshot.FullPrompt)
	}
	// 列表只查询证据是否可用，不把完整会话正文读入列表响应。
	if len(withFullPrompt) > 1 && withFullPrompt[1] {
		dest = append(dest, &event.FullContextAvailable)
	}
	err := row.Scan(dest...)
	if err != nil {
		return nil, err
	}
	event.Snapshot.UserID = nullableInt64Value(userID)
	event.Snapshot.APIKeyID = nullableInt64Value(apiKeyID)
	event.Snapshot.GroupID = nullableInt64Ptr(groupID)
	event.Snapshot.ChatRecordID = nullableInt64Value(chatRecordID)
	event.QueueDelayMS = nullableIntPtr(queueDelayMS)
	event.InputLimit = nullableIntPtr(inputLimit)
	event.MatchedChunkIndex = nullableIntPtr(matchedChunkIndex)
	_ = json.Unmarshal(categories, &event.Categories)
	_ = json.Unmarshal(matched, &event.MatchedScanners)
	_ = json.Unmarshal(scores, &event.ScannerScores)
	_ = json.Unmarshal(evidence, &event.ScannerEvidence)
	// Older rows may retain every known category reported by Guard. The policy
	// intersection is the effective finding set and is never inferred from the
	// current configuration.
	event.Categories = append([]string(nil), event.MatchedScanners...)
	event.ScannerScores = effectiveScannerScores(event.MatchedScanners, event.ScannerScores)
	event.ScannerEvidence = effectiveScannerEvidence(event.MatchedScanners, event.ScannerEvidence)
	result := NormalizedResult{Decision: event.Decision, RiskLevel: event.RiskLevel, Action: event.Action,
		Categories: event.Categories, MatchedScanners: event.MatchedScanners, ScannerScores: event.ScannerScores,
		ScannerEvidence: event.ScannerEvidence}
	event.IssueSummaries = BuildIssueSummaries(result)
	return event, nil
}

func effectiveScannerScores(scanners []string, values map[string]float64) map[string]float64 {
	filtered := make(map[string]float64, len(scanners))
	for _, scanner := range scanners {
		if value, ok := values[scanner]; ok {
			filtered[scanner] = value
		}
	}
	return filtered
}

func effectiveScannerEvidence(scanners []string, values map[string]string) map[string]string {
	filtered := make(map[string]string, len(scanners))
	for _, scanner := range scanners {
		if value, ok := values[scanner]; ok {
			filtered[scanner] = value
		}
	}
	return filtered
}

func nullableIntPtr(value sql.NullInt64) *int {
	if !value.Valid {
		return nil
	}
	result := int(value.Int64)
	return &result
}

func scanReturnedJobIDs(rows *sql.Rows) ([]int64, error) {
	defer func() { _ = rows.Close() }()
	result := make([]int64, 0)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, rows.Err()
}

func deleteOrphanJobs(ctx context.Context, tx *sql.Tx, jobIDs []int64) (int64, error) {
	jobIDs = canonicalInt64s(jobIDs)
	if len(jobIDs) == 0 {
		return 0, nil
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM prompt_audit_jobs j
		WHERE j.id=ANY($1) AND j.status IN ('done','failed')
		AND NOT EXISTS (SELECT 1 FROM prompt_audit_events e WHERE e.job_id=j.id)`, pq.Array(jobIDs))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func deleteOrphanChatRecordsTx(ctx context.Context, tx *sql.Tx, limit int) (int64, error) {
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	result, err := tx.ExecContext(ctx, `
		WITH orphaned AS (
			SELECT c.id FROM prompt_audit_chat_records c
			WHERE NOT EXISTS (SELECT 1 FROM prompt_audit_events e WHERE e.chat_record_id=c.id)
			ORDER BY c.id LIMIT $1 FOR UPDATE SKIP LOCKED
		)
		DELETE FROM prompt_audit_chat_records c USING orphaned o WHERE c.id=o.id`, limit)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
