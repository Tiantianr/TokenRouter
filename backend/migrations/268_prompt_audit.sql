-- 提示词审计初始结构：按旧工程已验证的依赖顺序建立最终表结构。
-- 当前工程迁移从 268 起递增，不复用旧工程迁移编号。


-- Independent OpenAI-compatible prompt input audit.
-- Raw prompts and Guard credentials are intentionally absent from PostgreSQL.

CREATE TABLE IF NOT EXISTS prompt_audit_jobs (
    id                    BIGSERIAL PRIMARY KEY,
    request_id            VARCHAR(128) NOT NULL DEFAULT '',
    user_id               BIGINT REFERENCES users(id) ON DELETE SET NULL,
    username_snapshot     VARCHAR(255) NOT NULL DEFAULT '',
    user_email_snapshot   VARCHAR(320) NOT NULL DEFAULT '',
    api_key_id            BIGINT REFERENCES api_keys(id) ON DELETE SET NULL,
    api_key_name_snapshot VARCHAR(255) NOT NULL DEFAULT '',
    group_id              BIGINT REFERENCES groups(id) ON DELETE SET NULL,
    group_name            VARCHAR(255) NOT NULL DEFAULT '',
    provider              VARCHAR(64) NOT NULL DEFAULT '',
    endpoint              VARCHAR(128) NOT NULL DEFAULT '',
    protocol              VARCHAR(64) NOT NULL DEFAULT '',
    model                 VARCHAR(255) NOT NULL DEFAULT '',
    prompt_hash           VARCHAR(64) NOT NULL DEFAULT '',
    redacted_preview      TEXT NOT NULL DEFAULT '',
    prompt_length         INT NOT NULL DEFAULT 0,
    message_count         INT NOT NULL DEFAULT 0,
    stage                 VARCHAR(32) NOT NULL DEFAULT 'http',
    execution_mode        VARCHAR(32) NOT NULL DEFAULT 'async_audit',
    config_version        BIGINT NOT NULL DEFAULT 1,
    status                VARCHAR(32) NOT NULL DEFAULT 'staging',
    attempts              INT NOT NULL DEFAULT 0,
    max_attempts          INT NOT NULL DEFAULT 3,
    claim_version         BIGINT NOT NULL DEFAULT 0,
    next_attempt_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processing_started_at TIMESTAMPTZ,
    processed_at          TIMESTAMPTZ,
    last_error_code       VARCHAR(64) NOT NULL DEFAULT '',
    last_error_message    VARCHAR(512) NOT NULL DEFAULT '',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_prompt_audit_jobs_status
        CHECK (status IN ('staging', 'queued', 'processing', 'retry', 'done', 'failed')),
    CONSTRAINT chk_prompt_audit_jobs_execution_mode
        CHECK (execution_mode IN ('async_audit', 'blocking')),
    CONSTRAINT chk_prompt_audit_jobs_nonnegative
        CHECK (
            attempts >= 0 AND max_attempts >= 0 AND claim_version >= 0 AND
            prompt_length >= 0 AND message_count >= 0 AND config_version >= 1
        )
);

CREATE TABLE IF NOT EXISTS prompt_audit_events (
    id                       BIGSERIAL PRIMARY KEY,
    job_id                   BIGINT NOT NULL REFERENCES prompt_audit_jobs(id) ON DELETE CASCADE,
    request_id               VARCHAR(128) NOT NULL DEFAULT '',
    user_id                  BIGINT REFERENCES users(id) ON DELETE SET NULL,
    username_snapshot        VARCHAR(255) NOT NULL DEFAULT '',
    user_email_snapshot      VARCHAR(320) NOT NULL DEFAULT '',
    api_key_id               BIGINT REFERENCES api_keys(id) ON DELETE SET NULL,
    api_key_name_snapshot    VARCHAR(255) NOT NULL DEFAULT '',
    group_id                 BIGINT REFERENCES groups(id) ON DELETE SET NULL,
    group_name               VARCHAR(255) NOT NULL DEFAULT '',
    provider                 VARCHAR(64) NOT NULL DEFAULT '',
    endpoint                 VARCHAR(128) NOT NULL DEFAULT '',
    protocol                 VARCHAR(64) NOT NULL DEFAULT '',
    model                    VARCHAR(255) NOT NULL DEFAULT '',
    prompt_hash              VARCHAR(64) NOT NULL DEFAULT '',
    redacted_preview         TEXT NOT NULL DEFAULT '',
    stage                    VARCHAR(32) NOT NULL DEFAULT 'http',
    decision                 VARCHAR(32) NOT NULL DEFAULT 'pass',
    risk_level               VARCHAR(32) NOT NULL DEFAULT 'low',
    action                   VARCHAR(32) NOT NULL DEFAULT 'Allow',
    categories               JSONB NOT NULL DEFAULT '[]'::jsonb,
    matched_scanners         JSONB NOT NULL DEFAULT '[]'::jsonb,
    scanner_scores           JSONB NOT NULL DEFAULT '{}'::jsonb,
    scanner_evidence         JSONB NOT NULL DEFAULT '{}'::jsonb,
    scanner_backend          VARCHAR(64) NOT NULL DEFAULT 'qwen3guard-openai',
    scanner_version          VARCHAR(128) NOT NULL DEFAULT '',
    guard_endpoint_id        VARCHAR(128) NOT NULL DEFAULT '',
    policy_id                VARCHAR(128) NOT NULL DEFAULT '',
    policy_version           INT NOT NULL DEFAULT 0,
    config_version           BIGINT NOT NULL DEFAULT 1,
    chunk_total              INT NOT NULL DEFAULT 0,
    latency_ms               INT NOT NULL DEFAULT 0,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_prompt_audit_events_decision
        CHECK (decision IN ('pass', 'flag', 'critical')),
    CONSTRAINT chk_prompt_audit_events_risk_level
        CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT chk_prompt_audit_events_action
        CHECK (action IN ('Allow', 'Warn', 'Block')),
    CONSTRAINT chk_prompt_audit_events_nonnegative
        CHECK (policy_version >= 0 AND config_version >= 1 AND chunk_total >= 0 AND latency_ms >= 0),
    CONSTRAINT chk_prompt_audit_events_categories_json
        CHECK (jsonb_typeof(categories) = 'array'),
    CONSTRAINT chk_prompt_audit_events_scanners_json
        CHECK (jsonb_typeof(matched_scanners) = 'array'),
    CONSTRAINT chk_prompt_audit_events_scores_json
        CHECK (jsonb_typeof(scanner_scores) = 'object'),
    CONSTRAINT chk_prompt_audit_events_evidence_json
        CHECK (jsonb_typeof(scanner_evidence) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_prompt_audit_jobs_schedule
    ON prompt_audit_jobs(status, next_attempt_at, id);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_jobs_request
    ON prompt_audit_jobs(request_id);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_jobs_user_created
    ON prompt_audit_jobs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_jobs_api_key_created
    ON prompt_audit_jobs(api_key_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_jobs_group_created
    ON prompt_audit_jobs(group_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_jobs_prompt_hash
    ON prompt_audit_jobs(prompt_hash);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_jobs_created
    ON prompt_audit_jobs(created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_prompt_audit_events_job
    ON prompt_audit_events(job_id);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_events_request
    ON prompt_audit_events(request_id);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_events_decision_created
    ON prompt_audit_events(decision, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_events_risk_created
    ON prompt_audit_events(risk_level, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_events_user_created
    ON prompt_audit_events(user_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_events_api_key_created
    ON prompt_audit_events(api_key_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_events_group_created
    ON prompt_audit_events(group_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_events_prompt_hash
    ON prompt_audit_events(prompt_hash);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_events_created
    ON prompt_audit_events(created_at DESC, id DESC);


-- Retain the full (unredacted) prompt text on audit events so admins can
-- review the exact content that triggered a finding. Scoped to events only:
-- transient processing jobs keep storing redacted metadata.
ALTER TABLE prompt_audit_events
    ADD COLUMN IF NOT EXISTS full_prompt TEXT NOT NULL DEFAULT '';


ALTER TABLE prompt_audit_jobs
    ADD COLUMN IF NOT EXISTS client_ip VARCHAR(64) NOT NULL DEFAULT '';

ALTER TABLE prompt_audit_events
    ADD COLUMN IF NOT EXISTS client_ip VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS prompt_length INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS message_count INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS execution_mode VARCHAR(32) NOT NULL DEFAULT 'async_audit',
    ADD COLUMN IF NOT EXISTS queue_delay_ms INT,
    ADD COLUMN IF NOT EXISTS input_limit INT,
    ADD COLUMN IF NOT EXISTS matched_chunk_index INT,
    ADD COLUMN IF NOT EXISTS full_prompt_truncated BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE prompt_audit_events AS event
SET prompt_length = job.prompt_length,
    message_count = job.message_count,
    execution_mode = job.execution_mode,
    client_ip = job.client_ip
FROM prompt_audit_jobs AS job
WHERE job.id = event.job_id;

UPDATE prompt_audit_events
SET full_prompt_truncated = TRUE
WHERE input_limit IS NULL
  AND (
      prompt_length > CHAR_LENGTH(full_prompt) OR
      (
          prompt_length >= 65537 AND CHAR_LENGTH(full_prompt) = 65537 AND
          RIGHT(full_prompt, 1) = '…'
      )
  );

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_prompt_audit_events_observability'
          AND conrelid = 'prompt_audit_events'::regclass
    ) THEN
        ALTER TABLE prompt_audit_events
            ADD CONSTRAINT chk_prompt_audit_events_observability
            CHECK (
                prompt_length >= 0 AND message_count >= 0 AND
                execution_mode IN ('async_audit', 'blocking') AND
                (queue_delay_ms IS NULL OR queue_delay_ms >= 0) AND
                (input_limit IS NULL OR input_limit >= 128) AND
                (matched_chunk_index IS NULL OR (
                    matched_chunk_index >= 1 AND matched_chunk_index <= chunk_total
                ))
            );
    END IF;
END $$;


CREATE INDEX IF NOT EXISTS idx_prompt_audit_events_client_ip_created
    ON prompt_audit_events(client_ip, created_at DESC, id DESC);


CREATE TABLE IF NOT EXISTS prompt_audit_event_contexts (
    event_id BIGINT PRIMARY KEY REFERENCES prompt_audit_events(id) ON DELETE CASCADE,
    context_ciphertext TEXT NOT NULL,
    context_sha256 VARCHAR(64) NOT NULL,
    context_bytes BIGINT NOT NULL CHECK (context_bytes >= 0),
    segment_count INTEGER NOT NULL CHECK (segment_count >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE prompt_audit_event_contexts IS 'Application-encrypted complete canonical context for authorized Prompt Audit event download';


ALTER TABLE prompt_audit_jobs
    DROP CONSTRAINT IF EXISTS chk_prompt_audit_jobs_execution_mode;

ALTER TABLE prompt_audit_jobs
    ADD CONSTRAINT chk_prompt_audit_jobs_execution_mode
        CHECK (execution_mode IN ('async_audit', 'async_deep', 'blocking'))
        NOT VALID;

ALTER TABLE prompt_audit_jobs
    VALIDATE CONSTRAINT chk_prompt_audit_jobs_execution_mode;

ALTER TABLE prompt_audit_events
    DROP CONSTRAINT IF EXISTS chk_prompt_audit_events_observability;

ALTER TABLE prompt_audit_events
    ADD CONSTRAINT chk_prompt_audit_events_observability
        CHECK (
            prompt_length >= 0 AND message_count >= 0 AND
            execution_mode IN ('async_audit', 'async_deep', 'blocking') AND
            (queue_delay_ms IS NULL OR queue_delay_ms >= 0) AND
            (input_limit IS NULL OR input_limit >= 128) AND
            (matched_chunk_index IS NULL OR (
                matched_chunk_index >= 1 AND matched_chunk_index <= chunk_total
            ))
        ) NOT VALID;

ALTER TABLE prompt_audit_events
    VALIDATE CONSTRAINT chk_prompt_audit_events_observability;


CREATE INDEX IF NOT EXISTS idx_prompt_audit_events_mode_created
    ON prompt_audit_events(execution_mode, created_at DESC, id DESC);


-- Pass evidence retention is now selected by user in an independently
-- versioned setting. Removing the legacy field makes older binaries default to
-- false after reload or rollback instead of resuming global Pass persistence.
UPDATE settings
SET value = (value::jsonb - 'store_pass_events')::text,
    updated_at = NOW()
WHERE key = 'prompt_audit_config'
  AND value::jsonb ? 'store_pass_events';


ALTER TABLE prompt_audit_events
    ADD COLUMN IF NOT EXISTS guard_endpoint_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS guard_model TEXT NOT NULL DEFAULT '';


ALTER TABLE prompt_audit_events
    ADD COLUMN IF NOT EXISTS error_code VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS error_message VARCHAR(160) NOT NULL DEFAULT '';

ALTER TABLE prompt_audit_events
    DROP CONSTRAINT IF EXISTS chk_prompt_audit_events_decision;
ALTER TABLE prompt_audit_events
    ADD CONSTRAINT chk_prompt_audit_events_decision
        CHECK (decision IN ('pass', 'flag', 'critical', 'failed')) NOT VALID;
ALTER TABLE prompt_audit_events
    VALIDATE CONSTRAINT chk_prompt_audit_events_decision;

ALTER TABLE prompt_audit_events
    DROP CONSTRAINT IF EXISTS chk_prompt_audit_events_risk_level;
ALTER TABLE prompt_audit_events
    ADD CONSTRAINT chk_prompt_audit_events_risk_level
        CHECK (risk_level IN ('low', 'medium', 'high', 'critical', 'unknown')) NOT VALID;
ALTER TABLE prompt_audit_events
    VALIDATE CONSTRAINT chk_prompt_audit_events_risk_level;

ALTER TABLE prompt_audit_events
    DROP CONSTRAINT IF EXISTS chk_prompt_audit_events_action;
ALTER TABLE prompt_audit_events
    ADD CONSTRAINT chk_prompt_audit_events_action
        CHECK (action IN ('Allow', 'Warn', 'Block', 'Error')) NOT VALID;
ALTER TABLE prompt_audit_events
    VALIDATE CONSTRAINT chk_prompt_audit_events_action;

ALTER TABLE prompt_audit_events
    DROP CONSTRAINT IF EXISTS chk_prompt_audit_events_failure_reason;
ALTER TABLE prompt_audit_events
    ADD CONSTRAINT chk_prompt_audit_events_failure_reason
        CHECK (
            (decision = 'failed' AND error_code <> '' AND error_message <> '') OR
            (decision <> 'failed' AND error_code = '' AND error_message = '')
        ) NOT VALID;
ALTER TABLE prompt_audit_events
    VALIDATE CONSTRAINT chk_prompt_audit_events_failure_reason;

INSERT INTO prompt_audit_events (
    job_id, request_id, user_id, username_snapshot, user_email_snapshot, api_key_id,
    api_key_name_snapshot, group_id, group_name, provider, endpoint, protocol, model,
    prompt_hash, redacted_preview, stage, decision, risk_level, action, categories,
    matched_scanners, scanner_scores, scanner_evidence, scanner_backend, scanner_version,
    guard_endpoint_id, guard_endpoint_name, guard_model, policy_id, policy_version,
    config_version, chunk_total, latency_ms, full_prompt, client_ip, prompt_length,
    message_count, execution_mode, queue_delay_ms, input_limit, matched_chunk_index,
    full_prompt_truncated, error_code, error_message, created_at
)
SELECT
    j.id, j.request_id, j.user_id, j.username_snapshot, j.user_email_snapshot, j.api_key_id,
    j.api_key_name_snapshot, j.group_id, j.group_name, j.provider, j.endpoint, j.protocol, j.model,
    j.prompt_hash, j.redacted_preview, j.stage, 'failed', 'unknown', 'Error', '[]'::jsonb,
    '[]'::jsonb, '{}'::jsonb, '{}'::jsonb, 'qwen3guard-openai', '',
    '', '', '', 'priority', 0,
    j.config_version, 0, 0, '', j.client_ip, j.prompt_length,
    j.message_count, j.execution_mode, NULL, NULL, NULL,
    TRUE,
    CASE
        WHEN LOWER(j.last_error_code) ~ '^[a-z0-9_.-]{1,64}$' THEN LOWER(j.last_error_code)
        ELSE 'prompt_guard_unavailable'
    END,
    CASE j.last_error_code
        WHEN 'prompt_guard_blocked' THEN 'Prompt Guard blocked the request'
        WHEN 'prompt_guard_unavailable' THEN 'Prompt Audit dependency is unavailable'
        WHEN 'payload_store_unavailable' THEN 'Prompt Audit dependency is unavailable'
        WHEN 'payload_missing' THEN 'Prompt Audit dependency is unavailable'
        WHEN 'prompt_guard_invalid_response' THEN 'Prompt Guard returned an invalid response'
        WHEN 'queue_full' THEN 'Prompt Audit queue is unavailable'
        WHEN 'queue_admission_busy' THEN 'Prompt Audit queue is unavailable'
        WHEN 'worker_panic' THEN 'Prompt Audit worker failed'
        WHEN 'config_load_failed' THEN 'Prompt Audit configuration could not be loaded'
        WHEN 'config_ttl_reload_failed' THEN 'Prompt Audit configuration could not be loaded'
        WHEN 'config_invalidation_reload_failed' THEN 'Prompt Audit configuration could not be loaded'
        ELSE 'Prompt Audit operation failed'
    END,
    COALESCE(j.processed_at, j.updated_at, j.created_at)
FROM prompt_audit_jobs AS j
WHERE j.status = 'failed'
  AND NOT EXISTS (SELECT 1 FROM prompt_audit_events AS e WHERE e.job_id = j.id);


ALTER TABLE prompt_audit_jobs
    ADD COLUMN IF NOT EXISTS blocking_exempt_at_request BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE prompt_audit_events
    ADD COLUMN IF NOT EXISTS blocking_exempt_at_request BOOLEAN NOT NULL DEFAULT FALSE;


-- Store Prompt Audit chat evidence below the user/session hierarchy. Event rows
-- keep only detection metadata and references so repeated content can be shared
-- and chat data can be omitted from logical database backups.

ALTER TABLE prompt_audit_jobs
    ADD COLUMN IF NOT EXISTS session_key VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS session_source VARCHAR(32) NOT NULL DEFAULT '';

ALTER TABLE prompt_audit_events
    ADD COLUMN IF NOT EXISTS session_key VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS session_source VARCHAR(32) NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS prompt_audit_sessions (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_key     VARCHAR(64) NOT NULL,
    session_source  VARCHAR(32) NOT NULL DEFAULT '',
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_prompt_audit_sessions_user_key UNIQUE (user_id, session_key)
);

CREATE TABLE IF NOT EXISTS prompt_audit_chat_records (
    id                    BIGSERIAL PRIMARY KEY,
    session_id            BIGINT NOT NULL REFERENCES prompt_audit_sessions(id) ON DELETE CASCADE,
    content_hash          VARCHAR(64) NOT NULL,
    full_prompt           TEXT NOT NULL DEFAULT '',
    full_prompt_truncated BOOLEAN NOT NULL DEFAULT FALSE,
    context_ciphertext    TEXT,
    context_sha256        VARCHAR(64),
    context_bytes         BIGINT NOT NULL DEFAULT 0,
    segment_count         INTEGER NOT NULL DEFAULT 0,
    retention_until       TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_prompt_audit_chat_records_session_content UNIQUE (session_id, content_hash),
    CONSTRAINT chk_prompt_audit_chat_records_context_bytes CHECK (context_bytes >= 0),
    CONSTRAINT chk_prompt_audit_chat_records_segment_count CHECK (segment_count >= 0)
);

ALTER TABLE prompt_audit_events
    -- This is an application-managed reference. The chat table is omitted from
    -- backups, so a database restore must allow metadata events to retain a
    -- dangling content reference after the payload is intentionally absent.
    ADD COLUMN IF NOT EXISTS chat_record_id BIGINT;

CREATE INDEX IF NOT EXISTS idx_prompt_audit_sessions_user_last_seen
    ON prompt_audit_sessions(user_id, last_seen_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_chat_records_session_created
    ON prompt_audit_chat_records(session_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_chat_records_retention
    ON prompt_audit_chat_records(retention_until, id);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_events_chat_record
    ON prompt_audit_events(chat_record_id);

-- Historical rows had no session identity. Keep their evidence accessible by
-- assigning one opaque request-scoped session per event before clearing the old
-- in-row/context-table copies. md5 is sufficient for this migration-only key;
-- new rows use the SHA-256 key generated by the application.
UPDATE prompt_audit_events
SET session_key = md5('sub2api:legacy-prompt-audit-session:' || COALESCE(user_id::TEXT, '0') || ':' || id::TEXT)
WHERE session_key = '';

UPDATE prompt_audit_jobs j
SET session_key = e.session_key,
    session_source = 'legacy_event'
FROM prompt_audit_events e
WHERE e.job_id = j.id AND j.session_key = '';

INSERT INTO prompt_audit_sessions (user_id, session_key, session_source, first_seen_at, last_seen_at)
SELECT e.user_id, e.session_key, 'legacy_event', MIN(e.created_at), MAX(e.created_at)
FROM prompt_audit_events e
WHERE e.user_id IS NOT NULL AND e.session_key <> ''
GROUP BY e.user_id, e.session_key
ON CONFLICT (user_id, session_key) DO UPDATE SET
    first_seen_at = LEAST(prompt_audit_sessions.first_seen_at, EXCLUDED.first_seen_at),
    last_seen_at = GREATEST(prompt_audit_sessions.last_seen_at, EXCLUDED.last_seen_at);

INSERT INTO prompt_audit_chat_records (
    session_id, content_hash, full_prompt, full_prompt_truncated,
    context_ciphertext, context_sha256, context_bytes, segment_count, retention_until, created_at
)
SELECT s.id,
       md5('sub2api:legacy-prompt-audit-record:v1:' || e.id::TEXT),
       e.full_prompt,
       e.full_prompt_truncated,
       c.context_ciphertext,
       c.context_sha256,
       COALESCE(c.context_bytes, 0),
       COALESCE(c.segment_count, 0),
       NULL,
       e.created_at
FROM prompt_audit_events e
JOIN prompt_audit_sessions s ON s.user_id = e.user_id AND s.session_key = e.session_key
LEFT JOIN prompt_audit_event_contexts c ON c.event_id = e.id
WHERE e.full_prompt <> '' OR c.event_id IS NOT NULL
ON CONFLICT (session_id, content_hash) DO NOTHING;

UPDATE prompt_audit_events e
SET chat_record_id = r.id
FROM prompt_audit_sessions s, prompt_audit_chat_records r
WHERE s.user_id = e.user_id
  AND s.session_key = e.session_key
  AND r.session_id = s.id
  AND r.content_hash = md5('sub2api:legacy-prompt-audit-record:v1:' || e.id::TEXT);

-- The new chat table is the sole owner of historical complete content. Keep
-- the legacy table as an empty compatibility shell for rolling migrations.
UPDATE prompt_audit_events SET full_prompt = '';
DELETE FROM prompt_audit_event_contexts;

COMMENT ON TABLE prompt_audit_sessions IS 'User-scoped opaque Prompt Audit sessions';
COMMENT ON TABLE prompt_audit_chat_records IS 'Prompt Audit chat evidence; excluded from logical backups and retained by policy';

-- 支持会话浏览和关联事件分页，避免每个会话重复扫描用户全部事件。
CREATE INDEX IF NOT EXISTS idx_prompt_audit_events_session_created
    ON prompt_audit_events(user_id, session_key, created_at DESC, id DESC);
