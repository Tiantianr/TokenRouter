CREATE TABLE IF NOT EXISTS openai_conversation_bindings (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope_group_id BIGINT NOT NULL,
    binding_type TEXT NOT NULL CHECK (binding_type IN ('session', 'response')),
    binding_key TEXT NOT NULL CHECK (length(binding_key) = 64),
    account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    credential_owner_account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    api_key_id BIGINT NOT NULL,
    oauth_account_id TEXT NOT NULL DEFAULT '',
    oauth_user_id TEXT NOT NULL DEFAULT '',
    revision BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, scope_group_id, binding_type, binding_key)
);

CREATE INDEX IF NOT EXISTS idx_openai_conversation_bindings_account
    ON openai_conversation_bindings(account_id);
CREATE INDEX IF NOT EXISTS idx_openai_conversation_bindings_credential_owner
    ON openai_conversation_bindings(credential_owner_account_id);

-- 软删除与物理删除均清理归属；普通健康、配额及 token 刷新不清理。
CREATE OR REPLACE FUNCTION cleanup_openai_conversation_bindings_on_delete()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL THEN
        IF TG_TABLE_NAME = 'users' THEN
            DELETE FROM openai_conversation_bindings WHERE user_id = NEW.id;
        ELSE
            DELETE FROM openai_conversation_bindings
            WHERE account_id = NEW.id OR credential_owner_account_id = NEW.id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_openai_conversation_user_delete ON users;
CREATE TRIGGER trg_openai_conversation_user_delete
    AFTER UPDATE OF deleted_at ON users FOR EACH ROW
    EXECUTE FUNCTION cleanup_openai_conversation_bindings_on_delete();

DROP TRIGGER IF EXISTS trg_openai_conversation_account_delete ON accounts;
CREATE TRIGGER trg_openai_conversation_account_delete
    AFTER UPDATE OF deleted_at ON accounts FOR EACH ROW
    EXECUTE FUNCTION cleanup_openai_conversation_bindings_on_delete();
