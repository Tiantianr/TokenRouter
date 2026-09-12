package repository

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/TokenFlux/TokenRouter/internal/service"
)

// CompareAndSwapCodexSession 的单条 SQL 同时写入状态和 outbox，跨实例也只允许一个版本获胜。
func (r *accountRepository) CompareAndSwapCodexSession(ctx context.Context, expected *service.Account, updates map[string]any) (bool, error) {
	payload, err := json.Marshal(updates)
	if err != nil {
		return false, err
	}
	extra, err := json.Marshal(normalizeJSONMap(expected.Extra))
	if err != nil {
		return false, err
	}
	credentials, err := json.Marshal(normalizeJSONMap(expected.Credentials))
	if err != nil {
		return false, err
	}
	var checks []string
	for _, key := range []string{"codex_account_turn", "codex_fingerprint_seed", "codex_fingerprint_mode", "codex_session_override_enabled", "codex_session_override_id", "openai_device_id"} {
		checks = append(checks, "extra -> '"+key+"' IS NOT DISTINCT FROM $3::jsonb -> '"+key+"'")
	}
	result, err := clientFromContext(ctx, r.client).ExecContext(ctx, `
		WITH updated AS (
			UPDATE accounts SET extra = COALESCE(extra, '{}'::jsonb) || $1::jsonb, updated_at = NOW()
			WHERE id = $2 AND deleted_at IS NULL AND platform = 'openai' AND type = $5
			AND credentials IS NOT DISTINCT FROM $4::jsonb AND `+strings.Join(checks, " AND ")+`
			RETURNING id
		)
		INSERT INTO scheduler_outbox (event_type, account_id, payload)
		SELECT $6, id, '{}'::jsonb FROM updated`, string(payload), expected.ID, string(extra), string(credentials), expected.Type, service.SchedulerOutboxEventAccountChanged)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	if err != nil || count == 0 {
		return false, err
	}
	r.syncSchedulerAccountSnapshot(ctx, expected.ID)
	return true, nil
}

// 增量/批量编辑身份或显式替换 OAuth token 时，在同一 SQL 中废弃原状态。
// 后台正常 token 刷新走 UpdateCredentials，不调用本方法。
func invalidateCodexTurnPatchSQL(expression, credentialPlaceholder string, credentials, extra map[string]any) string {
	var changed []string
	for _, key := range []string{"access_token", "refresh_token", "chatgpt_account_id", "chatgpt_user_id", "email"} {
		if _, ok := credentials[key]; ok && credentialPlaceholder != "" {
			changed = append(changed, "credentials -> '"+key+"' IS DISTINCT FROM "+credentialPlaceholder+"::jsonb -> '"+key+"'")
		}
	}
	for _, key := range []string{"codex_fingerprint_mode", "openai_device_id", "codex_session_override_enabled", "codex_session_override_id"} {
		if _, ok := extra[key]; ok {
			changed = append(changed, "extra -> '"+key+"' IS DISTINCT FROM ("+expression+") -> '"+key+"'")
		}
	}
	if len(changed) == 0 {
		return expression
	}
	return "CASE WHEN platform = 'openai' AND type IN ('oauth', 'setup_token') AND (" + strings.Join(changed, " OR ") + ") THEN (" + expression + ") - '" + service.CodexAccountTurnExtraKey + "' ELSE (" + expression + ") END"
}
