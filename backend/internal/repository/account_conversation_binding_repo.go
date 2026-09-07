package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/TokenFlux/TokenRouter/internal/service"
)

var _ service.OpenAIConversationBindingRepository = (*accountRepository)(nil)

func (r *accountRepository) GetOpenAIConversationBinding(ctx context.Context, userID, scopeGroupID int64, kind, key string) (*service.OpenAIConversationBinding, error) {
	rows, err := r.sql.QueryContext(ctx, `
		SELECT b.user_id, b.scope_group_id, b.binding_type, b.binding_key,
		       b.account_id, b.credential_owner_account_id, b.api_key_id,
		       b.oauth_account_id, b.oauth_user_id, b.revision, b.confirmed,
		       (a.deleted_at IS NULL AND owner.deleted_at IS NULL AND u.deleted_at IS NULL
		        AND a.platform = 'openai' AND a.type = 'oauth'
		        AND owner.platform = 'openai' AND owner.type = 'oauth'
		        AND COALESCE(a.parent_account_id, a.id) = b.credential_owner_account_id
		        AND COALESCE(owner.credentials->>'chatgpt_account_id', '') = b.oauth_account_id
		        AND COALESCE(owner.credentials->>'chatgpt_user_id', '') = b.oauth_user_id)
		FROM openai_conversation_bindings b
		JOIN accounts a ON a.id = b.account_id
		JOIN accounts owner ON owner.id = b.credential_owner_account_id
		JOIN users u ON u.id = b.user_id
		WHERE b.user_id = $1 AND b.scope_group_id = $2 AND b.binding_type = $3 AND b.binding_key = $4
	`, userID, scopeGroupID, kind, key)
	if err != nil {
		return nil, fmt.Errorf("lookup OpenAI conversation binding: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return nil, rows.Err()
	}
	var binding service.OpenAIConversationBinding
	if err := rows.Scan(&binding.UserID, &binding.ScopeGroupID, &binding.Type, &binding.Key,
		&binding.AccountID, &binding.CredentialOwnerAccountID, &binding.APIKeyID,
		&binding.OAuthAccountID, &binding.OAuthUserID, &binding.Revision, &binding.Confirmed, &binding.Valid); err != nil {
		return nil, err
	}
	return &binding, rows.Err()
}

// 在同条SQL中复核当前凭据身份并执行CAS，拒绝过期身份或并发抢占。
// @project-doc docs/domains/openai_history_admission.md#durable_ownership
func (r *accountRepository) SaveOpenAIConversationBinding(ctx context.Context, binding *service.OpenAIConversationBinding, expectedRevision int64) (*service.OpenAIConversationBinding, error) {
	if binding == nil || binding.UserID <= 0 || binding.APIKeyID <= 0 || binding.AccountID <= 0 ||
		binding.CredentialOwnerAccountID <= 0 || len(binding.Key) != 64 ||
		(binding.Type != "session" && binding.Type != "response") {
		return nil, errors.New("invalid OpenAI conversation binding")
	}
	rows, err := r.sql.QueryContext(ctx, `
		INSERT INTO openai_conversation_bindings AS existing
		    (user_id, scope_group_id, binding_type, binding_key, account_id,
		     credential_owner_account_id, api_key_id, oauth_account_id, oauth_user_id, confirmed)
		SELECT $1, $2, $3, $4, a.id, owner.id, $7, $8, $9, $11
		FROM accounts a
		JOIN accounts owner ON owner.id = COALESCE(a.parent_account_id, a.id)
		JOIN users u ON u.id = $1 AND u.deleted_at IS NULL
		WHERE a.id = $5 AND owner.id = $6 AND a.deleted_at IS NULL AND owner.deleted_at IS NULL
		  AND a.platform = 'openai' AND a.type = 'oauth' AND owner.platform = 'openai' AND owner.type = 'oauth'
		  AND COALESCE(owner.credentials->>'chatgpt_account_id', '') = $8
		  AND COALESCE(owner.credentials->>'chatgpt_user_id', '') = $9
		  AND (NOT $11 OR $3 = 'response' OR EXISTS (
		      SELECT 1 FROM openai_conversation_bindings reserved
		      WHERE reserved.user_id = $1 AND reserved.scope_group_id = $2
		        AND reserved.binding_type = 'session' AND reserved.binding_key = $4
		        AND reserved.revision = $10 AND reserved.account_id = $5
		        AND reserved.credential_owner_account_id = $6
		        AND reserved.oauth_account_id = $8 AND reserved.oauth_user_id = $9))
		ON CONFLICT (user_id, scope_group_id, binding_type, binding_key) DO UPDATE SET
		    account_id = EXCLUDED.account_id,
		    credential_owner_account_id = EXCLUDED.credential_owner_account_id,
		    api_key_id = EXCLUDED.api_key_id,
		    oauth_account_id = EXCLUDED.oauth_account_id,
		    oauth_user_id = EXCLUDED.oauth_user_id,
		    revision = CASE WHEN existing.account_id = EXCLUDED.account_id
		        AND existing.credential_owner_account_id = EXCLUDED.credential_owner_account_id
		        AND existing.oauth_account_id = EXCLUDED.oauth_account_id AND existing.oauth_user_id = EXCLUDED.oauth_user_id
		        THEN existing.revision ELSE existing.revision + 1 END,
		    confirmed = EXCLUDED.confirmed OR (existing.confirmed
		        AND existing.account_id = EXCLUDED.account_id
		        AND existing.credential_owner_account_id = EXCLUDED.credential_owner_account_id
		        AND existing.oauth_account_id = EXCLUDED.oauth_account_id AND existing.oauth_user_id = EXCLUDED.oauth_user_id),
		    updated_at = NOW()
		WHERE (existing.binding_type = 'session' AND existing.revision = $10)
		   OR (existing.account_id = EXCLUDED.account_id
		       AND existing.credential_owner_account_id = EXCLUDED.credential_owner_account_id
		       AND existing.oauth_account_id = EXCLUDED.oauth_account_id
		       AND existing.oauth_user_id = EXCLUDED.oauth_user_id
		       AND (NOT $11 OR existing.binding_type = 'response' OR existing.revision = $10))
		RETURNING revision, confirmed
	`, binding.UserID, binding.ScopeGroupID, binding.Type, binding.Key, binding.AccountID,
		binding.CredentialOwnerAccountID, binding.APIKeyID, binding.OAuthAccountID,
		binding.OAuthUserID, expectedRevision, binding.Confirmed)
	if err != nil {
		return nil, fmt.Errorf("save OpenAI conversation binding: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, service.ErrOpenAIHistoryConflict
	}
	result := *binding
	if err := rows.Scan(&result.Revision, &result.Confirmed); err != nil {
		return nil, err
	}
	result.Valid = true
	return &result, rows.Err()
}
