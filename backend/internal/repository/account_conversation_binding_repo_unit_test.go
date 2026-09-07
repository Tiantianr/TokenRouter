//go:build unit

package repository

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TokenFlux/TokenRouter/internal/service"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

// 使用独立schema执行真实迁移及仓储SQL，不连接默认开发/生产数据库。
func TestOpenAIHistoryPostgresRepository(t *testing.T) {
	dsn := os.Getenv("TOKENROUTER_HISTORY_TEST_DSN")
	if dsn == "" {
		t.Skip("requires an isolated PostgreSQL test DSN")
	}
	admin, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, admin.Close()) })
	schema := fmt.Sprintf("history_%d", time.Now().UnixNano())
	_, err = admin.Exec("CREATE SCHEMA " + pq.QuoteIdentifier(schema))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := admin.Exec("DROP SCHEMA " + pq.QuoteIdentifier(schema) + " CASCADE")
		require.NoError(t, err)
	})
	db, err := sql.Open("postgres", dsn+" search_path="+schema)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	ctx := context.Background()
	_, err = db.Exec(`CREATE TABLE users (id BIGINT PRIMARY KEY, deleted_at TIMESTAMPTZ);
CREATE TABLE accounts (id BIGINT PRIMARY KEY, platform TEXT, type TEXT, parent_account_id BIGINT, credentials JSONB, deleted_at TIMESTAMPTZ);
INSERT INTO users(id) VALUES(1),(2);
INSERT INTO accounts VALUES (1,'openai','oauth',NULL,'{"chatgpt_account_id":"owner-a"}',NULL),(2,'openai','oauth',NULL,'{"chatgpt_account_id":"owner-b"}',NULL),(3,'openai','oauth',1,'{}',NULL);`)
	require.NoError(t, err)
	migration, err := os.ReadFile("../../migrations/266_openai_conversation_bindings.sql")
	require.NoError(t, err)
	_, err = db.Exec(string(migration))
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO openai_conversation_bindings(user_id,scope_group_id,binding_type,binding_key,account_id,credential_owner_account_id,api_key_id) VALUES(2,7,'session',repeat('c',64),1,1,20)`)
	require.NoError(t, err)
	migration, err = os.ReadFile("../../migrations/267_openai_conversation_confirmation.sql")
	require.NoError(t, err)
	_, err = db.Exec(string(migration))
	require.NoError(t, err)
	var legacyConfirmed bool
	require.NoError(t, db.QueryRow(`SELECT confirmed FROM openai_conversation_bindings WHERE user_id=2`).Scan(&legacyConfirmed))
	require.False(t, legacyConfirmed)
	_, err = db.Exec(`DELETE FROM openai_conversation_bindings WHERE user_id=2`)
	require.NoError(t, err)
	r := &accountRepository{sql: db}
	b := &service.OpenAIConversationBinding{UserID: 1, ScopeGroupID: 7, Type: "session", Key: strings.Repeat("a", 64), AccountID: 1, CredentialOwnerAccountID: 1, APIKeyID: 10, OAuthAccountID: "owner-a"}
	saved, err := r.SaveOpenAIConversationBinding(ctx, b, 0)
	require.NoError(t, err)
	require.Equal(t, int64(1), saved.Revision)
	got, err := r.GetOpenAIConversationBinding(ctx, 1, 7, "session", b.Key)
	require.NoError(t, err)
	require.True(t, got.Valid)
	require.False(t, got.Confirmed)
	confirmed := *saved
	confirmed.Confirmed = true
	confirmedRow, err := r.SaveOpenAIConversationBinding(ctx, &confirmed, saved.Revision)
	require.NoError(t, err)
	require.True(t, confirmedRow.Confirmed)
	repeated, err := r.SaveOpenAIConversationBinding(ctx, b, 0)
	require.NoError(t, err)
	require.True(t, repeated.Confirmed)
	require.Equal(t, saved.Revision, repeated.Revision)
	for _, scope := range [][2]int64{{2, 7}, {1, 8}} {
		got, err = r.GetOpenAIConversationBinding(ctx, scope[0], scope[1], "session", b.Key)
		require.NoError(t, err)
		require.Nil(t, got)
	}
	other := *b
	other.AccountID = 2
	other.CredentialOwnerAccountID = 2
	other.OAuthAccountID = "owner-b"
	_, err = r.SaveOpenAIConversationBinding(ctx, &other, 0)
	require.ErrorIs(t, err, service.ErrOpenAIHistoryConflict)
	_, err = r.SaveOpenAIConversationBinding(ctx, &other, 1)
	require.NoError(t, err)
	_, err = r.SaveOpenAIConversationBinding(ctx, &confirmed, 1)
	require.ErrorIs(t, err, service.ErrOpenAIHistoryConflict, "旧响应不能确认另一账号的新预占")
	got, err = r.GetOpenAIConversationBinding(ctx, 1, 7, "session", b.Key)
	require.NoError(t, err)
	require.Equal(t, int64(2), got.AccountID)
	require.False(t, got.Confirmed)
	response := *b
	response.Type = "response"
	response.Key = strings.Repeat("b", 64)
	_, err = r.SaveOpenAIConversationBinding(ctx, &response, 0)
	require.NoError(t, err)
	response.Confirmed = true
	_, err = r.SaveOpenAIConversationBinding(ctx, &response, 0)
	require.NoError(t, err)
	foreignResponse := response
	foreignResponse.AccountID = 2
	foreignResponse.CredentialOwnerAccountID = 2
	foreignResponse.OAuthAccountID = "owner-b"
	_, err = r.SaveOpenAIConversationBinding(ctx, &foreignResponse, 1)
	require.ErrorIs(t, err, service.ErrOpenAIHistoryConflict)
	_, err = db.Exec(`UPDATE accounts SET credentials=credentials || '{"access_token":"refreshed"}' WHERE id=1`)
	require.NoError(t, err)
	got, err = r.GetOpenAIConversationBinding(ctx, 1, 7, "response", response.Key)
	require.NoError(t, err)
	require.True(t, got.Valid)
	_, err = db.Exec(`UPDATE accounts SET credentials=credentials || '{"chatgpt_account_id":"reauthorized"}' WHERE id=1`)
	require.NoError(t, err)
	got, err = r.GetOpenAIConversationBinding(ctx, 1, 7, "response", response.Key)
	require.NoError(t, err)
	require.False(t, got.Valid)
	_, err = r.SaveOpenAIConversationBinding(ctx, &response, 0)
	require.ErrorIs(t, err, service.ErrOpenAIHistoryConflict)
	_, err = db.Exec(`UPDATE accounts SET deleted_at=NOW() WHERE id=1`)
	require.NoError(t, err)
	got, err = r.GetOpenAIConversationBinding(ctx, 1, 7, "response", response.Key)
	require.NoError(t, err)
	require.Nil(t, got)
	_, err = db.Exec(`UPDATE users SET deleted_at=NOW() WHERE id=1`)
	require.NoError(t, err)
	var count int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM openai_conversation_bindings`).Scan(&count))
	require.Zero(t, count)
}
