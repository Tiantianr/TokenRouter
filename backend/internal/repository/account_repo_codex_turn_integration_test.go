//go:build integration

package repository

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/TokenFlux/TokenRouter/internal/service"
	"github.com/stretchr/testify/require"
)

// 真实 PostgreSQL 验证跨连接 CAS 和 outbox 原子性，以及普通编辑不覆盖专用状态。
func TestCodexAccountTurnRepositoryCAS(t *testing.T) {
	ctx := context.Background()
	client := testEntClient(t)
	repo := newAccountRepositoryWithSQL(client, integrationDB, nil)
	a := &service.Account{Name: "codex-turn-cas", Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth, Status: service.StatusActive, Concurrency: 1,
		Credentials: map[string]any{"access_token": "fake-token"}, Extra: map[string]any{"codex_fingerprint_mode": "session", service.CodexAccountTurnExtraKey: map[string]any{"enabled": false, "revision": "v1"}}}
	require.NoError(t, repo.Create(ctx, a))
	t.Cleanup(func() {
		// 本测试跨连接提交事务，必须清理自己的账号及单账号/批量 outbox，避免污染后续全局断言。
		_, err := integrationDB.ExecContext(ctx, "DELETE FROM scheduler_outbox WHERE account_id = $1 OR payload -> 'account_ids' @> jsonb_build_array($1::bigint)", a.ID)
		require.NoError(t, err)
		_, err = integrationDB.ExecContext(ctx, "DELETE FROM accounts WHERE id = $1", a.ID)
		require.NoError(t, err)
	})
	snapshot, err := repo.GetByID(ctx, a.ID)
	require.NoError(t, err)
	var before int
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT count(*) FROM scheduler_outbox WHERE account_id = $1", a.ID).Scan(&before))
	var wg sync.WaitGroup
	writes := make(chan bool, 2)
	errors := make(chan error, 2)
	for _, revision := range []string{"v2-a", "v2-b"} {
		wg.Add(1)
		go func(revision string) {
			defer wg.Done()
			written, err := repo.CompareAndSwapCodexSession(ctx, snapshot, map[string]any{service.CodexAccountTurnExtraKey: map[string]any{"enabled": false, "revision": revision}})
			writes <- written
			errors <- err
		}(revision)
	}
	wg.Wait()
	require.NoError(t, <-errors)
	require.NoError(t, <-errors)
	require.NotEqual(t, <-writes, <-writes, "并发只有一个数据库写入可以获胜")
	var after int
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT count(*) FROM scheduler_outbox WHERE account_id = $1", a.ID).Scan(&after))
	require.Equal(t, before+1, after, "失败 CAS 不能写 outbox")
	fresh, err := repo.GetByID(ctx, a.ID)
	require.NoError(t, err)
	currentJSON, err := json.Marshal(fresh.Extra[service.CodexAccountTurnExtraKey])
	require.NoError(t, err)
	// 使用 CAS 前取到的旧对象保存普通账号字段，必须保留数据库最新专用配置。
	snapshot.Name = "renamed-after-rotation"
	require.NoError(t, repo.Update(ctx, snapshot))
	afterEdit, err := repo.GetByID(ctx, a.ID)
	require.NoError(t, err)
	actualJSON, err := json.Marshal(afterEdit.Extra[service.CodexAccountTurnExtraKey])
	require.NoError(t, err)
	require.JSONEq(t, string(currentJSON), string(actualJSON))
	// 凭据替换后，即使回合版本相同，旧响应也不能覆盖状态。
	require.NoError(t, repo.UpdateCredentials(ctx, a.ID, map[string]any{"access_token": "replacement-token"}))
	written, err := repo.CompareAndSwapCodexSession(ctx, afterEdit, map[string]any{service.CodexAccountTurnExtraKey: map[string]any{"revision": "late"}})
	require.NoError(t, err)
	require.False(t, written)
	refreshed, err := repo.GetByID(ctx, a.ID)
	require.NoError(t, err)
	require.Contains(t, refreshed.Extra, service.CodexAccountTurnExtraKey, "后台正常刷新保留账号配置")
	// 管理员显式替换 token 与后台刷新不同，必须要求重新测试保存。
	refreshed.Credentials["access_token"] = "manually-replaced-token"
	require.NoError(t, repo.Update(ctx, refreshed))
	replaced, err := repo.GetByID(ctx, a.ID)
	require.NoError(t, err)
	require.NotContains(t, replaced.Extra, service.CodexAccountTurnExtraKey)

	for _, edit := range []struct {
		name  string
		apply func() error
	}{
		{"增量修改模式", func() error { return repo.UpdateExtra(ctx, a.ID, map[string]any{"codex_fingerprint_mode": "full"}) }},
		{"批量替换凭据", func() error {
			_, err := repo.BulkUpdate(ctx, []int64{a.ID}, service.AccountBulkUpdate{Credentials: map[string]any{"access_token": "batch-token"}})
			return err
		}},
	} {
		t.Run(edit.name, func(t *testing.T) {
			current, err := repo.GetByID(ctx, a.ID)
			require.NoError(t, err)
			written, err := repo.CompareAndSwapCodexSession(ctx, current, map[string]any{service.CodexAccountTurnExtraKey: map[string]any{"enabled": false, "revision": "before-edit"}})
			require.NoError(t, err)
			require.True(t, written)
			require.NoError(t, edit.apply())
			updated, err := repo.GetByID(ctx, a.ID)
			require.NoError(t, err)
			require.NotContains(t, updated.Extra, service.CodexAccountTurnExtraKey)
		})
	}
}
