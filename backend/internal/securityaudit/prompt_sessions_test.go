package securityaudit

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
)

// 会话列表与事件筛选必须按用户隔离，即使客户端提供相同会话标识。
func TestPromptAuditSessionsBrowseAndFilter(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	users := []int64{insertIdentity(t, db, "users"), insertIdentity(t, db, "users")}
	for _, user := range users {
		snapshot := integrationSnapshot("session")
		snapshot.UserID = user
		snapshot.SessionKey = HashSessionKey(user, snapshot.Protocol, "header:session-id", "same")
		snapshot.FullPrompt = "retained evidence"
		snapshot.FullContextCiphertext = "encrypted"
		snapshot.FullContextHash = "context"
		_, err := repo.RecordBlocking(ctx, snapshot, 1, integrationResult(EventCritical), true)
		require.NoError(t, err)
	}
	s := &PromptService{repo: repo}
	page, err := s.ListSessions(ctx, &users[0], 1, 20)
	require.NoError(t, err)
	require.Equal(t, int64(1), page.Total)
	require.Len(t, page.Items, 1)
	item := page.Items[0]
	require.Equal(t, int64(1), item.RiskCount)
	require.Equal(t, int64(1), item.EvidenceCount)
	events, err := repo.ListEvents(ctx, EventFilter{SessionID: &item.ID}, 1, 20)
	require.NoError(t, err)
	require.Len(t, events.Items, 1)
	require.Equal(t, users[0], events.Items[0].Snapshot.UserID)
	require.Empty(t, events.Items[0].Snapshot.FullPrompt, "列表不得加载完整证据")
	require.True(t, events.Items[0].FullContextAvailable)
	// 证据过期后即使清理尚未执行，也不能继续读取或下载。
	_, err = db.ExecContext(ctx, `UPDATE prompt_audit_chat_records SET retention_until=NOW()-INTERVAL '1 second' WHERE id=$1`, events.Items[0].Snapshot.ChatRecordID)
	require.NoError(t, err)
	detail, err := repo.GetEvent(ctx, events.Items[0].ID)
	require.NoError(t, err)
	require.Empty(t, detail.Snapshot.FullPrompt)
	require.False(t, detail.FullContextAvailable)
	_, err = repo.GetEventContext(ctx, detail.ID)
	require.ErrorIs(t, err, ErrEventContextNotFound)
}
