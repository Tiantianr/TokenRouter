package securityaudit

import (
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestScanEventIncludesObservabilityMetadataAndFullPrompt(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	createdAt := time.Unix(100, 0).UTC()
	columns := make([]string, 50)
	for index := range columns {
		columns[index] = "column"
	}
	rows := sqlmock.NewRows(columns).AddRow(
		int64(1), int64(2), "request-1", int64(3), "alice", "alice@example.test", int64(4), "key-1",
		int64(5), "group-1", "openai", "/v1/responses", "openai_responses", "gpt-test", "hash", "red***", "http",
		"critical", "critical", "Block", `["pii","jailbreak"]`, `["jailbreak"]`, `{"pii":1,"jailbreak":1}`, `{"pii":"PII","jailbreak":"Jailbreak"}`,
		"qwen3guard-openai", "test", "guard-1", "Primary Guard", "guard-model", "priority", 1, int64(9), 4, 27004, createdAt,
		"203.0.113.42", 395959, 1, "blocking", 0, 100000, 3, false,
		"", "", true, "session-key", "client_session", int64(10), "complete prompt",
	)
	mock.ExpectQuery("SELECT").WillReturnRows(rows)

	event, err := scanEvent(db.QueryRow("SELECT event"), true)
	require.NoError(t, err)
	require.Equal(t, "203.0.113.42", event.Snapshot.ClientIP)
	require.Equal(t, 395959, event.Snapshot.PromptLength)
	require.Equal(t, ModeBlocking, event.ExecutionMode)
	require.Equal(t, 0, *event.QueueDelayMS)
	require.Equal(t, 100000, *event.InputLimit)
	require.Equal(t, 3, *event.MatchedChunkIndex)
	require.Equal(t, "Primary Guard", event.GuardEndpointName)
	require.Equal(t, "guard-model", event.GuardModel)
	require.Equal(t, []string{"jailbreak"}, event.Categories)
	require.Equal(t, []string{"jailbreak"}, event.MatchedScanners)
	require.NotContains(t, event.ScannerScores, "pii")
	require.NotContains(t, event.ScannerEvidence, "pii")
	require.Len(t, event.IssueSummaries, 1)
	require.Equal(t, "jailbreak", event.IssueSummaries[0].Category)
	require.False(t, event.Snapshot.FullPromptTruncated)
	require.True(t, event.Snapshot.BlockingExemptAtRequest)
	require.Equal(t, "session-key", event.Snapshot.SessionKey)
	require.Equal(t, "client_session", event.Snapshot.SessionSource)
	require.Equal(t, int64(10), event.Snapshot.ChatRecordID)
	require.Equal(t, "complete prompt", event.Snapshot.FullPrompt)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestBuildEventWhereFiltersExactClientIP(t *testing.T) {
	where, args := buildEventWhere(EventFilter{ClientIP: "2001:0db8::1"}, 1)
	require.Contains(t, where, "e.client_ip=$1")
	require.Equal(t, []any{"2001:db8::1"}, args)
}

func TestBuildEventWhereFiltersAsyncDeepExecutionMode(t *testing.T) {
	where, args := buildEventWhere(EventFilter{ExecutionMode: " ASYNC_DEEP "}, 1)
	require.Contains(t, where, "e.execution_mode=$1")
	require.Equal(t, []any{"async_deep"}, args)
}

func TestBuildEventWhereLeavesDefaultFilterUnchanged(t *testing.T) {
	where, args := buildEventWhere(EventFilter{}, 1)
	require.Equal(t, " WHERE TRUE", where)
	require.NotContains(t, where, "error_code")
	require.Empty(t, args)

	where, args = buildEventWhere(EventFilter{Keyword: "Prompt Audit dependency"}, 1)
	require.Contains(t, where, "e.error_code ILIKE $1")
	require.Contains(t, where, "e.error_message ILIKE $1")
	require.Equal(t, []any{"%Prompt Audit dependency%"}, args)
}
