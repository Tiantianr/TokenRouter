package securityaudit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOpenAICompatibleScannerAnalyzeRedactsTranscriptAndReturnsReport(t *testing.T) {
	const credential = "sk-analysis-canary-123456789"
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, "/v1/chat/completions", request.URL.Path)
		require.NoError(t, json.NewDecoder(request.Body).Decode(&received))
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"choices":[{"message":{"content":"风险等级：中\n建议继续观察。"}}]}`))
	}))
	defer server.Close()

	report, err := NewOpenAICompatibleScanner().Analyze(context.Background(), ActiveEndpoint{
		ID: "analysis-node", BaseURL: server.URL, Model: "guard-model", TimeoutMS: 1000,
	}, "用户尝试读取 token="+credential)
	require.NoError(t, err)
	require.Contains(t, report, "风险等级")
	require.NotContains(t, report, credential)

	messages, ok := received["messages"].([]any)
	require.True(t, ok)
	require.Len(t, messages, 2)
	userPayload, ok := messages[1].(map[string]any)
	require.True(t, ok)
	userMessage, ok := userPayload["content"].(string)
	require.True(t, ok)
	require.Contains(t, userMessage, "<CREDENTIAL>")
	require.NotContains(t, userMessage, credential)
	systemPayload, ok := messages[0].(map[string]any)
	require.True(t, ok)
	systemMessage, ok := systemPayload["content"].(string)
	require.True(t, ok)
	require.Contains(t, systemMessage, "不可信数据")
}

func TestHashSessionKeyIsUserAndProtocolScoped(t *testing.T) {
	first := HashSessionKey(7, "openai_responses", "header:session-id", "client-session")
	require.Len(t, first, 64)
	require.Equal(t, first, HashSessionKey(7, "openai_responses", "header:session-id", "client-session"))
	require.NotEqual(t, first, HashSessionKey(8, "openai_responses", "header:session-id", "client-session"))
	require.NotEqual(t, first, HashSessionKey(7, "openai_chat", "header:session-id", "client-session"))
	require.NotEqual(t, first, HashSessionKey(7, "openai_responses", "body:conversation_id", "client-session"))
	require.Empty(t, HashSessionKey(7, "openai_responses", "header:session-id", ""))
}

func TestBuildUserAnalysisTranscriptIsChronologicalAndBounded(t *testing.T) {
	records := []UserChatRecord{
		{CreatedAt: time.Unix(3, 0), FullPrompt: "third"},
		{CreatedAt: time.Unix(1, 0), FullPrompt: "first"},
		{CreatedAt: time.Unix(2, 0), FullPrompt: "second"},
	}
	transcript := buildUserAnalysisTranscript(records)
	require.Less(t, strings.Index(transcript, "first"), strings.Index(transcript, "second"))
	require.Less(t, strings.Index(transcript, "second"), strings.Index(transcript, "third"))
}

func TestBuildUserAnalysisTranscriptPrioritizesSelectedRecord(t *testing.T) {
	records := []UserChatRecord{
		{ID: 1, CreatedAt: time.Unix(1, 0), FullPrompt: strings.Repeat("old", maxUserAnalysisRunes)},
		{ID: 2, CreatedAt: time.Unix(2, 0), FullPrompt: "selected-session-marker"},
	}
	transcript, included := buildBoundedUserAnalysisTranscript(records, 2)
	require.Contains(t, transcript, "selected-session-marker")
	require.NotEmpty(t, included)
	require.Contains(t, []int64{included[0].ID, included[len(included)-1].ID}, int64(2))
	require.LessOrEqual(t, len([]rune(transcript)), maxUserAnalysisRunes)
}
