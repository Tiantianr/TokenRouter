package apicompat

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// 验证实际 Responses→Chat 请求输出同时包含任务信封和正文，顺序和边界不丢失。
func TestResponsesToChatPreservesAgentTaskAndReply(t *testing.T) {
	request := &ResponsesRequest{Model: "test-model", Instructions: "system rules", Input: json.RawMessage(`[
		{"type":"reasoning","summary":[{"type":"summary_text","text":"previous thinking"}]},
		{"type":"agent_message","content":[{"type":"input_text","text":"Task from parent:\n"},{"type":"encrypted_content","encrypted_content":"Inspect parser.go\n"},{"type":"text","text":"Report concrete failures."}]},
		{"type":"message","role":"assistant","content":"Found a parsing defect."},
		{"type":"agent_message","content":"Parent reply: fix that defect."}
	]`)}
	chat, err := ResponsesToChatCompletionsRequest(request)
	require.NoError(t, err)
	require.Len(t, chat.Messages, 4)
	require.Equal(t, "system", chat.Messages[0].Role)
	require.Equal(t, "user", chat.Messages[1].Role)
	require.JSONEq(t, `"Task from parent:\nInspect parser.go\nReport concrete failures."`, string(chat.Messages[1].Content))
	require.Equal(t, "assistant", chat.Messages[2].Role)
	require.Empty(t, chat.Messages[2].ReasoningContent, "父任务以前的推理不应归给新任务")
	require.Equal(t, "user", chat.Messages[3].Role)
	require.JSONEq(t, `"Parent reply: fix that defect."`, string(chat.Messages[3].Content))
}

func TestAgentMessageEmptyAndUnknownContent(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `""`, `{}`, `[{"type":"image","text":"not task text"}]`} {
		messages, err := responsesInputToChatMessages("", json.RawMessage(`[{"type":"agent_message","content":`+raw+`},{"role":"user","content":"continue"}]`))
		require.NoError(t, err)
		require.Len(t, messages, 1)
		require.JSONEq(t, `"continue"`, string(messages[0].Content))
	}
}
