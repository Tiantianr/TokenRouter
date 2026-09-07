//go:build unit

package auditcontent

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConversationHistoryClassificationPreservesCanonicalContent(t *testing.T) {
	for _, tc := range []struct {
		name, protocol, body string
		history              bool
	}{
		{"new_responses", "openai_responses", `{"model":"gpt-5.1","instructions":"policy","tools":[{"type":"function","name":"read","parameters":{"type":"object"}}],"input":"hello"}`, false},
		{"additional_tools_declaration", "openai_responses", `{"input":[{"type":"additional_tools","id":"tools_1","role":"developer","tools":[{"type":"function","name":"read","description":"Read a file"}]},{"role":"user","content":"hello"}]}`, false},
		{"additional_tools_only", "openai_responses", `{"input":[{"type":"additional_tools","tools":[{"type":"function","name":"read","description":"Read a file"}]}]}`, false},
		{"additional_tools_with_call", "openai_responses", `{"input":[{"type":"additional_tools","role":"developer","tools":[]},{"type":"function_call","call_id":"call_1","name":"read","arguments":"{}"},{"role":"user","content":"next"}]}`, true},
		{"additional_tools_with_output", "openai_responses", `{"input":[{"type":"additional_tools","role":"developer","tools":[]},{"type":"function_call_output","call_id":"call_1","output":""},{"role":"user","content":"next"}]}`, true},
		{"mcp_list_tools_is_history", "openai_responses", `{"input":[{"type":"mcp_list_tools","server_label":"docs","tools":[{"name":"read","description":"Read a file"}]},{"role":"user","content":"next"}]}`, true},
		{"responses_user_context", "openai_responses", `{"input":[{"role":"user","content":"project rules"},{"role":"user","content":"environment"},{"role":"user","content":"first question"}]}`, false},
		{"responses_user_fragments", "openai_responses", `{"input":["project context",{"type":"input_text","text":"first question"}]}`, false},
		{"responses_trailing_instruction", "openai_responses", `{"input":[{"role":"user","content":"first question"},{"role":"developer","content":"policy"}]}`, false},
		{"responses_empty_assistant", "openai_responses", `{"input":[{"role":"assistant","content":null},{"role":"user","content":"next"}]}`, true},
		{"responses_encrypted_agent", "openai_responses", `{"input":[{"type":"agent_message","author":"assistant","recipient":"all","content":[{"type":"encrypted_content","encrypted_content":"opaque"}]},{"role":"user","content":"next"}]}`, true},
		{"responses_history", "openai_responses", `{"input":[{"role":"assistant","content":"old answer"},{"role":"user","content":"next"}]}`, true},
		{"responses_opaque", "openai_responses", `{"input":[{"type":"compaction","id":"cmp_1","encrypted_content":"opaque-state"},{"role":"user","content":"next"}]}`, true},
		{"responses_reference", "openai_responses", `{"input":[{"type":"item_reference","id":"fc_1"}]}`, true},
		{"responses_empty_output", "openai_responses", `{"input":[{"type":"function_call_output","call_id":"call_1","output":""}]}`, true},
		{"chat_new", "openai_chat_completions", `{"messages":[{"role":"system","content":"instructions"},{"role":"user","content":"new question"}]}`, false},
		{"chat_user_context", "openai_chat_completions", `{"messages":[{"role":"user","content":"project context"},{"role":"user","content":"first question"}]}`, false},
		{"chat_empty_assistant", "openai_chat_completions", `{"messages":[{"role":"user","content":"older prompt"},{"role":"assistant","content":null},{"role":"user","content":"next"}]}`, true},
		{"chat_tool", "openai_chat_completions", `{"messages":[{"role":"tool","tool_call_id":"call_1","content":{"ok":true}}]}`, true},
		{"messages_new", "anthropic_messages", `{"system":"instructions","messages":[{"role":"user","content":"new question"}]}`, false},
		{"messages_user_context", "anthropic_messages", `{"messages":[{"role":"user","content":"project context"},{"role":"user","content":"first question"}]}`, false},
		{"messages_tool", "anthropic_messages", `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"tool_1","content":""}]}]}`, true},
		{"messages_redacted", "anthropic_messages", `{"messages":[{"role":"assistant","content":[{"type":"redacted_thinking","data":"opaque"}]},{"role":"user","content":"next"}]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			document, err := Extract(tc.protocol, []byte(tc.body))
			require.NoError(t, err)
			require.Equal(t, tc.history, document.HistoryBearing)
		})
	}
}

func TestCodexFirstTurnHistoryDoesNotChangeAuditAttribution(t *testing.T) {
	body, err := os.ReadFile("testdata/codex_first_turn.json")
	require.NoError(t, err)
	document, err := Extract("openai_responses", body)
	require.NoError(t, err)
	require.False(t, document.HistoryBearing)
	require.False(t, document.Incomplete)
	var definitions []Segment
	var users []Segment
	for _, segment := range document.Segments {
		if segment.Source == SourceToolDefinition {
			definitions = append(definitions, segment)
		}
		if segment.Role == "user" {
			users = append(users, segment)
			require.Equal(t, SourceMessage, segment.Source)
			require.True(t, segment.ClientControlled)
		}
	}
	require.NotEmpty(t, definitions)
	require.Contains(t, definitions[0].Text, "Read a project file.")
	require.Len(t, users, 3)
	require.Contains(t, users[0].Text, "# AGENTS.md")
	require.Contains(t, users[1].Text, "<environment_context>")
	require.Contains(t, users[2].Text, "How many candies")
	require.False(t, users[0].Current)
	require.False(t, users[1].Current)
	require.True(t, users[2].Current)
}
