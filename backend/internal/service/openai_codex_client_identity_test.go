package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// 同 session 的父子线程必须分开；同一真实 turn 在工具续轮中必须稳定。
func TestCodexClientIdentityThreadsAndLineage(t *testing.T) {
	account := codexSessionFlowAccount()
	headers := http.Header{"Session-Id": {"root"}, "Thread-Id": {"root"}}
	root := resolveCodexFingerprintIDsForTurn(account, headers, []byte(`{"client_metadata":{"turn_id":"turn-root","root_turn_id":"turn-root"}}`), 7)
	childBody := []byte(`{"client_metadata":{"session_id":"root","thread_id":"child","turn_id":"turn-child","parent_thread_id":"root","parent_turn_id":"turn-root","root_turn_id":"turn-root","x-codex-window-id":"child:3","window_number":3}}`)
	child := resolveCodexFingerprintIDsForTurn(account, headers, childBody, 7)
	require.Equal(t, testCodexSessionOverride, root.sessionID)
	require.Equal(t, root.sessionID, child.sessionID)
	require.NotEqual(t, root.threadID, child.threadID)
	require.Equal(t, resolveConvergedThreadID(testCodexFingerprintSeed, "root"), root.threadID)
	require.Equal(t, root.threadID, child.lineage["parent_thread_id"])
	require.Equal(t, root.turnID, root.lineage["root_turn_id"])
	require.Equal(t, root.turnID, child.lineage["root_turn_id"])
	require.Equal(t, root.turnID, child.lineage["parent_turn_id"])
	require.Equal(t, child.threadID+":3", child.windowID)
	repeated := resolveCodexFingerprintIDsForTurn(account, headers, childBody, 7)
	require.Equal(t, child.turnID, repeated.turnID)
	otherUser := resolveCodexFingerprintIDsForTurn(account, headers, childBody, 8)
	require.NotEqual(t, child.turnID, otherUser.turnID)
	require.Equal(t, testCodexFingerprintSeed, account.Extra[codexFingerprintSeedExtraKey])
	account.Extra[codexFingerprintModeExtraKey] = "full"
	full := resolveCodexFingerprintIDsForTurn(account, headers, childBody, 7)
	require.Equal(t, full.sessionID, full.threadID)
	require.Equal(t, full.threadID, full.lineage["parent_thread_id"])
}

// 当前帧内嵌 metadata 优先于旧握手，并保留真实窗口号及时间戳。
func TestCodexClientIdentityFramePrecedence(t *testing.T) {
	headers := http.Header{"Session-Id": {"old-session"}, "Thread-Id": {"old-thread"}}
	headers.Set(openAIWSTurnMetadataHeader, `{"turn_id":"old-turn","window_id":"old-thread:0"}`)
	body := []byte(`{"client_metadata":{"x-codex-turn-metadata":"{\"session_id\":\"current-session\",\"thread_id\":\"current-thread\",\"turn_id\":\"current-turn\",\"root_turn_id\":\"current-turn\",\"window_number\":7,\"turn_started_at_unix_ms\":1700000000000}"}}`)
	ids := resolveCodexFingerprintIDsForTurn(codexSessionFlowAccount(), headers, body, 9)
	require.Equal(t, resolveConvergedThreadID(testCodexFingerprintSeed, "current-thread"), ids.threadID)
	require.Equal(t, ids.threadID+":7", ids.windowID)
	require.Equal(t, int64(1700000000000), ids.turnStartedAtUnixMs)
	require.Equal(t, ids.turnID, ids.lineage["root_turn_id"])
	windowOnly := resolveCodexFingerprintIDsForTurn(codexSessionFlowAccount(), headers, []byte(`{"client_metadata":{"window_id":"current-thread:9"}}`), 9)
	require.Equal(t, ids.threadID+":9", windowOnly.windowID, "当前帧窗口中的线程优先于旧握手")
}

// 复合缓存键与父线程同步；兼容别名不能残留账号隔离阶段的旧值。
func TestCodexClientIdentityCompositeCacheAndAliases(t *testing.T) {
	account := codexSessionFlowAccount()
	parent := "11111111-1111-4111-8111-111111111111"
	body := []byte(fmt.Sprintf(`{"prompt_cache_key":"guardian:%s","client_metadata":{"session_id":%q,"thread-id":"child","parent_thread_id":%q,"x-client-request-id":"child","turn-id":"child-turn"}}`, parent, parent, parent))
	ids := resolveCodexFingerprintIDsForTurn(account, nil, body, 7)
	scoped, _, err := applyCodexAccountIdentityClientMetadataRaw(body, account, 7)
	require.NoError(t, err)
	out, _, err := applyCodexFingerprintClientMetadataRaw(scoped, ids)
	require.NoError(t, err)
	require.Equal(t, "guardian:"+fmt.Sprint(ids.lineage["parent_thread_id"]), gjson.GetBytes(out, "prompt_cache_key").String())
	require.Equal(t, ids.threadID, gjson.GetBytes(out, "client_metadata.thread-id").String())
	require.Equal(t, ids.threadID, gjson.GetBytes(out, "client_metadata.x-client-request-id").String())
	require.Equal(t, ids.turnID, gjson.GetBytes(out, "client_metadata.turn-id").String())
}

// 顶层 client_metadata 是字符串字典；内嵌 turn metadata 的序号和时间戳保持数值。
func TestCodexClientMetadataScalarTypes(t *testing.T) {
	for _, mode := range []string{"session", "full"} {
		for _, quoted := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/quoted=%t", mode, quoted), func(t *testing.T) {
				account := codexSessionFlowAccount()
				account.Extra[codexFingerprintModeExtraKey] = mode
				window, timestamp := "7", "1700000000000"
				if quoted {
					window, timestamp = `"7"`, `"1700000000000"`
				}
				body := []byte(fmt.Sprintf(`{"client_metadata":{"thread_id":"current-thread","window_number":%s,"turn_started_at_unix_ms":%s,"x-codex-turn-metadata":"{}"}}`, window, timestamp))
				headers := http.Header{"X-Codex-Window-Id": {"stale-thread:0"}, "X-Codex-Turn-Metadata": {`{}`}}
				ids := resolveCodexFingerprintIDsForTurn(account, headers, body, 7)
				out, _, err := applyCodexFingerprintClientMetadataRaw(body, ids)
				require.NoError(t, err)
				var flat map[string]string
				require.NoError(t, json.Unmarshal([]byte(gjson.GetBytes(out, "client_metadata").Raw), &flat))
				require.Equal(t, "7", flat["window_number"])
				require.Equal(t, "1700000000000", flat["turn_started_at_unix_ms"])
				require.Equal(t, ids.threadID+":7", flat["x-codex-window-id"])
				applyCodexFingerprintHeaders(headers, ids)
				for _, embedded := range []string{flat[openAIWSTurnMetadataHeader], headers.Get(openAIWSTurnMetadataHeader)} {
					require.Equal(t, gjson.Number, gjson.Get(embedded, "window_number").Type)
					require.Equal(t, int64(7), gjson.Get(embedded, "window_number").Int())
					require.Equal(t, gjson.Number, gjson.Get(embedded, "turn_started_at_unix_ms").Type)
					require.Equal(t, int64(1700000000000), gjson.Get(embedded, "turn_started_at_unix_ms").Int())
				}
			})
		}
	}
}

// 关闭额外收敛仍保留账号隔离，但不能把相等的根会话标识映射成不同 UUID。
func TestCodexAccountIdentityPreservesRelationships(t *testing.T) {
	account := codexSessionFlowAccount()
	account.Extra[codexFingerprintModeExtraKey] = "off"
	thread := "11111111-1111-4111-8111-111111111111"
	metadata := map[string]any{"session_id": thread, "thread_id": thread, "x-client-request-id": thread, "window_id": thread + ":5", "turn_id": "root-turn", "root_turn_id": "root-turn"}
	body := map[string]any{"client_metadata": metadata, "prompt_cache_key": thread}
	require.True(t, applyCodexAccountIdentityClientMetadataMap(body, account, 7))
	require.Equal(t, metadata["session_id"], metadata["thread_id"])
	require.Equal(t, metadata["thread_id"], metadata["x-client-request-id"])
	require.Equal(t, metadata["thread_id"], body["prompt_cache_key"])
	require.Equal(t, fmt.Sprint(metadata["thread_id"])+":5", metadata["window_id"])
	require.Equal(t, metadata["turn_id"], metadata["root_turn_id"])
	require.Equal(t, metadata["session_id"], isolateOpenAIUpstreamSessionID(7, account, thread))
	require.Equal(t, "guardian:"+fmt.Sprint(metadata["thread_id"]), scopeCodexAccountIdentityValue(account, 7, "prompt-cache", "guardian:"+thread))
}

// 真正经过 HTTP 转 WS 的请求必须在握手、flat body、嵌入对象上保持同一引用。
func TestCodexClientIdentityWire(t *testing.T) {
	svc, requests := newCodexSessionWireGateway(t)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set("session-id", "root-session")
	c.Request.Header.Set("thread-id", "stale-thread")
	c.Request.Header.Set(openAIWSTurnMetadataHeader, `{"turn_id":"stale-turn"}`)
	metadata := map[string]any{"session_id": "root-session", "thread_id": "child-thread", "turn_id": "child-turn", "root_turn_id": "root-turn", "parent_turn_id": "root-turn", "parent_thread_id": "root-session", "window_id": "child-thread:4", "window_number": 4}
	embedded, err := json.Marshal(metadata)
	require.NoError(t, err)
	metadata[openAIWSTurnMetadataHeader] = string(embedded)
	body, err := json.Marshal(map[string]any{"model": "gpt-5.1", "stream": true, "input": "hello", "client_metadata": metadata})
	require.NoError(t, err)
	_, err = svc.Forward(context.Background(), c, codexSessionFlowAccount(), body)
	require.NoError(t, err)
	wire := readCodexSessionWire(t, requests)
	assertCodexSessionWire(t, wire, testCodexSessionOverride, true)
	want := resolveCodexFingerprintIDsForTurn(codexSessionFlowAccount(), c.Request.Header, body, 0)
	require.Equal(t, want.threadID+":4", wire.headers.Get("x-codex-window-id"))
	require.Equal(t, want.lineage["root_turn_id"], gjson.GetBytes(wire.body, "client_metadata.root_turn_id").String())
	require.Equal(t, want.lineage["parent_thread_id"], wire.headers.Get("x-codex-parent-thread-id"))
	inner := gjson.GetBytes(wire.body, "client_metadata."+openAIWSTurnMetadataHeader).String()
	require.Equal(t, want.lineage["root_turn_id"], gjson.Get(inner, "root_turn_id").String())
	require.Equal(t, int64(4), gjson.Get(inner, "window_number").Int())
}
