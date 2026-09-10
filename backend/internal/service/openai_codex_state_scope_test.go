//go:build unit

package service

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/TokenFlux/TokenRouter/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// 同一 session 的两次签发各自保留来源，不能用最近账号覆盖整个会话。
func TestCodexTurnStatePerValueAndExecution(t *testing.T) {
	svc := &OpenAIGatewayService{}
	a := codexSessionFlowAccount()
	b := codexSessionFlowAccount()
	b.ID++
	b.Credentials = map[string]any{"chatgpt_account_id": "another-owner"}
	c, _ := newTurnStateTestContext(t, 7, "shared-session")
	stageCodexClientIdentity(c, []byte(`{"client_metadata":{"thread_id":"child-a","turn_id":"turn-a"}}`))
	svc.relayOpenAICodexTurnState(c, a, http.Header{"X-Codex-Turn-State": {"state-a"}})
	svc.relayOpenAICodexTurnState(c, b, http.Header{"X-Codex-Turn-State": {"state-b"}})
	assertEcho := func(ctx *gin.Context, account *Account, state string, allowed bool) {
		t.Helper()
		h := http.Header{"X-Codex-Turn-State": {state}}
		svc.guardOpenAICodexTurnStateEcho(ctx, account, h)
		if allowed {
			require.Equal(t, state, h.Get(openAICodexTurnStateHeader))
		} else {
			require.Empty(t, h.Get(openAICodexTurnStateHeader))
		}
	}
	assertEcho(c, a, "state-a", true)
	assertEcho(c, b, "state-b", true)
	assertEcho(c, b, "state-a", false)
	assertEcho(c, a, "untracked-client-state", true)
	for _, tc := range []struct {
		user         int64
		thread, turn string
	}{
		{8, "child-a", "turn-a"}, {7, "child-b", "turn-a"}, {7, "child-a", "turn-b"},
	} {
		d, _ := newTurnStateTestContext(t, tc.user, "shared-session")
		stageCodexClientIdentity(d, []byte(fmt.Sprintf(`{"client_metadata":{"thread_id":%q,"turn_id":%q}}`, tc.thread, tc.turn)))
		assertEcho(d, a, "state-a", false)
	}
	changed, err := accountWithCodexSessionDraft(a, CodexSessionOverride{Enabled: true, SessionID: "33333333-3333-4333-8333-333333333333"})
	require.NoError(t, err)
	assertEcho(c, changed, "state-a", false)
}

// 复现审查中发现的两个缺口：旧 session 缓存自动回填，以及 WS 未调用来源守卫。
func TestCodexTurnStateWireRejectsForeignAndCachedValues(t *testing.T) {
	for _, tc := range []struct{ name, incoming, want string }{
		{"no-client-echo", "", ""}, {"known-foreign", "foreign-state", ""}, {"unknown-client", "unknown-state", "unknown-state"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, requests := newCodexSessionWireGateway(t)
			c, _ := newTurnStateTestContext(t, 7, "wire-session")
			svc.getOpenAIWSStateStore().BindSessionTurnState(0, svc.GenerateSessionHash(c, nil), "foreign-state", time.Hour)
			svc.relayOpenAICodexTurnState(c, &Account{ID: 999}, http.Header{"X-Codex-Turn-State": {"foreign-state"}})
			c.Request.Header.Set(openAICodexTurnStateHeader, tc.incoming)
			_, err := svc.Forward(context.Background(), c, codexSessionFlowAccount(), []byte(`{"model":"gpt-5.1","stream":true,"input":"hi"}`))
			require.NoError(t, err)
			wire := readCodexSessionWire(t, requests)
			require.Equal(t, tc.want, wire.headers.Get(openAICodexTurnStateHeader))
		})
	}
}

// 复用同一上游连接不意味着旧握手状态在新 turn 再次签发。
func TestCodexTurnStateReusedHandshakeIsNotReissued(t *testing.T) {
	svc, requests := newCodexSessionWireGateway(t, http.Header{"X-Codex-Turn-State": {"issued-on-connect"}})
	for turn := 1; turn <= 2; turn++ {
		c, _ := newTurnStateTestContext(t, 7, "same-thread")
		body := []byte(fmt.Sprintf(`{"model":"gpt-5.1","stream":true,"input":"hi","client_metadata":{"turn_id":"turn-%d"}}`, turn))
		result, err := svc.Forward(context.Background(), c, codexSessionFlowAccount(), body)
		require.NoError(t, err)
		_ = readCodexSessionWire(t, requests)
		if turn == 1 {
			require.Equal(t, "issued-on-connect", result.ResponseHeaders.Get(openAICodexTurnStateHeader))
		} else {
			require.Empty(t, result.ResponseHeaders.Get(openAICodexTurnStateHeader))
			require.Empty(t, c.Writer.Header().Get(openAICodexTurnStateHeader))
		}
	}
	require.Equal(t, int64(1), svc.SnapshotOpenAIWSPoolMetrics().AcquireReuseTotal)
}

// 子代理各自保有租约；只有同一用户线程的新连接抢占旧连接。
func TestCodexWSPreemptionSeparatesChildThreads(t *testing.T) {
	svc := &OpenAIGatewayService{}
	account := codexSessionFlowAccount()
	begin := func(user int64, thread string) (context.Context, func()) {
		c, _ := newTurnStateTestContext(t, user, "same-root-session")
		group := int64(7)
		c.Set("api_key", &APIKey{ID: user, GroupID: &group})
		ctx, cleanup, armed := svc.BeginOpenAIWSIngressSessionPreemption(context.Background(), c, account, []byte(fmt.Sprintf(`{"client_metadata":{"thread_id":%q}}`, thread)))
		require.True(t, armed)
		return ctx, cleanup
	}
	root, cleanRoot := begin(7, "root")
	defer cleanRoot()
	child, cleanChild := begin(7, "child")
	defer cleanChild()
	other, cleanOther := begin(8, "root")
	defer cleanOther()
	require.NoError(t, root.Err())
	replacement, cleanReplacement := begin(7, "root")
	defer cleanReplacement()
	require.True(t, IsOpenAIWSSessionPreemptedError(context.Cause(root)))
	require.NoError(t, child.Err())
	require.NoError(t, other.Err())
	require.NoError(t, replacement.Err())
}

// 即使 full 模式对外 thread 相等，连接仍按原始用户线程隔离，且共用账号预算。
func TestCodexWSPoolIsolationRetainsAccountBudget(t *testing.T) {
	cfg := &config.Config{}
	cfg.Gateway.OpenAIWS.MaxConnsPerAccount = 1
	cfg.Gateway.OpenAIWS.MaxIdlePerAccount = 1
	pool := newOpenAIWSConnPool(cfg)
	pool.setClientDialerForTest(&openAIWSFakeDialer{})
	defer pool.Close()
	account := codexSessionFlowAccount()
	account.Extra[codexFingerprintModeExtraKey] = "full"
	request := func(user int64, thread string) openAIWSAcquireRequest {
		c, _ := newTurnStateTestContext(t, user, "root")
		stageCodexClientIdentity(c, []byte(fmt.Sprintf(`{"client_metadata":{"thread_id":%q}}`, thread)))
		return openAIWSAcquireRequest{Account: account, WSURL: "wss://example.test/responses", Headers: http.Header{"Thread-Id": {testCodexSessionOverride}}, IsolationKey: codexWSStateScope(c, account)}
	}
	firstReq := request(7, "root")
	first, err := pool.Acquire(context.Background(), firstReq)
	require.NoError(t, err)
	defer first.Release()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, err = pool.Acquire(ctx, request(8, "root"))
	require.Error(t, err, "不能按作用域分裂账号连接总预算")
	firstID := first.ConnID()
	first.Release()
	second, err := pool.Acquire(context.Background(), request(7, "child"))
	require.NoError(t, err)
	defer second.Release()
	require.NotEqual(t, firstID, second.ConnID())
	require.False(t, second.Reused())
}

// 压缩窗口增加可复用线程连接，切换真实 thread 必须显式重连。
func TestCodexWSWindowProgressionAndThreadBoundary(t *testing.T) {
	account := codexSessionFlowAccount()
	a := http.Header{"Thread-Id": {"thread"}, "X-Codex-Window-Id": {"thread:3"}}
	b := a.Clone()
	b.Set("X-Codex-Window-Id", "thread:4")
	require.Equal(t, normalizeOpenAIWSHandshakeCompatibility(account, a, "scope"), normalizeOpenAIWSHandshakeCompatibility(account, b, "scope"))
	c, _ := newTurnStateTestContext(t, 7, "root")
	first := []byte(`{"client_metadata":{"thread_id":"child"}}`)
	c.Set(codexWSClientIdentityContextKey, readCodexClientIdentity(c.Request.Header, first))
	require.NoError(t, validateCodexWSThread(c, []byte(`{"client_metadata":{"turn_id":"next-turn"}}`)))
	require.Equal(t, "child", codexRequestHeaders(c).Get("thread-id"))
	require.Error(t, validateCodexWSThread(c, []byte(`{"client_metadata":{"thread_id":"other-child"}}`)))
}
