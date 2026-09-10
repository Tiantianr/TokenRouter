package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenFlux/TokenRouter/internal/config"
	"github.com/TokenFlux/TokenRouter/internal/pkg/tlsfingerprint"
	coderws "github.com/coder/websocket"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

const testCodexSessionOverride = "22222222-2222-4222-8222-222222222222"

type codexSessionWireRequest struct {
	headers http.Header
	body    []byte
}

// 测试拨号器只连接本地假上游，捕获实际握手与编码后的帧，避免仅验证内部 helper。
type codexSessionLocalDialer struct {
	url string
	openAIWSClientDialer
}

func (d *codexSessionLocalDialer) Dial(ctx context.Context, _ string, headers http.Header, _ string, _ *tlsfingerprint.Profile) (openAIWSClientConn, int, http.Header, error) {
	return d.openAIWSClientDialer.Dial(ctx, d.url, headers, "", nil)
}

func newCodexSessionWireGateway(t *testing.T, responseHeaders ...http.Header) (*OpenAIGatewayService, <-chan codexSessionWireRequest) {
	t.Helper()
	requests := make(chan codexSessionWireRequest, 16)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(responseHeaders) > 0 {
			for key, values := range responseHeaders[0] {
				w.Header()[key] = append([]string(nil), values...)
			}
		}
		conn, err := coderws.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.CloseNow() }()
		for turn := 1; ; turn++ {
			_, body, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			requests <- codexSessionWireRequest{headers: r.Header.Clone(), body: body}
			event := fmt.Sprintf(`{"type":"response.completed","response":{"id":"resp_session_%d","model":"gpt-5.1","usage":{"input_tokens":1,"output_tokens":1}}}`, turn)
			if err := conn.Write(r.Context(), coderws.MessageText, []byte(event)); err != nil {
				return
			}
		}
	}))
	t.Cleanup(upstream.Close)
	dialer := &codexSessionLocalDialer{url: "ws" + strings.TrimPrefix(upstream.URL, "http"), openAIWSClientDialer: newDefaultOpenAIWSClientDialer()}
	cfg := &config.Config{}
	cfg.Gateway.OpenAIWS.Enabled = true
	cfg.Gateway.OpenAIWS.OAuthEnabled = true
	cfg.Gateway.OpenAIWS.ResponsesWebsocketsV2 = true
	cfg.Gateway.OpenAIWS.MaxConnsPerAccount = 2
	cfg.Gateway.OpenAIWS.MaxIdlePerAccount = 2
	cfg.Gateway.OpenAIWS.DialTimeoutSeconds = 3
	cfg.Gateway.OpenAIWS.ReadTimeoutSeconds = 3
	cfg.Gateway.OpenAIWS.WriteTimeoutSeconds = 3
	pool := newOpenAIWSConnPool(cfg)
	pool.setClientDialerForTest(dialer)
	t.Cleanup(pool.Close)
	return &OpenAIGatewayService{
		cfg: cfg, httpUpstream: &httpUpstreamRecorder{}, cache: &stubGatewayCache{},
		openaiWSResolver: NewOpenAIWSProtocolResolver(cfg), toolCorrector: NewCodexToolCorrector(),
		openaiWSPool: pool, openaiWSPassthroughDialer: dialer,
	}, requests
}

func codexSessionFlowAccount() *Account {
	a := newTestOAuthAccount(901, map[string]any{
		codexFingerprintModeExtraKey: "session", codexSessionOverrideEnabledKey: true,
		codexSessionOverrideIDKey: testCodexSessionOverride, "responses_websockets_v2_enabled": true,
	})
	a.Status, a.Schedulable, a.Concurrency = StatusActive, true, 1
	a.Credentials = map[string]any{"access_token": "test-token"}
	return a
}

func readCodexSessionWire(t *testing.T, requests <-chan codexSessionWireRequest) codexSessionWireRequest {
	t.Helper()
	select {
	case req := <-requests:
		return req
	case <-time.After(5 * time.Second):
		t.Fatal("未收到本地上游请求")
		return codexSessionWireRequest{}
	}
}

func assertCodexSessionWire(t *testing.T, req codexSessionWireRequest, session string, checkTurnHeader bool) {
	t.Helper()
	// 按上游的字符串字典约束解码真实出站 body，不能只比较 ID 的文本值。
	var flat map[string]string
	require.NoError(t, json.Unmarshal([]byte(gjson.GetBytes(req.body, "client_metadata").Raw), &flat))
	for field, header := range map[string]string{
		"session_id": "session_id", "thread_id": "thread-id", "x-codex-installation-id": "x-codex-installation-id",
	} {
		value := gjson.GetBytes(req.body, "client_metadata."+field).String()
		require.NotEmpty(t, value, field)
		require.Equal(t, value, req.headers.Get(header), field)
	}
	require.Equal(t, session, req.headers.Get("session-id"))
	require.Equal(t, session, gjson.GetBytes(req.body, "client_metadata.session_id").String())
	turn := gjson.GetBytes(req.body, "client_metadata.turn_id").String()
	require.NotEmpty(t, turn)
	if checkTurnHeader {
		require.Equal(t, turn, gjson.Get(req.headers.Get("x-codex-turn-metadata"), "turn_id").String())
	}
	embedded := gjson.GetBytes(req.body, "client_metadata.x-codex-turn-metadata").String()
	require.Equal(t, session, gjson.Get(embedded, "session_id").String())
	require.Equal(t, turn, gjson.Get(embedded, "turn_id").String())
}

// HTTP 转 WS 必须保持握手与 body 身份一致，禁用覆盖则恢复原 seed 派生值。
func TestCodexSessionFlowHTTPToWebSocket(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			svc, requests := newCodexSessionWireGateway(t)
			account := codexSessionFlowAccount()
			account.Extra[codexSessionOverrideEnabledKey] = enabled
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
			c.Request.Header.Set("session-id", "real-client-session")
			c.Request.Header.Set("x-codex-turn-metadata", `{"session_id":"client-old","turn_id":"client-turn","window_number":3}`)
			_, err := svc.Forward(context.Background(), c, account, []byte(`{"model":"gpt-5.1","input":"hi","stream":true}`))
			require.NoError(t, err)
			want := testCodexSessionOverride
			if !enabled {
				want = resolveConvergedSessionID(testCodexFingerprintSeed)
			}
			assertCodexSessionWire(t, readCodexSessionWire(t, requests), want, true)
		})
	}
}

// 普通 HTTP 与 OAuth 透传均验证最终头体；影子账号不得用自身的陈旧配置派生身份。
func TestCodexSessionFlowHTTPAndPassthroughShadow(t *testing.T) {
	for _, passthrough := range []bool{false, true} {
		t.Run(fmt.Sprint(passthrough), func(t *testing.T) {
			parent := codexSessionFlowAccount()
			shadow := &Account{
				ID: 902, ParentAccountID: &parent.ID, Platform: PlatformOpenAI, Type: AccountTypeOAuth,
				Status: StatusActive, Schedulable: true, Concurrency: 1,
				Extra: map[string]any{"openai_passthrough": passthrough},
			}
			upstream := &httpUpstreamRecorder{resp: &http.Response{
				StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}},
				Body: io.NopCloser(strings.NewReader("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_http\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n")),
			}}
			svc := &OpenAIGatewayService{cfg: &config.Config{}, httpUpstream: upstream, accountRepo: stubOpenAIAccountRepo{accounts: []Account{*parent}}, toolCorrector: NewCodexToolCorrector()}
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
			c.Request.Header.Set("session-id", "client-session")
			c.Request.Header.Set("x-codex-turn-metadata", `{"session_id":"old","turn_id":"old"}`)
			_, err := svc.Forward(context.Background(), c, shadow, []byte(`{"model":"gpt-5.4","stream":true,"input":"hi","client_metadata":{"window_number":"3","turn_started_at_unix_ms":"1700000000000","x-codex-turn-metadata":"{\"session_id\":\"old\",\"turn_id\":\"old\",\"window_number\":3}"}}`))
			require.NoError(t, err)
			require.NotNil(t, upstream.lastReq)
			assertCodexSessionWire(t, codexSessionWireRequest{headers: upstream.lastReq.Header, body: upstream.lastBody}, testCodexSessionOverride, true)
		})
	}
}

// 原生池化和透传 WS 均逐轮更新 turn，配置保存不会在旧连接中途切换身份。
func TestCodexSessionFlowNativeWebSocket(t *testing.T) {
	for _, mode := range []string{OpenAIWSIngressModeCtxPool, OpenAIWSIngressModePassthrough} {
		t.Run(mode, func(t *testing.T) {
			svc, requests := newCodexSessionWireGateway(t)
			svc.cfg.Gateway.OpenAIWS.ModeRouterV2Enabled = true
			svc.cfg.Gateway.OpenAIWS.IngressModeDefault = OpenAIWSIngressModeCtxPool
			account := codexSessionFlowAccount()
			account.Extra["openai_oauth_responses_websockets_v2_mode"] = mode
			var saved atomic.Pointer[Account]
			saved.Store(account)
			serverErrors := make(chan error, 2)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := coderws.Accept(w, r, nil)
				if err != nil {
					serverErrors <- err
					return
				}
				defer func() { _ = conn.CloseNow() }()
				c, _ := gin.CreateTestContext(httptest.NewRecorder())
				c.Request = r
				_, first, err := conn.Read(r.Context())
				if err == nil {
					err = svc.ProxyResponsesWebSocketFromClient(r.Context(), c, conn, saved.Load(), "test-token", first, nil)
				}
				serverErrors <- err
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			connect := func() *coderws.Conn {
				headers := http.Header{"Session-Id": {"real-client-session"}}
				headers.Set("x-codex-turn-metadata", `{"session_id":"client-old","turn_id":"client-turn"}`)
				conn, _, err := coderws.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), &coderws.DialOptions{HTTPHeader: headers})
				require.NoError(t, err)
				t.Cleanup(func() { _ = conn.CloseNow() })
				return conn
			}
			turnNumber := 0
			sendTurn := func(conn *coderws.Conn) codexSessionWireRequest {
				turnNumber++
				// 明确提供逐帧身份，验证旧握手不会覆盖新的 turn 和压缩窗口。
				frame := fmt.Sprintf(`{"type":"response.create","model":"gpt-5.1","input":"hi","client_metadata":{"x-codex-turn-metadata":"{\"session_id\":\"real-client-session\",\"thread_id\":\"real-client-thread\",\"turn_id\":\"turn-%d\",\"root_turn_id\":\"turn-%d\",\"window_number\":%d}"}}`, turnNumber, turnNumber, turnNumber+2)
				require.NoError(t, conn.Write(ctx, coderws.MessageText, []byte(frame)))
				_, response, err := conn.Read(ctx)
				require.NoError(t, err)
				require.Equal(t, "response.completed", gjson.GetBytes(response, "type").String())
				return readCodexSessionWire(t, requests)
			}
			conn := connect()
			first := sendTurn(conn)
			assertCodexSessionWire(t, first, testCodexSessionOverride, true)
			next, err := accountWithCodexSessionDraft(account, CodexSessionOverride{Enabled: true, SessionID: "33333333-3333-4333-8333-333333333333"})
			require.NoError(t, err)
			saved.Store(next)
			second := sendTurn(conn)
			assertCodexSessionWire(t, second, testCodexSessionOverride, false)
			require.Equal(t, gjson.GetBytes(first.body, "client_metadata.thread_id").String()+":3", first.headers.Get("x-codex-window-id"))
			require.Equal(t, gjson.GetBytes(second.body, "client_metadata.thread_id").String()+":4", gjson.GetBytes(second.body, "client_metadata.x-codex-window-id").String())
			require.NotEqual(t, gjson.GetBytes(first.body, "client_metadata.turn_id").String(), gjson.GetBytes(second.body, "client_metadata.turn_id").String())
			_ = conn.Close(coderws.StatusNormalClosure, "done")
			// 新连接读取已保存的新快照，不复用旧会话的握手身份。
			reconnected := connect()
			assertCodexSessionWire(t, sendTurn(reconnected), "33333333-3333-4333-8333-333333333333", true)
			_ = reconnected.Close(coderws.StatusNormalClosure, "done")
			for i := 0; i < 2; i++ {
				select {
				case err := <-serverErrors:
					if err != nil {
						require.True(t, isOpenAIWSClientDisconnectError(err), err.Error())
					}
				case <-ctx.Done():
					t.Fatal("WS 测试未正常退出")
				}
			}
		})
	}
}

// 草稿不修改原账号；关闭覆盖不旋转 seed，普通编辑也不能覆盖专用配置。
func TestCodexSessionFlowDraftIsolationAndDisable(t *testing.T) {
	account := codexSessionFlowAccount()
	before, err := json.Marshal(account.Extra)
	require.NoError(t, err)
	draft, err := accountWithCodexSessionDraft(account, CodexSessionOverride{Enabled: false, SessionID: testCodexSessionOverride})
	require.NoError(t, err)
	require.Equal(t, resolveConvergedSessionID(testCodexFingerprintSeed), CodexSessionConfig(draft).EffectiveSessionID)
	after, err := json.Marshal(account.Extra)
	require.NoError(t, err)
	require.Equal(t, before, after)
	prepared := prepareCodexFingerprintExtraForUpdate(account, map[string]any{codexSessionOverrideEnabledKey: false})
	require.Equal(t, true, prepared[codexSessionOverrideEnabledKey])
	require.Equal(t, testCodexSessionOverride, prepared[codexSessionOverrideIDKey])
	require.Equal(t, testCodexFingerprintSeed, prepared[codexFingerprintSeedExtraKey])
}

// 母账号与影子共享收敛身份；故障转移到 off 账号必须清除上一轮暂存值。
func TestCodexSessionFlowShadowAndOffIsolation(t *testing.T) {
	parent := codexSessionFlowAccount()
	shadow := &Account{ID: 902, ParentAccountID: &parent.ID, Platform: PlatformOpenAI, Type: AccountTypeOAuth}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/responses", nil)
	c.Request.Header.Set("session-id", "client-session")
	c.Set(codexAccountIdentitySourceContextKey, parent)
	body := []byte(`{"type":"response.create","client_metadata":{"session_id":"client-session","thread_id":"client-thread"}}`)
	for _, mode := range []string{"session", "full", "device", "off"} {
		parent.Extra[codexFingerprintModeExtraKey] = mode
		updated, err := prepareCodexWSFingerprintTurn(c, shadow, body)
		require.NoError(t, err)
		ids := stagedCodexFingerprintIDs(c, shadow)
		switch mode {
		case "off":
			require.Nil(t, ids)
			require.Equal(t, body, updated)
		case "device":
			require.Equal(t, "client-session", gjson.GetBytes(updated, "client_metadata.session_id").String())
			require.Equal(t, "client-thread", gjson.GetBytes(updated, "client_metadata.thread_id").String())
		default:
			require.NotNil(t, ids)
			require.Equal(t, testCodexSessionOverride, gjson.GetBytes(updated, "client_metadata.session_id").String())
			if mode == "full" {
				require.Equal(t, ids.sessionID, ids.threadID)
			} else {
				require.NotEqual(t, ids.sessionID, ids.threadID)
			}
		}
	}
}
