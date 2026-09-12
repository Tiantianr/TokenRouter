//go:build unit

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TokenFlux/TokenRouter/internal/config"
	coderws "github.com/coder/websocket"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// 内存 CAS 返回独立快照，用于验证真实 Forward 而非只测试头部 helper。
type codexAccountTurnRepo struct {
	AccountRepository
	mu      sync.Mutex
	account *Account
}

func (r *codexAccountTurnRepo) GetByID(context.Context, int64) (*Account, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	copy := *r.account
	copy.Extra, copy.Credentials = maps.Clone(copy.Extra), maps.Clone(copy.Credentials)
	return &copy, nil
}

func (r *codexAccountTurnRepo) CompareAndSwapCodexSession(_ context.Context, expected *Account, updates map[string]any) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if storedCodexAccountTurn(r.account).Revision != storedCodexAccountTurn(expected).Revision || codexAccountTurnIdentity(r.account) != codexAccountTurnIdentity(expected) || !reflect.DeepEqual(r.account.Credentials, expected.Credentials) {
		return false, nil
	}
	copy := *r.account
	copy.Extra = maps.Clone(copy.Extra)
	maps.Copy(copy.Extra, updates)
	r.account = &copy
	return true, nil
}

func savedCodexTurnAccount() *Account {
	a := codexSessionFlowAccount()
	a.Extra[CodexAccountTurnExtraKey] = CodexAccountTurnConfiguration{
		Enabled: true, TurnID: "44444444-4444-4444-8444-444444444444", TurnState: "chosen-state", Revision: "v1", Identity: codexAccountTurnIdentity(a),
	}
	return a
}

func TestCodexAccountTurnForwardRotation(t *testing.T) {
	for _, passthrough := range []bool{false, true} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("passthrough=%v/stream=%v", passthrough, stream), func(t *testing.T) {
				account := savedCodexTurnAccount()
				account.Extra["openai_passthrough"] = passthrough
				repo := &codexAccountTurnRepo{account: account}
				upstream := &httpUpstreamRecorder{}
				svc := &OpenAIGatewayService{cfg: &config.Config{}, accountRepo: repo, httpUpstream: upstream, toolCorrector: NewCodexToolCorrector()}
				for round := 0; round < 2; round++ {
					upstream.resp = &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}, "X-Codex-Turn-State": {fmt.Sprintf("state-%d", round)}}, Body: io.NopCloser(strings.NewReader("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_fixed\",\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n"))}
					c, _ := newTurnStateTestContext(t, int64(round+1), fmt.Sprintf("client-%d", round))
					c.Request.Header.Set("turn-id", fmt.Sprintf("caller-turn-%d", round))
					c.Request.Header.Set(openAICodexTurnStateHeader, "caller-state")
					_, err := svc.Forward(context.Background(), c, account, []byte(fmt.Sprintf(`{"model":"gpt-5.4","stream":%v,"input":"hi","client_metadata":{"turn_id":"caller"}}`, stream)))
					require.NoError(t, err)
					require.Equal(t, storedCodexAccountTurn(account).TurnID, upstream.lastReq.Header.Get("turn-id"))
					require.Equal(t, upstream.lastReq.Header.Get("turn-id"), gjson.GetBytes(upstream.lastBody, "client_metadata.turn_id").String())
					wantState := "chosen-state"
					if round == 1 {
						wantState = "state-0"
					}
					require.Equal(t, wantState, upstream.lastReq.Header.Get(openAICodexTurnStateHeader))
					fresh, err := repo.GetByID(context.Background(), account.ID)
					require.NoError(t, err)
					require.Equal(t, fmt.Sprintf("state-%d", round), storedCodexAccountTurn(fresh).TurnState)
				}
			})
		}
	}
}

func TestCodexAccountTurnFailedResponsesRetainState(t *testing.T) {
	for _, payload := range []string{
		`{"type":"response.failed","response":{"status":"failed","error":{"message":"failed"}}}`,
		`{"type":"response.incomplete","response":{"status":"incomplete"}}`,
		`{"type":"response.output_text.delta","delta":"partial"}`,
		`{"type":"response.done","response":{"status":"failed","error":{"message":"failed"}}}`,
	} {
		for _, passthrough := range []bool{false, true} {
			t.Run(fmt.Sprint(passthrough)+payload, func(t *testing.T) {
				account := savedCodexTurnAccount()
				account.Extra["openai_passthrough"] = passthrough
				repo := &codexAccountTurnRepo{account: account}
				upstream := &httpUpstreamRecorder{resp: &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}, "X-Codex-Turn-State": {"failed-state"}}, Body: io.NopCloser(strings.NewReader("data: " + payload + "\n\n"))}}
				svc := &OpenAIGatewayService{cfg: &config.Config{}, accountRepo: repo, httpUpstream: upstream, toolCorrector: NewCodexToolCorrector()}
				c, _ := newTurnStateTestContext(t, 1, "client")
				_, _ = svc.Forward(context.Background(), c, account, []byte(`{"model":"gpt-5.4","stream":true,"input":"hi"}`))
				fresh, err := repo.GetByID(context.Background(), account.ID)
				require.NoError(t, err)
				require.Equal(t, "v1", storedCodexAccountTurn(fresh).Revision)
				require.Equal(t, "chosen-state", storedCodexAccountTurn(fresh).TurnState)
			})
		}
	}
}

func TestCodexAccountTurnSaveAndConcurrentUpdates(t *testing.T) {
	ctx := context.Background()
	account := codexSessionFlowAccount()
	repo := &codexAccountTurnRepo{account: account}
	admin := &adminServiceImpl{accountRepo: repo}
	value := CodexSessionOverride{Enabled: true, SessionID: testCodexSessionOverride, AccountTurn: &CodexAccountTurnConfiguration{Enabled: true, TurnID: "44444444-4444-4444-8444-444444444444", TurnState: "chosen-state", Identity: codexAccountTurnIdentity(account)}}
	saved, err := admin.SetCodexSessionOverride(ctx, account.ID, value)
	require.NoError(t, err)
	snapshot := &codexAccountTurnSnapshot{account: saved, value: storedCodexAccountTurn(saved)}
	require.NotEmpty(t, snapshot.value.Revision)
	svc := &OpenAIGatewayService{accountRepo: repo}
	var wg sync.WaitGroup
	for _, state := range []string{"new-a", "new-b"} {
		wg.Add(1)
		go func(state string) { defer wg.Done(); svc.rotateCodexAccountTurn(ctx, snapshot, state) }(state)
	}
	wg.Wait()
	fresh, err := repo.GetByID(ctx, account.ID)
	require.NoError(t, err)
	current := storedCodexAccountTurn(fresh)
	require.Contains(t, []string{"new-a", "new-b"}, current.TurnState)
	svc.rotateCodexAccountTurn(ctx, snapshot, "late")
	_, err = admin.SetCodexSessionOverride(ctx, account.ID, value)
	require.Error(t, err, "旧弹窗不能覆盖自动更新")
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	svc.rotateCodexAccountTurn(cancelled, &codexAccountTurnSnapshot{account: fresh, value: current}, "cancelled")
	disable := CodexSessionOverride{Enabled: true, SessionID: testCodexSessionOverride, AccountTurn: &CodexAccountTurnConfiguration{Revision: current.Revision}}
	disabled, err := admin.SetCodexSessionOverride(ctx, account.ID, disable)
	require.NoError(t, err)
	require.False(t, effectiveCodexAccountTurn(disabled).Enabled)
	require.Empty(t, storedCodexAccountTurn(disabled).TurnState)
	svc.rotateCodexAccountTurn(ctx, &codexAccountTurnSnapshot{account: fresh, value: current}, "late-after-disable")
	final, err := repo.GetByID(ctx, account.ID)
	require.NoError(t, err)
	require.False(t, effectiveCodexAccountTurn(final).Enabled)
}

func TestCodexAccountTurnIdentityAndDraftValidation(t *testing.T) {
	account := savedCodexTurnAccount()
	saved := storedCodexAccountTurn(account)
	for _, value := range []string{"\rstate", "state\n", "state\x00", strings.Repeat("s", 8193)} {
		require.Error(t, validateCodexTurnStateTestOverride(account, CodexTurnStateTestOverride{TurnID: saved.TurnID, TurnState: value, Identity: saved.Identity}))
	}
	account.Credentials["access_token"] = "refreshed-token"
	require.True(t, effectiveCodexAccountTurn(account).Enabled, "正常 token 刷新不改变稳定身份")
	account.Extra[codexSessionOverrideIDKey] = "55555555-5555-4555-8555-555555555555"
	require.False(t, effectiveCodexAccountTurn(account).Enabled)
	InvalidateChangedCodexAccountTurn(account, account.Extra)
	require.Empty(t, storedCodexAccountTurn(account).TurnState)
}

func TestCodexAccountTurnDraftFailureNeverCaptures(t *testing.T) {
	for _, body := range []string{"data: {\"type\":\"response.failed\"}\n\n", "data: {\"type\":\"response.done\",\"response\":{\"status\":\"failed\"}}\n\n", "data: [DONE]\n\n", ""} {
		c, recorder := newTestContext()
		svc := &AccountTestService{}
		require.Error(t, svc.processOpenAIStreamWithTurnState(c, strings.NewReader(body), "turn", "state", "identity"))
		require.NotContains(t, recorder.Body.String(), `"type":"codex_turn_state"`)
	}
}

func TestCodexAccountTurnCaptureThenSaveWithSessionDraft(t *testing.T) {
	account := codexSessionFlowAccount()
	repo := &codexAccountTurnRepo{account: account}
	upstream := &queuedHTTPUpstream{}
	resp := newJSONResponse(200, "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n")
	resp.Header.Set(openAICodexTurnStateHeader, "selected-state")
	upstream.responses = append(upstream.responses, resp)
	probe := &AccountTestService{accountRepo: repo, httpUpstream: upstream}
	session := CodexSessionOverride{Enabled: true, SessionID: "55555555-5555-4555-8555-555555555555"}
	turnID := "44444444-4444-4444-8444-444444444444"
	c, recorder := newTestContext()
	c.Set(CodexSessionTestOverrideKey, session)
	c.Set(CodexTurnStateTestOverrideKey, CodexTurnStateTestOverride{TurnID: turnID})
	require.NoError(t, probe.TestAccountConnection(c, account.ID, "gpt-5.4", "hi", AccountTestModeDefault, AccountTestTypeText))
	var captured TestEvent
	for _, line := range strings.Split(recorder.Body.String(), "\n") {
		payload := strings.TrimPrefix(line, "data: ")
		if gjson.Get(payload, "type").String() == "codex_turn_state" {
			require.NoError(t, json.Unmarshal([]byte(payload), &captured))
		}
	}
	require.Equal(t, turnID, captured.TurnID)
	require.Equal(t, "selected-state", captured.TurnState)
	require.NotEmpty(t, captured.Identity)
	fresh, err := repo.GetByID(context.Background(), account.ID)
	require.NoError(t, err)
	require.Empty(t, storedCodexAccountTurn(fresh).Revision, "测试不自动保存")
	session.AccountTurn = &CodexAccountTurnConfiguration{Enabled: true, TurnID: captured.TurnID, TurnState: captured.TurnState, Identity: captured.Identity}
	admin := &adminServiceImpl{accountRepo: repo}
	saved, err := admin.SetCodexSessionOverride(context.Background(), account.ID, session)
	require.NoError(t, err)
	require.Equal(t, session.SessionID, configuredCodexSessionID(saved))
	require.True(t, effectiveCodexAccountTurn(saved).Enabled)
	require.Equal(t, turnID, CodexSessionConfig(saved).AccountTurn.TurnID)
}

// HTTP 下游写失败但上游仍被完整读取时，不能把状态升级为成功。
type codexTurnFailWriter struct{ gin.ResponseWriter }

func (w codexTurnFailWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestCodexAccountTurnResponseObserver(t *testing.T) {
	for _, tc := range []struct {
		name, contentType, body string
		writeFails, success     bool
	}{
		{"SSE成功", "text/event-stream", "data: {\"type\":\"response.completed\"}\n\n", false, true},
		{"先错误后终态", "text/event-stream", "data: {\"type\":\"error\"}\n\ndata: {\"type\":\"response.completed\"}\n\n", false, false},
		{"非对象错误", "text/event-stream", "data: {\"type\":\"response.completed\",\"response\":{\"error\":\"failed\"}}\n\n", false, false},
		{"JSON成功", "application/json", `{"status":"completed","error":null}`, false, true},
		{"JSON仅200", "application/json", `{"output":[]}`, false, false},
		{"客户端写失败", "text/event-stream", "data: {\"type\":\"response.completed\"}\n\n", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newTurnStateTestContext(t, 1, "client")
			if tc.writeFails {
				c.Writer = codexTurnFailWriter{c.Writer}
			}
			originalWriter := c.Writer
			resp := &http.Response{Header: http.Header{"Content-Type": {tc.contentType}, "X-Codex-Turn-State": {"new-state"}}, Body: io.NopCloser(strings.NewReader(tc.body))}
			o := observeCodexTurnResponse(resp, &codexAccountTurnSnapshot{}, c)
			data, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			_, _ = c.Writer.Write(data)
			require.Equal(t, tc.success, o.successful())
			o.restore(c)
			require.Equal(t, originalWriter, c.Writer)
		})
	}
}

func TestCodexAccountTurnNativeWebSocket(t *testing.T) {
	for _, mode := range []string{OpenAIWSIngressModeCtxPool, OpenAIWSIngressModePassthrough} {
		t.Run(mode, func(t *testing.T) {
			svc, requests := newCodexSessionWireGateway(t, http.Header{"X-Codex-Turn-State": {"ws-new-state"}})
			svc.cfg.Gateway.OpenAIWS.ModeRouterV2Enabled = true
			account := savedCodexTurnAccount()
			account.Extra["openai_oauth_responses_websockets_v2_mode"] = mode
			repo := &codexAccountTurnRepo{account: account}
			svc.accountRepo = repo
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := coderws.Accept(w, r, nil)
				if err != nil {
					return
				}
				defer func() { _ = conn.CloseNow() }()
				c, _ := gin.CreateTestContext(httptest.NewRecorder())
				c.Request = r
				_, first, err := conn.Read(r.Context())
				if err == nil {
					_ = svc.ProxyResponsesWebSocketFromClient(r.Context(), c, conn, account, "test-token", first, nil)
				}
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, _, err := coderws.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/v1/responses", &coderws.DialOptions{HTTPHeader: http.Header{"Session-Id": {"client-session"}}})
			require.NoError(t, err)
			defer func() { _ = conn.CloseNow() }()
			for i := 0; i < 2; i++ {
				payload := fmt.Sprintf(`{"type":"response.create","model":"gpt-5.1","input":"hi","client_metadata":{"turn_id":"client-turn-%d"}}`, i)
				require.NoError(t, conn.Write(ctx, coderws.MessageText, []byte(payload)))
				_, _, err := conn.Read(ctx)
				require.NoError(t, err)
				wire := readCodexSessionWire(t, requests)
				require.Equal(t, storedCodexAccountTurn(account).TurnID, gjson.GetBytes(wire.body, "client_metadata.turn_id").String())
				require.Equal(t, storedCodexAccountTurn(account).TurnID, wire.headers.Get("turn-id"))
				if i == 0 {
					require.Equal(t, "chosen-state", wire.headers.Get(openAICodexTurnStateHeader))
				}
			}
			require.Eventually(t, func() bool {
				fresh, err := repo.GetByID(ctx, account.ID)
				return err == nil && storedCodexAccountTurn(fresh).TurnState == "ws-new-state"
			}, time.Second, 10*time.Millisecond)
		})
	}
}
