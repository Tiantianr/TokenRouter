//go:build unit

package handler

import (
	"context"
	"github.com/TokenFlux/TokenRouter/internal/securityaudit"
	middleware "github.com/TokenFlux/TokenRouter/internal/server/middleware"
	"github.com/TokenFlux/TokenRouter/internal/service"
	coderws "github.com/coder/websocket"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	"net/http"
	"strings"
	"testing"
	"time"
)

// 首轮和后续轮次都必须真实调用引擎；后续命中不能继续写入上游。
func TestPromptAuditWebSocketSubsequentTurn(t *testing.T) {
	u := &historyHTTPUpstream{stream: true}
	h, r := newHistoryHTTPHandler(t, false, service.AccountTypeOAuth, u)
	h.cfg.Gateway.OpenAIWS.Enabled = true
	h.cfg.Gateway.OpenAIWS.OAuthEnabled = true
	h.cfg.Gateway.OpenAIWS.ResponsesWebsocketsV2 = true
	h.cfg.Gateway.OpenAIWS.ModeRouterV2Enabled = true
	h.cfg.Gateway.OpenAIWS.HTTPBridgeEnabled = true
	accounts := r.AccountRepository.(openAIResponsesFailoverAccountRepo)
	for i := range accounts.accounts {
		if accounts.accounts[i].Extra == nil {
			accounts.accounts[i].Extra = map[string]any{}
		}
		accounts.accounts[i].Extra["openai_oauth_responses_websockets_v2_mode"] = service.OpenAIWSIngressModeHTTPBridge
		accounts.accounts[i].Extra["openai_oauth_responses_websockets_v2_enabled"] = true
	}
	r.AccountRepository = accounts
	engine := &blockingPromptTestEngine{allowFirst: true}
	h.promptAudit = securityaudit.NewCoordinator(nil, engine)
	server := newOpenAIWSHandlerTestServer(t, h, middleware.AuthSubject{UserID: 100})
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := coderws.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/openai/v1/responses", &coderws.DialOptions{HTTPHeader: http.Header{"session_id": []string{"audit-ws"}}})
	require.NoError(t, err)
	defer func() { _ = conn.CloseNow() }()
	readTerminal := func() []byte {
		for {
			_, body, err := conn.Read(ctx)
			require.NoError(t, err)
			kind := gjson.GetBytes(body, "type").String()
			if kind == "error" || kind == "response.completed" {
				return body
			}
		}
	}
	require.NoError(t, conn.Write(ctx, coderws.MessageText, []byte(`{"type":"response.create","model":"gpt-5.1","input":"first"}`)))
	require.Equal(t, "response.completed", gjson.GetBytes(readTerminal(), "type").String())
	require.NoError(t, conn.Write(ctx, coderws.MessageText, []byte(`{"type":"response.create","model":"gpt-5.1","input":"second"}`)))
	require.Equal(t, securityaudit.ErrorCodeBlocked, gjson.GetBytes(readTerminal(), "error.code").String())
	require.Len(t, engine.requests, 2)
	require.Equal(t, []int64{1}, u.calls())
}
