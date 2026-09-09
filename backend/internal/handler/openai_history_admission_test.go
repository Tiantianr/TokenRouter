//go:build unit

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TokenFlux/TokenRouter/internal/pkg/tlsfingerprint"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	middleware "github.com/TokenFlux/TokenRouter/internal/server/middleware"
	"github.com/TokenFlux/TokenRouter/internal/service"
	"github.com/TokenFlux/TokenRouter/internal/testutil"
	coderws "github.com/coder/websocket"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// 通过真实handler和模拟上游检查请求顺序，不将调用次数等价于源码包含某函数。
type openAIHistoryHandlerRepository struct {
	service.AccountRepository
	mu              sync.Mutex
	bindings        map[string]service.OpenAIConversationBinding
	lookups, writes int
	failWrites      string
	cache           service.GatewayCache
}

func withOpenAIHistoryTestRepository(repo service.AccountRepository) service.AccountRepository {
	if repo == nil {
		return nil
	}
	if _, ok := repo.(service.OpenAIConversationBindingRepository); ok {
		return repo
	}
	return &openAIHistoryHandlerRepository{AccountRepository: repo, bindings: map[string]service.OpenAIConversationBinding{}}
}

func handlerHistoryKey(user, group int64, kind, key string) string {
	return fmt.Sprintf("%d:%d:%s:%s", user, group, kind, key)
}
func (r *openAIHistoryHandlerRepository) GetOpenAIConversationBinding(_ context.Context, user, group int64, kind, key string) (*service.OpenAIConversationBinding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookups++
	b, ok := r.bindings[handlerHistoryKey(user, group, kind, key)]
	if !ok {
		return nil, nil
	}
	return &b, nil
}
func (r *openAIHistoryHandlerRepository) SaveOpenAIConversationBinding(_ context.Context, b *service.OpenAIConversationBinding, revision int64) (*service.OpenAIConversationBinding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writes++
	if b.Type == r.failWrites {
		return nil, errors.New("storage offline")
	}
	key := handlerHistoryKey(b.UserID, b.ScopeGroupID, b.Type, b.Key)
	old, exists := r.bindings[key]
	sessionCAS := b.Type == "session" && old.Revision == revision
	sameOwner := old.AccountID == b.AccountID && old.CredentialOwnerAccountID == b.CredentialOwnerAccountID && old.OAuthAccountID == b.OAuthAccountID && old.OAuthUserID == b.OAuthUserID
	if exists && !sessionCAS && !sameOwner {
		return nil, service.ErrOpenAIHistoryConflict
	}
	if b.Type == "session" && b.Confirmed && (!exists || !sessionCAS || !sameOwner) {
		return nil, service.ErrOpenAIHistoryConflict
	}
	saved := *b
	saved.Revision, saved.Valid = old.Revision+1, true
	if sameOwner {
		saved.Revision = old.Revision
		saved.Confirmed = saved.Confirmed || old.Confirmed
	}
	r.bindings[key] = saved
	return &saved, nil
}

type historyHTTPUpstream struct {
	service.HTTPUpstream
	mu       sync.Mutex
	accounts []int64
	stream   bool
}

func (u *historyHTTPUpstream) DoWithTLS(req *http.Request, proxy string, accountID int64, concurrency int, _ *tlsfingerprint.Profile) (*http.Response, error) {
	return u.Do(req, proxy, accountID, concurrency)
}

func (u *historyHTTPUpstream) Do(_ *http.Request, _ string, accountID int64, _ int) (*http.Response, error) {
	u.mu.Lock()
	u.accounts = append(u.accounts, accountID)
	count := len(u.accounts)
	u.mu.Unlock()
	id := fmt.Sprintf("resp_history_%d", count)
	body := fmt.Sprintf(`{"id":%q,"object":"response","status":"completed","model":"gpt-5.1","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":1,"output_tokens":1}}`, id)
	contentType := "application/json"
	if u.stream {
		contentType = "text/event-stream"
		body = fmt.Sprintf("data: {\"type\":\"response.created\",\"response\":{\"id\":%q,\"status\":\"in_progress\"}}\n\ndata: {\"type\":\"response.completed\",\"response\":%s}\n\n", id, body)
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{contentType}}, Body: io.NopCloser(strings.NewReader(body))}, nil
}
func (u *historyHTTPUpstream) calls() []int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]int64(nil), u.accounts...)
}

func newHistoryHTTPHandler(t *testing.T, loose bool, kind string, u *historyHTTPUpstream, caches ...service.GatewayCache) (*OpenAIGatewayHandler, *openAIHistoryHandlerRepository) {
	t.Helper()
	accounts := []service.Account{
		{ID: 1, Platform: service.PlatformOpenAI, Type: kind, Status: service.StatusActive, Schedulable: true, Priority: 0, GroupIDs: []int64{3131}, Credentials: map[string]any{"access_token": "test-a", "api_key": "test-a", "chatgpt_account_id": "owner-a"}, Extra: map[string]any{service.OpenAIOAuthRejectExternalHistoryKey: true}},
		{ID: 2, Platform: service.PlatformOpenAI, Type: kind, Status: service.StatusActive, Schedulable: true, Priority: 1, GroupIDs: []int64{3131}, Credentials: map[string]any{"access_token": "test-b", "api_key": "test-b", "chatgpt_account_id": "owner-b"}, Extra: map[string]any{service.OpenAIOAuthRejectExternalHistoryKey: !loose}},
	}
	r, ok := withOpenAIHistoryTestRepository(openAIResponsesFailoverAccountRepo{accounts: accounts}).(*openAIHistoryHandlerRepository)
	require.True(t, ok)
	if len(caches) > 0 {
		r.cache = caches[0]
	}
	return newOpenAIResponsesFailoverTestHandler(t, u, r), r
}
func historyHTTPContext(t *testing.T, body string) (*gin.Context, *httptest.ResponseRecorder) {
	c, w := newOpenAIResponsesFailoverTestContext(t, nil)
	c.Request.Body = io.NopCloser(strings.NewReader(body))
	c.Request.ContentLength = int64(len(body))
	c.Request.Header.Set("session_id", "history-http")
	key, _ := middleware.GetAPIKeyFromContext(c)
	key.Group.AllowedClientProtocols = []service.GroupClientProtocol{service.GroupClientProtocolOpenAIResponses, service.GroupClientProtocolOpenAIChatCompletions, service.GroupClientProtocolAnthropicMessages}
	return c, w
}

func TestOpenAIHistoryHTTPRouting(t *testing.T) {
	for _, tc := range []struct {
		name, body, kind string
		loose            bool
		status           int
		ids              []int64
	}{
		{"fresh", `{"model":"gpt-5.1","input":"hello"}`, service.AccountTypeOAuth, false, 200, []int64{1}},
		{"foreign", `{"model":"gpt-5.1","input":[{"role":"assistant","content":"old"},{"role":"user","content":"next"}]}`, service.AccountTypeOAuth, false, 400, nil},
		{"mixed", `{"model":"gpt-5.1","input":[{"role":"assistant","content":"old"},{"role":"user","content":"next"}]}`, service.AccountTypeOAuth, true, 200, []int64{2}},
		{"api_key", `{"model":"gpt-5.1","input":[{"role":"assistant","content":"old"},{"role":"user","content":"next"}]}`, service.AccountTypeAPIKey, false, 200, []int64{1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := &historyHTTPUpstream{}
			h, _ := newHistoryHTTPHandler(t, tc.loose, tc.kind, u)
			c, w := historyHTTPContext(t, tc.body)
			h.Responses(c)
			require.Equal(t, tc.status, w.Code, w.Body.String())
			require.Equal(t, tc.ids, u.calls())
		})
	}
}

func TestOpenAIHistoryGroupIsolationComposition(t *testing.T) {
	for _, groupIsolated := range []bool{false, true} {
		for _, accountStrict := range []bool{false, true} {
			t.Run(fmt.Sprintf("group_%t/account_%t", groupIsolated, accountStrict), func(t *testing.T) {
				cache := testutil.NewRedisGatewayCache(t)
				u := &historyHTTPUpstream{}
				h, r := newHistoryHTTPHandler(t, false, service.AccountTypeOAuth, u, cache)
				accounts, ok := r.AccountRepository.(openAIResponsesFailoverAccountRepo)
				require.True(t, ok)
				for i := range accounts.accounts {
					accounts.accounts[i].Extra = map[string]any{}
					if accountStrict {
						accounts.accounts[i].Extra[service.OpenAIOAuthRejectExternalHistoryKey] = true
					}
				}
				r.AccountRepository = accounts
				body := `{"model":"gpt-5.1","input":[{"role":"assistant","content":"external"},{"role":"user","content":"next"}]}`
				c, w := historyHTTPContext(t, body)
				key, _ := middleware.GetAPIKeyFromContext(c)
				key.Group.SessionIsolationEnabled = groupIsolated
				hash := h.gatewayService.GenerateExplicitSessionHash(c, []byte(body))
				_, err := cache.SetSessionOwnerGroupID(c.Request.Context(), 100, service.SessionIsolationSourceOpenAI, hash, 99, time.Hour)
				require.NoError(t, err)
				h.Responses(c)
				switch {
				case groupIsolated:
					require.Equal(t, 403, w.Code, w.Body.String())
					require.Contains(t, w.Body.String(), service.SessionIsolationConflictMessage)
					require.Zero(t, r.writes)
					require.Empty(t, u.calls())
				case accountStrict:
					require.Equal(t, 400, w.Code, w.Body.String())
					require.Zero(t, r.writes)
					require.Empty(t, u.calls())
				default:
					require.Equal(t, 200, w.Code, w.Body.String())
					require.Len(t, u.calls(), 1)
				}
			})
		}
	}
}

func TestOpenAIHistoryHTTPCompletionConfirmsAllOutputPaths(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, protocol := range []string{"responses", "passthrough", "chat", "messages"} {
			t.Run(fmt.Sprintf("%s/stream_%t", protocol, stream), func(t *testing.T) {
				u := &historyHTTPUpstream{stream: stream || protocol != "responses"}
				h, r := newHistoryHTTPHandler(t, false, service.AccountTypeOAuth, u)
				body := fmt.Sprintf(`{"model":"gpt-5.1","stream":%t,"input":"hello"}`, stream)
				path := "/v1/responses"
				handle := (*OpenAIGatewayHandler).Responses
				if protocol == "passthrough" {
					accounts, ok := r.AccountRepository.(openAIResponsesFailoverAccountRepo)
					require.True(t, ok)
					for i := range accounts.accounts {
						accounts.accounts[i].Extra["openai_passthrough"] = true
					}
					r.AccountRepository = accounts
				}
				if protocol == "chat" || protocol == "messages" {
					body = fmt.Sprintf(`{"model":"gpt-5.1","stream":%t,"max_tokens":64,"messages":[{"role":"user","content":"hello"}]}`, stream)
					if protocol == "chat" {
						path = "/v1/chat/completions"
						handle = (*OpenAIGatewayHandler).ChatCompletions
					} else {
						path = "/v1/messages"
						handle = (*OpenAIGatewayHandler).Messages
					}
				}
				c, w := historyHTTPContext(t, body)
				c.Request.URL.Path = path
				handle(h, c)
				require.Equal(t, 200, w.Code, w.Body.String())
				require.NotEmpty(t, r.bindings)
				for _, binding := range r.bindings {
					require.True(t, binding.Confirmed, "完成后才有历史授权")
				}
			})
		}
	}
}

func TestOpenAIHistoryModerationPrecedesOwnership(t *testing.T) {
	for _, kind := range []string{service.AccountTypeOAuth, service.AccountTypeAPIKey} {
		t.Run(kind, func(t *testing.T) {
			u := &historyHTTPUpstream{}
			h, r := newHistoryHTTPHandler(t, true, kind, u)
			cfg := &service.ContentModerationConfig{Enabled: true, Mode: service.ContentModerationModePreBlock, AllGroups: true, SampleRate: 100, BlockedKeywords: []string{"blocked-history-sample"}, BlockMessage: "blocked"}
			body, err := json.Marshal(cfg)
			require.NoError(t, err)
			settings := &contentModerationHandlerSettingRepo{values: map[string]string{service.SettingKeyRiskControlEnabled: "true", service.SettingKeyContentModerationConfig: string(body)}}
			h.contentModerationService = service.NewContentModerationService(settings, &contentModerationHandlerTestRepo{}, nil, nil, nil, nil, nil)
			for _, endpoint := range []struct {
				path, body string
				handle     func(*OpenAIGatewayHandler, *gin.Context)
			}{
				{"/v1/responses", `{"model":"gpt-5.1","input":[{"role":"assistant","content":"old"},{"role":"user","content":"blocked-history-sample"}]}`, (*OpenAIGatewayHandler).Responses},
				{"/v1/responses", `{"model":"gpt-5.1","previous_response_id":"resp_unknown","input":"blocked-history-sample"}`, (*OpenAIGatewayHandler).Responses},
				{"/v1/responses/input_tokens", `{"model":"gpt-5.1","input":"blocked-history-sample"}`, (*OpenAIGatewayHandler).ResponsesInputTokens},
				{"/v1/messages/count_tokens", `{"model":"gpt-5.1","messages":[{"role":"user","content":"blocked-history-sample"}]}`, (*OpenAIGatewayHandler).CountTokens},
			} {
				c, w := historyHTTPContext(t, endpoint.body)
				c.Request.URL.Path = endpoint.path
				endpoint.handle(h, c)
				require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
				require.Zero(t, r.lookups)
				require.Zero(t, r.writes)
				require.Empty(t, u.calls())
			}
		})
	}
}

func TestOpenAIHistoryHTTPPersistenceBeforeResponse(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			u := &historyHTTPUpstream{stream: stream}
			h, r := newHistoryHTTPHandler(t, false, service.AccountTypeOAuth, u)
			r.failWrites = "response"
			c, w := historyHTTPContext(t, fmt.Sprintf(`{"model":"gpt-5.1","input":"hello","stream":%t}`, stream))
			h.Responses(c)
			require.NotContains(t, w.Body.String(), "resp_history_1")
			require.Contains(t, w.Body.String(), "conversation_ownership_unavailable")
			require.Len(t, u.calls(), 1)
		})
	}
}

func TestOpenAIHistoryOpsKeepsLocalAttribution(t *testing.T) {
	c, _ := historyHTTPContext(t, `{"model":"gpt-5.1","input":"next"}`)
	c.Set(service.OpsUpstreamStatusCodeKey, http.StatusTooManyRequests)
	message := service.ErrOpenAIExternalHistory.Error()
	_, _, _, source := classifyOpsErrorLog(c, "invalid_request_error", message, "external_history_not_allowed", 400)
	require.NotEqual(t, "gateway", source, "上游自报相同文案不能伪造本地策略标记")
	markOpenAIHistoryOpsError(c, 400, "invalid_request_error", "external_history_not_allowed", message)
	phase, business, owner, source := classifyOpsErrorLog(c, "invalid_request_error", message, "external_history_not_allowed", 400)
	require.Equal(t, "routing", phase)
	require.True(t, business)
	require.Equal(t, "platform", owner)
	require.Equal(t, "gateway", source)
	accountID := int64(99)
	entry := &service.OpsInsertErrorLogInput{AccountID: &accountID, UpstreamEndpoint: "old-attempt", ErrorMessage: message}
	suppressOpsUpstreamAttributionForLocalModelConfiguration(c, entry)
	require.Nil(t, entry.AccountID)
	require.Empty(t, entry.UpstreamEndpoint)
	streamErrors := service.GetOpsStreamErrors(c)
	require.Len(t, streamErrors, 1)
	require.Equal(t, 400, streamErrors[0].IntendedStatus)
	require.Equal(t, "external_history_not_allowed", streamErrors[0].Code)
}

// 归属写入取消必须可见，且不得覆盖真正的超时或数据库故障。
func TestOpenAIHistoryCanceledErrorRecorded(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			setupOpsErrorLogTestQueue(t, 4)
			c, w := historyHTTPContext(t, `{"model":"gpt-5.1","input":"hello"}`)
			if stream {
				c.Writer.WriteHeaderNow()
			}
			c.Set(service.OpsUpstreamStatusCodeKey, 502)
			err := fmt.Errorf("%w: save binding: %w", service.ErrOpenAIHistoryUnavailable, context.Canceled)
			h := &OpenAIGatewayHandler{}
			require.True(t, h.handleOpenAIHistoryError(c, err, false, stream))
			require.Contains(t, w.Body.String(), "request_canceled")
			require.NotContains(t, w.Body.String(), "conversation_ownership_unavailable")
			if !stream {
				require.Equal(t, 499, w.Code)
			}
			ops := service.NewOpsService(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
			logOpsStreamError(c, ops, w.Code)
			require.Equal(t, int64(1), OpsErrorLogQueueLength())
			entry := (<-opsErrorLogQueue).entry
			require.Equal(t, 499, entry.StatusCode)
			require.Equal(t, "request_canceled", entry.ErrorType)
			require.Equal(t, "request", entry.ErrorPhase)
			require.Equal(t, "client", entry.ErrorOwner)
			require.True(t, entry.IsBusinessLimited)
			require.Equal(t, "P3", entry.Severity)
		})
	}
	for _, cause := range []error{context.DeadlineExceeded, errors.New("database unavailable")} {
		status, _, code, _, ok := openAIHistoryErrorDetails(fmt.Errorf("%w: %w", service.ErrOpenAIHistoryUnavailable, cause))
		require.True(t, ok)
		require.Equal(t, 503, status)
		require.Equal(t, "conversation_ownership_unavailable", code)
	}
}

func TestOpenAIHistoryCompatibilityAndCount(t *testing.T) {
	for _, tc := range []struct {
		path, body string
		handle     func(*OpenAIGatewayHandler, *gin.Context)
	}{
		{"/v1/responses/compact", `{"model":"gpt-5.1","input":[{"role":"assistant","content":"old"},{"role":"user","content":"next"}]}`, (*OpenAIGatewayHandler).Responses},
		{"/v1/chat/completions", `{"model":"gpt-5.1","messages":[{"role":"assistant","content":"old"},{"role":"user","content":"next"}]}`, (*OpenAIGatewayHandler).ChatCompletions},
		{"/v1/messages", `{"model":"gpt-5.1","max_tokens":64,"messages":[{"role":"assistant","content":"old"},{"role":"user","content":"next"}]}`, (*OpenAIGatewayHandler).Messages},
		{"/v1/responses/input_tokens", `{"model":"gpt-5.1","input":[{"role":"assistant","content":"old"},{"role":"user","content":"next"}]}`, (*OpenAIGatewayHandler).ResponsesInputTokens},
		{"/v1/messages/count_tokens", `{"model":"gpt-5.1","messages":[{"role":"assistant","content":"old"},{"role":"user","content":"next"}]}`, (*OpenAIGatewayHandler).CountTokens},
	} {
		t.Run(tc.path, func(t *testing.T) {
			u := &historyHTTPUpstream{}
			h, r := newHistoryHTTPHandler(t, false, service.AccountTypeOAuth, u)
			c, w := historyHTTPContext(t, tc.body)
			c.Request.URL.Path = tc.path
			key, _ := middleware.GetAPIKeyFromContext(c)
			key.Group.AllowMessagesDispatch = true
			tc.handle(h, c)
			require.Equal(t, 400, w.Code, w.Body.String())
			require.Contains(t, w.Body.String(), service.ErrOpenAIExternalHistory.Error())
			require.Empty(t, u.calls())
			require.Zero(t, r.writes)
		})
	}
}

func TestOpenAIHistoryWebSocketTurns(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		firstHistory, unknown bool
	}{{"foreign_first", true, false}, {"unknown_later", false, true}, {"owned_later", false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			u := &historyHTTPUpstream{stream: true}
			h, r := newHistoryHTTPHandler(t, false, service.AccountTypeOAuth, u)
			h.cfg.Gateway.OpenAIWS.Enabled = true
			h.cfg.Gateway.OpenAIWS.OAuthEnabled = true
			h.cfg.Gateway.OpenAIWS.ResponsesWebsocketsV2 = true
			h.cfg.Gateway.OpenAIWS.ModeRouterV2Enabled = true
			h.cfg.Gateway.OpenAIWS.HTTPBridgeEnabled = true
			accounts, ok := r.AccountRepository.(openAIResponsesFailoverAccountRepo)
			require.True(t, ok)
			for i := range accounts.accounts {
				if accounts.accounts[i].Extra == nil {
					accounts.accounts[i].Extra = map[string]any{}
				}
				accounts.accounts[i].Extra["openai_oauth_responses_websockets_v2_mode"] = service.OpenAIWSIngressModeHTTPBridge
				accounts.accounts[i].Extra["openai_oauth_responses_websockets_v2_enabled"] = true
			}
			r.AccountRepository = accounts
			server := newOpenAIWSHandlerTestServer(t, h, middleware.AuthSubject{UserID: 100})
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, _, err := coderws.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/openai/v1/responses", &coderws.DialOptions{HTTPHeader: http.Header{"session_id": []string{"history-ws"}}})
			require.NoError(t, err)
			defer func() { _ = conn.CloseNow() }()
			first := `{"type":"response.create","model":"gpt-5.1","input":"hello"}`
			if tc.firstHistory {
				first = `{"type":"response.create","model":"gpt-5.1","input":[{"role":"assistant","content":"old"},{"role":"user","content":"next"}]}`
			}
			readTerminal := func() []byte {
				for {
					_, frame, err := conn.Read(ctx)
					require.NoError(t, err)
					kind := gjson.GetBytes(frame, "type").String()
					if kind == "response.completed" || kind == "error" {
						return frame
					}
				}
			}
			require.NoError(t, conn.Write(ctx, coderws.MessageText, []byte(first)))
			frame := readTerminal()
			if tc.firstHistory {
				require.Equal(t, "external_history_not_allowed", gjson.GetBytes(frame, "error.code").String())
				require.Empty(t, u.calls())
				return
			}
			require.Equal(t, "resp_history_1", gjson.GetBytes(frame, "response.id").String())
			previous := "resp_history_1"
			if tc.unknown {
				previous = "resp_unknown"
			}
			require.NoError(t, conn.Write(ctx, coderws.MessageText, []byte(fmt.Sprintf(`{"type":"response.create","model":"gpt-5.1","input":"next","previous_response_id":%q}`, previous))))
			frame = readTerminal()
			if tc.unknown {
				require.Equal(t, "conversation_reconnect_required", gjson.GetBytes(frame, "error.code").String())
				require.Equal(t, []int64{1}, u.calls())
			} else {
				require.Equal(t, "resp_history_2", gjson.GetBytes(frame, "response.id").String())
				require.Equal(t, []int64{1, 1}, u.calls())
			}
		})
	}
}

func TestOpenAIHistoryWSGroupIsolationBeforeReservation(t *testing.T) {
	for _, later := range []bool{false, true} {
		t.Run(fmt.Sprintf("later_%t", later), func(t *testing.T) {
			cache := testutil.NewRedisGatewayCache(t)
			u := &historyHTTPUpstream{stream: true}
			h, r := newHistoryHTTPHandler(t, false, service.AccountTypeOAuth, u, cache)
			h.cfg.Gateway.OpenAIWS.Enabled = true
			h.cfg.Gateway.OpenAIWS.OAuthEnabled = true
			h.cfg.Gateway.OpenAIWS.ResponsesWebsocketsV2 = true
			h.cfg.Gateway.OpenAIWS.ModeRouterV2Enabled = true
			h.cfg.Gateway.OpenAIWS.HTTPBridgeEnabled = true
			accounts, ok := r.AccountRepository.(openAIResponsesFailoverAccountRepo)
			require.True(t, ok)
			for i := range accounts.accounts {
				accounts.accounts[i].Extra = map[string]any{"openai_oauth_responses_websockets_v2_mode": service.OpenAIWSIngressModeHTTPBridge, "openai_oauth_responses_websockets_v2_enabled": true}
			}
			r.AccountRepository = accounts
			groupID := int64(3131)
			key := &service.APIKey{ID: 99, UserID: 100, GroupID: &groupID, User: &service.User{ID: 100}, Group: &service.Group{ID: groupID, Platform: service.PlatformOpenAI, SessionIsolationEnabled: true, AllowedClientProtocols: []service.GroupClientProtocol{service.GroupClientProtocolOpenAIResponses}}}
			foreign := `{"type":"response.create","model":"gpt-5.1","prompt_cache_key":"foreign-group","input":"next"}`
			probe, _ := historyHTTPContext(t, foreign)
			probe.Request.Header.Del("session_id")
			hash := h.gatewayService.GenerateExplicitSessionHash(probe, []byte(foreign))
			_, err := cache.SetSessionOwnerGroupID(context.Background(), 100, service.SessionIsolationSourceOpenAI, hash, 99, time.Hour)
			require.NoError(t, err)
			done := make(chan struct{})
			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Set(string(middleware.ContextKeyAPIKey), key)
				c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 100})
				c.Next()
			})
			router.GET("/openai/v1/responses", func(c *gin.Context) { defer close(done); h.ResponsesWebSocket(c) })
			server := httptest.NewServer(router)
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, _, err := coderws.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/openai/v1/responses", nil)
			require.NoError(t, err)
			defer func() { _ = conn.CloseNow() }()
			readTerminal := func() []byte {
				for {
					_, frame, err := conn.Read(ctx)
					require.NoError(t, err)
					kind := gjson.GetBytes(frame, "type").String()
					if kind == "error" || kind == "response.completed" {
						return frame
					}
				}
			}
			writesBefore := 0
			if later {
				require.NoError(t, conn.Write(ctx, coderws.MessageText, []byte(`{"type":"response.create","model":"gpt-5.1","prompt_cache_key":"current-group","input":"hello"}`)))
				require.Equal(t, "response.completed", gjson.GetBytes(readTerminal(), "type").String())
				r.mu.Lock()
				writesBefore = r.writes
				r.mu.Unlock()
			}
			require.NoError(t, conn.Write(ctx, coderws.MessageText, []byte(foreign)))
			frame := readTerminal()
			require.Contains(t, string(frame), service.SessionIsolationConflictMessage)
			_ = conn.CloseNow()
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			r.mu.Lock()
			writesAfter := r.writes
			r.mu.Unlock()
			require.Equal(t, writesBefore, writesAfter, "分组拒绝前不得预占账号")
			if later {
				require.Len(t, u.calls(), 1)
			} else {
				require.Empty(t, u.calls())
			}
		})
	}
}
