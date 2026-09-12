//go:build unit

package service

import (
	"context"
	"io"
	"maps"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// 专用保存接口使用独立仓储快照，模拟数据库原子合并，不修改运行中请求持有的账号。
type codexSessionSaveRepo struct {
	AccountRepository
	account *Account
}

func (r *codexSessionSaveRepo) GetByID(context.Context, int64) (*Account, error) {
	copy := *r.account
	copy.Extra = maps.Clone(r.account.Extra)
	return &copy, nil
}

func (r *codexSessionSaveRepo) UpdateExtra(_ context.Context, _ int64, updates map[string]any) error {
	copy := *r.account
	copy.Extra = maps.Clone(r.account.Extra)
	maps.Copy(copy.Extra, updates)
	r.account = &copy
	return nil
}

// 在测试入口使用草稿、专用接口保存后重测、禁用后再测，核对真正的出站请求。
func TestAccountTestCodexSessionSaveAndDraftUseSameThread(t *testing.T) {
	for _, mode := range []string{"session", "full"} {
		t.Run(mode, func(t *testing.T) {
			account := codexSessionFlowAccount()
			account.Extra[codexFingerprintModeExtraKey] = mode
			delete(account.Extra, codexSessionOverrideEnabledKey)
			delete(account.Extra, codexSessionOverrideIDKey)
			repo := &codexSessionSaveRepo{account: account}
			admin := &adminServiceImpl{accountRepo: repo}
			upstream := &queuedHTTPUpstream{}
			svc := &AccountTestService{accountRepo: repo, httpUpstream: upstream}
			test := func(draft *CodexSessionOverride) (string, string) {
				c, recorder := newTestContext()
				if draft != nil {
					c.Set(CodexSessionTestOverrideKey, *draft)
				}
				upstream.responses = append(upstream.responses, newJSONResponse(http.StatusOK, "data: {\"type\":\"response.completed\"}\n\n"))
				require.NoError(t, svc.TestAccountConnection(c, account.ID, "gpt-5.1", "hi", AccountTestModeDefault, AccountTestTypeText))
				req := upstream.requests[len(upstream.requests)-1]
				body, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				session, thread := req.Header.Get("session-id"), req.Header.Get("thread-id")
				require.Equal(t, session, gjson.GetBytes(body, "client_metadata.session_id").String())
				require.Equal(t, thread, gjson.GetBytes(body, "client_metadata.thread_id").String())
				require.Contains(t, recorder.Body.String(), `"session_id":"`+session+`"`)
				require.Contains(t, recorder.Body.String(), `"thread_id":"`+thread+`"`)
				require.NotEmpty(t, req.Header.Get(openAICodexRoutingHintHeader))
				require.Empty(t, req.Header.Get("OpenAI-Beta"))
				return session, thread
			}
			baseSession, baseThread := test(nil)
			require.Equal(t, resolveConvergedSessionID(testCodexFingerprintSeed), baseSession)
			draft := CodexSessionOverride{Enabled: true, SessionID: testCodexSessionOverride}
			draftSession, draftThread := test(&draft)
			require.Equal(t, testCodexSessionOverride, draftSession)
			require.Empty(t, configuredCodexSessionID(repo.account), "临时测试不能落库")
			_, err := admin.SetCodexSessionOverride(context.Background(), account.ID, draft)
			require.NoError(t, err)
			savedSession, savedThread := test(nil)
			require.Equal(t, draftSession, savedSession)
			require.Equal(t, draftThread, savedThread)
			if mode == "session" {
				require.Equal(t, baseThread, draftThread, "刷候选只更换 session，不应同时更换测试 thread")
				require.NotEqual(t, savedSession, savedThread)
			} else {
				require.Equal(t, savedSession, savedThread)
			}
			draft.Enabled = false
			_, err = admin.SetCodexSessionOverride(context.Background(), account.ID, draft)
			require.NoError(t, err)
			restoredSession, restoredThread := test(nil)
			require.Equal(t, baseSession, restoredSession)
			require.Equal(t, baseThread, restoredThread)
			require.Equal(t, testCodexFingerprintSeed, repo.account.Extra[codexFingerprintSeedExtraKey])
		})
	}
}

// 测试弹窗的 turn_id 与上游回合状态只在当前测试会话内复用，不写入账号配置。
func TestAccountTestCodexTurnStateCapturesAndReusesAfterSuccess(t *testing.T) {
	account := codexSessionFlowAccount()
	account.Extra[codexFingerprintModeExtraKey] = "session"
	upstream := &queuedHTTPUpstream{}
	svc := &AccountTestService{accountRepo: &codexSessionSaveRepo{account: account}, httpUpstream: upstream}
	draft := CodexTurnStateTestOverride{
		TurnID:    "44444444-4444-4444-8444-444444444444",
		TurnState: "",
	}

	first := newJSONResponse(http.StatusOK, "data: {\"type\":\"response.completed\"}\n\n")
	first.Header.Set(openAICodexTurnStateHeader, "turn-state-1")
	upstream.responses = append(upstream.responses, first)
	firstContext, firstRecorder := newTestContext()
	firstContext.Set(CodexTurnStateTestOverrideKey, draft)
	require.NoError(t, svc.TestAccountConnection(firstContext, account.ID, "gpt-5.1", "hi", AccountTestModeDefault, AccountTestTypeText))
	require.Contains(t, firstRecorder.Body.String(), `"type":"codex_turn_state"`)
	require.Contains(t, firstRecorder.Body.String(), `"turn_state":"turn-state-1"`)
	firstRequest := upstream.requests[0]
	firstTurnID := firstRequest.Header.Get("turn-id")
	require.NotEmpty(t, firstTurnID)
	firstBody, err := io.ReadAll(firstRequest.Body)
	require.NoError(t, err)
	require.Equal(t, firstTurnID, gjson.GetBytes(firstBody, "client_metadata.turn_id").String())

	draft.TurnState = "turn-state-1"
	draft.Identity = codexAccountTurnIdentity(account)
	second := newJSONResponse(http.StatusOK, "data: {\"type\":\"response.completed\"}\n\n")
	upstream.responses = append(upstream.responses, second)
	secondContext, _ := newTestContext()
	secondContext.Set(CodexTurnStateTestOverrideKey, draft)
	require.NoError(t, svc.TestAccountConnection(secondContext, account.ID, "gpt-5.1", "continue", AccountTestModeDefault, AccountTestTypeText))
	secondRequest := upstream.requests[1]
	require.Equal(t, firstTurnID, secondRequest.Header.Get("turn-id"))
	require.Equal(t, "turn-state-1", secondRequest.Header.Get(openAICodexTurnStateHeader))
}
