//go:build unit

package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/TokenFlux/TokenRouter/internal/config"
	"github.com/TokenFlux/TokenRouter/internal/pkg/ctxkey"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// 内存仓储复现身份校验与CAS，不把Redis粘性写入当作可信归属。
type historyAccountRepo struct {
	AccountRepository
	mu                  sync.Mutex
	accounts            map[int64]*Account
	bindings            map[string]OpenAIConversationBinding
	lookupErr, writeErr error
	advanced            bool
}

type historyGatewayCache struct{ stubGatewayCache }

func (c *historyGatewayCache) GetSessionAccountID(ctx context.Context, group int64, hash string) (int64, error) {
	id, err := c.stubGatewayCache.GetSessionAccountID(ctx, group, hash)
	if err != nil {
		return 0, nil
	}
	return id, nil
}

func (r *historyAccountRepo) GetByID(_ context.Context, id int64) (*Account, error) {
	if a := r.accounts[id]; a != nil {
		return a, nil
	}
	return nil, ErrAccountNotFound
}

func (r *historyAccountRepo) ListSchedulableByPlatform(_ context.Context, platform string) ([]Account, error) {
	var result []Account
	for _, a := range r.accounts {
		if a.Platform == platform && a.IsSchedulable() {
			result = append(result, *a)
		}
	}
	return result, nil
}

func (r *historyAccountRepo) ListSchedulableByGroupIDAndPlatform(ctx context.Context, _ int64, platform string) ([]Account, error) {
	return r.ListSchedulableByPlatform(ctx, platform)
}

func (r *historyAccountRepo) ListSchedulableUngroupedByPlatform(ctx context.Context, platform string) ([]Account, error) {
	return r.ListSchedulableByPlatform(ctx, platform)
}

func historyTestKey(user, group int64, kind, key string) string {
	return fmt.Sprintf("%d:%d:%s:%s", user, group, kind, key)
}

func (r *historyAccountRepo) GetOpenAIConversationBinding(_ context.Context, user, group int64, kind, key string) (*OpenAIConversationBinding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lookupErr != nil {
		return nil, r.lookupErr
	}
	b, ok := r.bindings[historyTestKey(user, group, kind, key)]
	if !ok {
		return nil, nil
	}
	b.Valid = openAIHistoryBindingMatchesIdentity(&b, r.accounts[b.CredentialOwnerAccountID])
	return &b, nil
}

func (r *historyAccountRepo) SaveOpenAIConversationBinding(_ context.Context, b *OpenAIConversationBinding, revision int64) (*OpenAIConversationBinding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.writeErr != nil {
		return nil, r.writeErr
	}
	key := historyTestKey(b.UserID, b.ScopeGroupID, b.Type, b.Key)
	old, exists := r.bindings[key]
	sessionCAS := b.Type == "session" && old.Revision == revision
	sameOwner := old.AccountID == b.AccountID && old.CredentialOwnerAccountID == b.CredentialOwnerAccountID && old.OAuthAccountID == b.OAuthAccountID && old.OAuthUserID == b.OAuthUserID
	if exists && !sessionCAS && !sameOwner {
		return nil, ErrOpenAIHistoryConflict
	}
	if b.Type == "session" && b.Confirmed && (!exists || !sessionCAS || !sameOwner) {
		return nil, ErrOpenAIHistoryConflict
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

func newHistoryTestService(t *testing.T, advanced bool) (*OpenAIGatewayService, *historyAccountRepo) {
	t.Helper()
	r := &historyAccountRepo{accounts: map[int64]*Account{}, bindings: map[string]OpenAIConversationBinding{}, advanced: advanced}
	for _, id := range []int64{1, 2} {
		r.accounts[id] = &Account{ID: id, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Status: StatusActive, Schedulable: true, Priority: int(id), GroupIDs: []int64{7}, Credentials: map[string]any{"chatgpt_account_id": fmt.Sprintf("owner-%d", id)}, Extra: map[string]any{OpenAIOAuthRejectExternalHistoryKey: true}}
	}
	return &OpenAIGatewayService{accountRepo: r, cache: &historyGatewayCache{}, cfg: &config.Config{RunMode: config.RunModeSimple}}, r
}

const historyFreshBody = `{"model":"gpt-5.1","input":"hello"}`
const historyReplayBody = `{"model":"gpt-5.1","input":[{"role":"assistant","content":"old"},{"role":"user","content":"next"}]}`

func historyTestRequest(t *testing.T, svc *OpenAIGatewayService, user int64, session, body string) *gin.Context {
	t.Helper()
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/v1/responses", bytes.NewBufferString(body))
	group := &Group{ID: 7, Platform: PlatformOpenAI, Status: StatusActive, Hydrated: true, SchedulerType: GroupSchedulerTypeBasic}
	repo, ok := svc.accountRepo.(*historyAccountRepo)
	require.True(t, ok)
	if repo.advanced {
		group.SchedulerType = GroupSchedulerTypeAdvanced
	}
	c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), ctxkey.Group, group))
	c.Set("api_key", &APIKey{ID: user + 100, UserID: user, GroupID: &group.ID, Group: group, User: &User{ID: user}})
	if session != "" {
		c.Request.Header.Set("session_id", session)
	}
	require.NoError(t, svc.PrepareOpenAIHistoryRequest(c, ContentModerationProtocolOpenAIResponses, []byte(body), svc.GenerateSessionHash(c, []byte(body))))
	return c
}

func selectHistoryTestAccount(s *OpenAIGatewayService, c *gin.Context, excluded map[int64]struct{}) (*AccountSelectionResult, error) {
	state := openAIHistoryFromContext(c.Request.Context())
	result, _, err := s.SelectAccountWithSchedulerForCapability(c.Request.Context(), ptrInt64(7), state.previousID, state.sessionHash, "gpt-5.1", excluded, OpenAIUpstreamTransportAny, OpenAIEndpointCapabilityResponses, false, false)
	if result != nil && result.ReleaseFunc != nil {
		result.ReleaseFunc()
	}
	return result, err
}

func TestOpenAIHistoryAdmissionCandidateMatrix(t *testing.T) {
	fixture, err := os.ReadFile("../auditcontent/testdata/codex_first_turn.json")
	require.NoError(t, err)
	for _, advanced := range []bool{false, true} {
		for _, tc := range []struct {
			name, body           string
			bound, loose, denied bool
			want                 int64
		}{
			{"fresh", historyFreshBody, false, false, false, 1},
			{"codex_first_turn", string(fixture), false, false, false, 1},
			{"owned", historyReplayBody, true, false, false, 1},
			{"foreign", historyReplayBody, false, false, true, 0},
			{"mixed_pool", historyReplayBody, false, true, false, 2},
			{"unknown_response", `{"model":"gpt-5.1","input":"next","previous_response_id":"resp_unknown"}`, true, false, true, 0},
		} {
			t.Run(fmt.Sprintf("advanced_%t/%s", advanced, tc.name), func(t *testing.T) {
				s, r := newHistoryTestService(t, advanced)
				if tc.loose {
					r.accounts[2].Extra[OpenAIOAuthRejectExternalHistoryKey] = false
				}
				if tc.bound {
					first := historyTestRequest(t, s, 11, "same", historyFreshBody)
					selected, err := selectHistoryTestAccount(s, first, map[int64]struct{}{2: {}})
					require.NoError(t, err)
					require.NoError(t, s.persistOpenAIHistoryResponse(first.Request.Context(), selected.Account, "resp_first", true))
				}
				selected, err := selectHistoryTestAccount(s, historyTestRequest(t, s, 11, "same", tc.body), nil)
				if tc.denied {
					require.ErrorIs(t, err, ErrOpenAIExternalHistory)
					require.Nil(t, selected)
				} else {
					require.NoError(t, err)
					require.NotNil(t, selected)
					if !tc.bound && !tc.loose {
						require.Contains(t, []int64{1, 2}, selected.Account.ID)
					} else {
						require.Equal(t, tc.want, selected.Account.ID)
					}
				}
			})
		}
	}
}

func TestOpenAIHistoryPersistenceIsolationAndIdentity(t *testing.T) {
	s, r := newHistoryTestService(t, true)
	first := historyTestRequest(t, s, 11, "session", historyFreshBody)
	selected, err := selectHistoryTestAccount(s, first, map[int64]struct{}{2: {}})
	require.NoError(t, err)
	require.NoError(t, s.persistOpenAIHistoryResponse(first.Request.Context(), selected.Account, "resp_owned", true))
	restarted := &OpenAIGatewayService{accountRepo: r, cache: &historyGatewayCache{}, cfg: s.cfg}
	r.accounts[2].Priority = 0
	for _, body := range []string{historyReplayBody, `{"model":"gpt-5.1","input":"next","previous_response_id":"resp_owned"}`} {
		selected, err = selectHistoryTestAccount(restarted, historyTestRequest(t, restarted, 11, "session", body), nil)
		require.NoError(t, err)
		require.Equal(t, int64(1), selected.Account.ID)
	}
	_, err = selectHistoryTestAccount(s, historyTestRequest(t, s, 12, "session", historyReplayBody), nil)
	require.ErrorIs(t, err, ErrOpenAIExternalHistory)
	owned, err := s.ValidateOpenAIHTTPResponseOwner(context.Background(), 7, "resp_owned", 11, 999)
	require.NoError(t, err)
	require.True(t, owned)
	owned, err = s.ValidateOpenAIHTTPResponseOwner(context.Background(), 8, "resp_owned", 11, 999)
	require.NoError(t, err)
	require.False(t, owned)
	c := historyTestRequest(t, s, 11, "session", historyReplayBody)
	r.accounts[1].Credentials["access_token"] = "refreshed"
	require.NoError(t, s.ValidateOpenAIHistoryTurn(c.Request.Context(), r.accounts[1]))
	r.accounts[1].Credentials["chatgpt_account_id"] = "reauthorized"
	require.ErrorIs(t, s.ValidateOpenAIHistoryTurn(c.Request.Context(), r.accounts[1]), ErrOpenAIExternalHistory)
}

func TestOpenAIHistoryErrorsReadOnlyAndCAS(t *testing.T) {
	for _, operation := range []string{"lookup", "write"} {
		t.Run(operation, func(t *testing.T) {
			s, r := newHistoryTestService(t, false)
			if operation == "lookup" {
				r.lookupErr = errors.New("offline")
			} else {
				r.writeErr = errors.New("read only")
			}
			_, err := selectHistoryTestAccount(s, historyTestRequest(t, s, 11, "session", historyFreshBody), nil)
			require.ErrorIs(t, err, ErrOpenAIHistoryUnavailable)
		})
	}
	s, r := newHistoryTestService(t, false)
	c := historyTestRequest(t, s, 11, "count", historyFreshBody)
	require.NoError(t, s.PrepareOpenAIHistoryRequest(c, ContentModerationProtocolOpenAIResponses, []byte(historyFreshBody), s.GenerateSessionHash(c, []byte(historyFreshBody)), true))
	selected, err := selectHistoryTestAccount(s, c, nil)
	require.NoError(t, err)
	require.NoError(t, s.ValidateOpenAIHistoryTurn(c.Request.Context(), selected.Account))
	require.NoError(t, s.persistOpenAIHistoryResponse(c.Request.Context(), selected.Account, "resp_count", true))
	require.Empty(t, r.bindings)
	first := historyTestRequest(t, s, 11, "racing", historyFreshBody)
	second := historyTestRequest(t, s, 11, "racing", historyFreshBody)
	require.Empty(t, openAIHistoryCandidateFailureReason(first.Request.Context(), r.accounts[1]))
	require.Empty(t, openAIHistoryCandidateFailureReason(second.Request.Context(), r.accounts[2]))
	require.NoError(t, s.CommitOpenAIHistoryRoute(first.Request.Context(), r.accounts[1]))
	require.ErrorIs(t, s.CommitOpenAIHistoryRoute(second.Request.Context(), r.accounts[2]), ErrOpenAIHistoryConflict)
}

func TestOpenAIHistoryConfigurationAndShadow(t *testing.T) {
	for _, raw := range []any{nil, true, false, "false", 0} {
		a := &Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth, Extra: map[string]any{OpenAIOAuthRejectExternalHistoryKey: raw}}
		require.Equal(t, raw == true, a.IsOpenAIOAuthRejectExternalHistoryEnabled())
	}
	current := &Account{Extra: map[string]any{OpenAIOAuthRejectExternalHistoryKey: false}}
	extra, err := normalizeOpenAIHistoryExtra(PlatformOpenAI, AccountTypeOAuth, map[string]any{"unrelated": true}, current)
	require.NoError(t, err)
	require.Equal(t, false, extra[OpenAIOAuthRejectExternalHistoryKey])
	_, err = normalizeOpenAIHistoryExtra(PlatformOpenAI, AccountTypeOAuth, map[string]any{OpenAIOAuthRejectExternalHistoryKey: "false"}, nil)
	require.Error(t, err)
	s, r := newHistoryTestService(t, false)
	shadow := &Account{ID: 3, Platform: PlatformOpenAI, Type: AccountTypeOAuth, ParentAccountID: ptrInt64(1), Extra: map[string]any{OpenAIOAuthRejectExternalHistoryKey: false}}
	r.accounts[3] = shadow
	c := historyTestRequest(t, s, 11, "foreign", historyReplayBody)
	require.NotEmpty(t, openAIHistoryCandidateFailureReason(c.Request.Context(), shadow))
	r.accounts[1].Extra[OpenAIOAuthRejectExternalHistoryKey] = false
	require.NoError(t, s.ValidateOpenAIHistoryTurn(c.Request.Context(), shadow))
	r.accounts[1].Extra[OpenAIOAuthRejectExternalHistoryKey] = true
	require.ErrorIs(t, s.ValidateOpenAIHistoryTurn(c.Request.Context(), shadow), ErrOpenAIExternalHistory)
}

func TestOpenAIHistoryReservationRequiresCompletedResponse(t *testing.T) {
	for _, payload := range []string{
		`{"type":"response.created","response":{"id":"resp_pending","status":"in_progress"}}`,
		`{"type":"response.output_text.delta","response_id":"resp_pending","delta":"partial"}`,
		`{"type":"response.failed","response":{"id":"resp_pending","status":"failed"}}`,
		`{"type":"response.completed","response":{"id":"resp_pending","status":"incomplete"}}`,
		`{"type":"response.completed","response":{"id":"resp_pending","status":null}}`,
		`{"type":"response.completed","response":{"id":"resp_pending","status":""}}`,
		`{"type":"response.completed","response":{"id":"resp_pending","status":"completed","error":{"message":"failed"}}}`,
		`{"status":"completed"}`,
		`{"id":"not-a-response","status":"completed"}`,
		`[DONE]`,
	} {
		t.Run(payload, func(t *testing.T) {
			s, r := newHistoryTestService(t, false)
			first := historyTestRequest(t, s, 11, "pending", historyFreshBody)
			selected, err := selectHistoryTestAccount(s, first, map[int64]struct{}{2: {}})
			require.NoError(t, err)
			require.NoError(t, s.persistOpenAIHistoryResponsePayload(first.Request.Context(), selected.Account, []byte(payload)))
			for _, b := range r.bindings {
				require.False(t, b.Confirmed)
			}
			_, err = selectHistoryTestAccount(s, historyTestRequest(t, s, 11, "pending", historyReplayBody), nil)
			require.ErrorIs(t, err, ErrOpenAIExternalHistory)
			_, err = selectHistoryTestAccount(s, historyTestRequest(t, s, 11, "pending", historyFreshBody), nil)
			require.NoError(t, err, "失败预占不能妨碍普通首轮重试")
		})
	}
}

func TestOpenAIHistorySuccessfulCompletionConfirmsReservation(t *testing.T) {
	for _, payload := range []string{
		`{"object":"response","id":"resp_confirmed","status":"completed","error":null}`,
		`{"type":"response.completed","response":{"id":"resp_confirmed","status":"completed"}}`,
		`{"type":"response.done","response":{"id":"resp_confirmed"}}`,
		"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_confirmed\",\"status\":\"completed\"}}\n\n",
	} {
		t.Run(payload, func(t *testing.T) {
			s, r := newHistoryTestService(t, false)
			first := historyTestRequest(t, s, 11, "confirmed", historyFreshBody)
			selected, err := selectHistoryTestAccount(s, first, map[int64]struct{}{2: {}})
			require.NoError(t, err)
			require.NoError(t, s.persistOpenAIHistoryResponse(first.Request.Context(), selected.Account, "resp_confirmed"))
			owned, err := s.ValidateOpenAIHTTPResponseOwner(context.Background(), 7, "resp_confirmed", 11, 111)
			require.NoError(t, err)
			require.False(t, owned)
			require.NoError(t, s.persistOpenAIHistoryResponsePayload(first.Request.Context(), selected.Account, []byte(payload)))
			for _, b := range r.bindings {
				require.True(t, b.Confirmed)
			}
			owned, err = s.ValidateOpenAIHTTPResponseOwner(context.Background(), 7, "resp_confirmed", 11, 111)
			require.NoError(t, err)
			require.True(t, owned)
			selected, err = selectHistoryTestAccount(s, historyTestRequest(t, s, 11, "confirmed", historyReplayBody), nil)
			require.NoError(t, err)
			require.Equal(t, int64(1), selected.Account.ID)
			for _, b := range r.bindings {
				require.True(t, b.Confirmed, "重复预占不清除成功证据")
			}
		})
	}
}

func TestOpenAIHistoryLateCompletionCannotConfirmReroutedSession(t *testing.T) {
	s, r := newHistoryTestService(t, false)
	first := historyTestRequest(t, s, 11, "routed", historyFreshBody)
	selected, err := selectHistoryTestAccount(s, first, map[int64]struct{}{2: {}})
	require.NoError(t, err)
	second := historyTestRequest(t, s, 11, "routed", historyFreshBody)
	next, err := selectHistoryTestAccount(s, second, map[int64]struct{}{1: {}})
	require.NoError(t, err)
	require.Equal(t, int64(2), next.Account.ID)
	require.ErrorIs(t, s.persistOpenAIHistoryResponse(first.Request.Context(), selected.Account, "resp_late", true), ErrOpenAIHistoryConflict)
	for _, b := range r.bindings {
		if b.Type == "session" {
			require.Equal(t, int64(2), b.AccountID)
			require.False(t, b.Confirmed)
		}
	}
}

func TestOpenAIHistoryMissingPolicyDefaultsOff(t *testing.T) {
	s, r := newHistoryTestService(t, false)
	for _, a := range r.accounts {
		a.Extra = nil
		require.False(t, a.IsOpenAIOAuthRejectExternalHistoryEnabled())
	}
	_, err := selectHistoryTestAccount(s, historyTestRequest(t, s, 11, "external", historyReplayBody), nil)
	require.NoError(t, err)
	extra, err := normalizeOpenAIHistoryExtra(PlatformOpenAI, AccountTypeOAuth, nil, nil)
	require.NoError(t, err)
	require.Equal(t, false, extra[OpenAIOAuthRejectExternalHistoryKey])
	current := &Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth, Extra: map[string]any{OpenAIOAuthRejectExternalHistoryKey: true}}
	extra, err = normalizeOpenAIHistoryExtra(PlatformOpenAI, AccountTypeOAuth, nil, current)
	require.NoError(t, err)
	require.Equal(t, true, extra[OpenAIOAuthRejectExternalHistoryKey])
}
