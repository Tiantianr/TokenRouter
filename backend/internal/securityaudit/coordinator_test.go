package securityaudit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

type fakeLegacyEngine struct {
	decision *LegacyDecision
	err      error
	calls    atomic.Int64
	last     Request
}

func (f *fakeLegacyEngine) Check(_ context.Context, req Request) (*LegacyDecision, error) {
	f.calls.Add(1)
	f.last = req
	return f.decision, f.err
}

type fakePromptEngine struct {
	mode           Mode
	decision       *PromptDecision
	err            error
	enqueues       atomic.Int64
	deepEnqueues   atomic.Int64
	evaluates      atomic.Int64
	receiptCommits atomic.Int64
	fenceChecks    atomic.Int64
	applies        bool
	fenceDecision  *PromptDecision
	fenceErr       error
	lastEnqueue    Request
	lastDeep       Request
	lastEvaluate   Request
}

type fakePolicyPromptEngine struct {
	*fakePromptEngine
	policy promptBlockingPolicy
}

func (f *fakePolicyPromptEngine) blockingPolicy(Request) promptBlockingPolicy { return f.policy }

func (f *fakePromptEngine) EffectiveMode() Mode          { return f.mode }
func (f *fakePromptEngine) BlockingApplies(Request) bool { return f.applies }
func (f *fakePromptEngine) Enqueue(_ context.Context, req Request) error {
	f.enqueues.Add(1)
	f.lastEnqueue = req
	return f.err
}
func (f *fakePromptEngine) EnqueueDeep(_ context.Context, req Request) error {
	f.deepEnqueues.Add(1)
	f.lastDeep = req
	return f.err
}
func (f *fakePromptEngine) commitAllowReceipts(context.Context, *PromptDecision) {
	f.receiptCommits.Add(1)
}
func (f *fakePromptEngine) pendingRecoveryDecision(context.Context, Request) (*PromptDecision, error) {
	f.fenceChecks.Add(1)
	return f.fenceDecision, f.fenceErr
}

func TestCoordinatorMarksLegacyTextAsShadowOnlyWhenPromptCoversRequest(t *testing.T) {
	legacy := &fakeLegacyEngine{decision: &LegacyDecision{Allowed: true}}
	prompt := &fakePromptEngine{
		mode: ModeBlocking, applies: true,
		decision: &PromptDecision{Kind: DecisionAllow, AllowNextStage: true},
	}
	decision := NewCoordinator(legacy, prompt).Check(context.Background(), Request{APIKeyID: 7})
	require.True(t, decision.AllowNextStage)
	require.True(t, legacy.last.PromptTextAuthority)

	legacy = &fakeLegacyEngine{decision: &LegacyDecision{Allowed: true}}
	prompt.applies = false
	decision = NewCoordinator(legacy, prompt).Check(context.Background(), Request{APIKeyID: 7})
	require.True(t, decision.AllowNextStage)
	require.False(t, legacy.last.PromptTextAuthority)
}

func TestCoordinatorPropagatesFrozenBlockingExemptionToLegacyAcrossTransports(t *testing.T) {
	for _, stage := range []string{"http", "first_turn", "subsequent_turn"} {
		t.Run(stage, func(t *testing.T) {
			legacy := &fakeLegacyEngine{decision: &LegacyDecision{Allowed: true}}
			prompt := &fakePolicyPromptEngine{
				fakePromptEngine: &fakePromptEngine{
					mode: ModeBlocking,
					decision: &PromptDecision{
						Kind: DecisionAllow, AllowNextStage: true,
						AsyncAuditHandled: true, BlockingExemptAtRequest: true,
					},
				},
				policy: promptBlockingPolicy{Applies: true, BlockingExempt: true, ConfigVersion: 7},
			}

			decision := NewCoordinator(legacy, prompt).Check(context.Background(), Request{UserID: 42, Stage: stage})

			require.True(t, decision.AllowNextStage)
			require.True(t, legacy.last.BlockingExemptAtRequest)
			require.False(t, legacy.last.PromptTextAuthority)
		})
	}
}

func TestCoordinatorFinalRecoveryFenceStopsConcurrentOrdinaryAllow(t *testing.T) {
	prompt := &fakePromptEngine{
		mode:     ModeBlocking,
		decision: &PromptDecision{Kind: DecisionAllow, AllowNextStage: true},
		fenceDecision: &PromptDecision{
			Kind: DecisionBlock, ErrorCode: ErrorCodeDeepReviewRequired,
			AllowNextStage: false, DeepReviewed: true,
		},
	}
	decision := NewCoordinator(&fakeLegacyEngine{decision: &LegacyDecision{Allowed: true}}, prompt).
		Check(context.Background(), Request{UserID: 42})

	require.Equal(t, DecisionBlock, decision.Kind)
	require.Equal(t, ErrorCodeDeepReviewRequired, decision.ErrorCode)
	require.False(t, decision.AllowNextStage)
	require.Equal(t, int64(1), prompt.fenceChecks.Load())
	require.Zero(t, prompt.receiptCommits.Load())
	require.Zero(t, prompt.deepEnqueues.Load())
}

func TestCoordinatorFinalRecoveryFenceFailsClosedOnStateError(t *testing.T) {
	prompt := &fakePromptEngine{
		mode:     ModeBlocking,
		decision: &PromptDecision{Kind: DecisionAllow, AllowNextStage: true},
		fenceErr: errors.New("redis unavailable"),
	}
	decision := NewCoordinator(&fakeLegacyEngine{decision: &LegacyDecision{Allowed: true}}, prompt).
		Check(context.Background(), Request{UserID: 42})

	require.Equal(t, DecisionUnavailable, decision.Kind)
	require.Equal(t, ErrorCodeDeepReviewState, decision.ErrorCode)
	require.False(t, decision.AllowNextStage)
	require.Zero(t, prompt.receiptCommits.Load())
	require.Zero(t, prompt.deepEnqueues.Load())
}

func TestCoordinatorBlockingExemptAdmissionKeepsContentModerationAuthoritative(t *testing.T) {
	prompt := &fakePromptEngine{
		mode: ModeBlocking, applies: false,
		decision: &PromptDecision{
			Kind: DecisionAllow, AllowNextStage: true, AsyncAuditHandled: true,
			BlockingExemptAtRequest: true,
		},
	}
	legacy := &fakeLegacyEngine{decision: &LegacyDecision{Blocked: true, StatusCode: http.StatusForbidden, ErrorCode: "content_policy_violation"}}
	decision := NewCoordinator(legacy, prompt).Check(context.Background(), Request{UserID: 42})

	require.Equal(t, DecisionBlock, decision.Kind)
	require.False(t, decision.AllowNextStage)
	require.False(t, legacy.last.PromptTextAuthority)
	require.Zero(t, prompt.fenceChecks.Load())
	require.Zero(t, prompt.receiptCommits.Load())
	require.Zero(t, prompt.deepEnqueues.Load())
}
func (f *fakePromptEngine) Evaluate(_ context.Context, req Request) (*PromptDecision, error) {
	f.evaluates.Add(1)
	f.lastEvaluate = req
	return f.decision, f.err
}

func TestCoordinatorSharesFrozenBodyAcrossSynchronousAuditBranches(t *testing.T) {
	body := []byte(`{"input":"immutable"}`)
	legacy := &fakeLegacyEngine{decision: &LegacyDecision{Allowed: true}}
	prompt := &fakePromptEngine{mode: ModeBlocking, applies: true, decision: &PromptDecision{Kind: DecisionAllow, AllowNextStage: true, DeepReviewed: true}}
	decision := NewCoordinator(legacy, prompt).Check(context.Background(), Request{Body: body})
	require.True(t, decision.AllowNextStage)
	require.True(t, &body[0] == &legacy.last.Body[0])
	require.True(t, &body[0] == &prompt.lastEvaluate.Body[0])
}

func TestCoordinatorModesAndPriority(t *testing.T) {
	tests := []struct {
		name           string
		mode           Mode
		legacy         *LegacyDecision
		prompt         *PromptDecision
		promptErr      error
		wantKind       DecisionKind
		wantCode       string
		wantEnqueue    int64
		wantEvaluation int64
	}{
		{name: "off", mode: ModeOff, wantKind: DecisionAllow},
		{name: "async only enqueues", mode: ModeAsync, wantKind: DecisionAllow, wantEnqueue: 1},
		{name: "prompt block", mode: ModeBlocking, prompt: &PromptDecision{Kind: DecisionBlock}, wantKind: DecisionBlock, wantCode: ErrorCodeBlocked, wantEvaluation: 1},
		{name: "prompt unavailable", mode: ModeBlocking, promptErr: errors.New("down"), wantKind: DecisionAllow, wantEvaluation: 1},
		{name: "legacy unavailable", mode: ModeOff,
			legacy:   &LegacyDecision{Blocked: true, StatusCode: http.StatusServiceUnavailable, ErrorCode: "content_moderation_unavailable", Message: "legacy unavailable", Action: "error"},
			wantKind: DecisionUnavailable, wantCode: "content_moderation_unavailable"},
		{name: "legacy wins both block", mode: ModeBlocking,
			legacy: &LegacyDecision{Blocked: true, StatusCode: http.StatusForbidden, ErrorCode: "content_policy_violation", Message: "legacy"},
			prompt: &PromptDecision{Kind: DecisionBlock}, wantKind: DecisionBlock, wantCode: "content_policy_violation", wantEvaluation: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			legacy := &fakeLegacyEngine{decision: tt.legacy}
			prompt := &fakePromptEngine{mode: tt.mode, decision: tt.prompt, err: tt.promptErr}
			decision := NewCoordinator(legacy, prompt).Check(context.Background(), Request{Body: []byte(`{}`)})
			require.Equal(t, tt.wantKind, decision.Kind)
			require.Equal(t, tt.wantCode, decision.ErrorCode)
			require.Equal(t, int64(1), legacy.calls.Load())
			require.Equal(t, tt.wantEnqueue, prompt.enqueues.Load())
			require.Equal(t, tt.wantEvaluation, prompt.evaluates.Load())
		})
	}
}

func TestCoordinatorClassifiesLegacyModerationDependencyAsUnavailable(t *testing.T) {
	legacy := &LegacyDecision{
		Blocked: true, Flagged: false, StatusCode: http.StatusServiceUnavailable,
		ErrorCode: "content_moderation_unavailable", Message: "content moderation is temporarily unavailable", Action: "error",
	}
	decision := NewCoordinator(
		&fakeLegacyEngine{decision: legacy},
		&fakePromptEngine{mode: ModeBlocking, decision: &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}},
	).Check(context.Background(), Request{})

	require.Equal(t, DecisionUnavailable, decision.Kind)
	require.Equal(t, http.StatusServiceUnavailable, decision.HTTPStatus)
	require.Equal(t, "content_moderation_unavailable", decision.ErrorCode)
	require.Equal(t, "content moderation is temporarily unavailable", decision.ClientMessage)
	require.False(t, decision.AllowNextStage)
	require.Same(t, legacy, decision.Legacy)
}

func TestCoordinatorPromptPolicyBlockWinsLegacyUnavailable(t *testing.T) {
	decision := NewCoordinator(
		&fakeLegacyEngine{decision: &LegacyDecision{Blocked: true, StatusCode: http.StatusServiceUnavailable, ErrorCode: "content_moderation_unavailable", Action: "error"}},
		&fakePromptEngine{mode: ModeBlocking, decision: &PromptDecision{Kind: DecisionBlock}},
	).Check(context.Background(), Request{})

	require.Equal(t, DecisionBlock, decision.Kind)
	require.Equal(t, ErrorCodeBlocked, decision.ErrorCode)
	require.Equal(t, "安全审计拒绝了本次请求。风险内容可能来自当前输入、会话上下文、系统指令或插件/工具内容，请检查并移除相关内容后重试", decision.ClientMessage)
	require.False(t, decision.AllowNextStage)
}

func TestCoordinatorPromptBlockMessageUsesRedactedCategoryLabels(t *testing.T) {
	tests := []struct {
		name       string
		result     *NormalizedResult
		want       string
		notContain string
	}{
		{
			name: "known categories",
			result: &NormalizedResult{
				Categories: []string{"pii", "jailbreak"}, MatchedScanners: []string{"pii", "jailbreak"},
			},
			want: "安全审计拒绝了本次请求，命中风险类别：个人敏感信息、越狱攻击。风险内容可能来自当前输入、会话上下文、系统指令或插件/工具内容，请检查并移除相关内容后重试",
		},
		{
			name: "unknown category",
			result: &NormalizedResult{
				UnknownCategories: []string{unknownCategoryID("future raw category")},
			},
			want:       "安全审计拒绝了本次请求，命中风险类别：未知高风险分类。风险内容可能来自当前输入、会话上下文、系统指令或插件/工具内容，请检查并移除相关内容后重试",
			notContain: "unknown:",
		},
		{
			name:   "missing result",
			result: nil,
			want:   "安全审计拒绝了本次请求。风险内容可能来自当前输入、会话上下文、系统指令或插件/工具内容，请检查并移除相关内容后重试",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := NewCoordinator(
				&fakeLegacyEngine{decision: &LegacyDecision{Allowed: true}},
				&fakePromptEngine{mode: ModeBlocking, decision: &PromptDecision{Kind: DecisionBlock, Result: tt.result}},
			).Check(context.Background(), Request{})
			require.Equal(t, tt.want, decision.ClientMessage)
			if tt.notContain != "" {
				require.NotContains(t, decision.ClientMessage, tt.notContain)
			}
		})
	}
}

func TestCoordinatorDoesNotMutateRequestBody(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"hello"}]}`)
	original := append([]byte(nil), body...)
	prompt := &fakePromptEngine{mode: ModeAsync}
	decision := NewCoordinator(&fakeLegacyEngine{}, prompt).Check(context.Background(), Request{Body: body})
	require.True(t, decision.AllowNextStage)
	require.Equal(t, original, body)
}

func TestCoordinatorBlockingPriorityCoversBothEngineDecisionMatrix(t *testing.T) {
	legacyCases := []struct {
		name     string
		decision *LegacyDecision
	}{
		{name: "allow", decision: &LegacyDecision{Allowed: true, StatusCode: http.StatusOK, Action: "allow"}},
		{name: "flag", decision: &LegacyDecision{Allowed: true, Flagged: true, StatusCode: http.StatusOK, Action: "flag"}},
		{name: "block", decision: &LegacyDecision{Blocked: true, StatusCode: http.StatusForbidden, ErrorCode: "legacy_exact_code", Message: "legacy exact message", Action: "block"}},
	}
	promptCases := []struct {
		name     string
		decision *PromptDecision
		wantKind DecisionKind
		wantCode string
	}{
		{name: "allow", decision: &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, wantKind: DecisionAllow},
		{name: "flag", decision: &PromptDecision{Kind: DecisionFlag, AllowNextStage: true}, wantKind: DecisionFlag},
		{name: "block", decision: &PromptDecision{Kind: DecisionBlock}, wantKind: DecisionBlock, wantCode: ErrorCodeBlocked},
		{name: "unavailable", decision: &PromptDecision{Kind: DecisionUnavailable, ErrorCode: ErrorCodeUnavailable}, wantKind: DecisionAllow},
		{name: "invalid", decision: &PromptDecision{Kind: DecisionInvalid, ErrorCode: ErrorCodeInvalidResponse}, wantKind: DecisionInvalid, wantCode: ErrorCodeInvalidResponse},
	}

	for _, legacyCase := range legacyCases {
		for _, promptCase := range promptCases {
			t.Run(fmt.Sprintf("legacy_%s_prompt_%s", legacyCase.name, promptCase.name), func(t *testing.T) {
				legacy := &fakeLegacyEngine{decision: legacyCase.decision}
				prompt := &fakePromptEngine{mode: ModeBlocking, decision: promptCase.decision}
				decision := NewCoordinator(legacy, prompt).Check(context.Background(), Request{})

				require.Same(t, legacyCase.decision, decision.Legacy)
				if promptCase.name == "unavailable" {
					require.NotSame(t, promptCase.decision, decision.Prompt)
					require.True(t, decision.Prompt.FailureAllowed)
					require.Equal(t, ErrorCodeUnavailable, decision.Prompt.ErrorCode)
				} else {
					require.Same(t, promptCase.decision, decision.Prompt)
				}
				require.Equal(t, int64(1), legacy.calls.Load())
				require.Equal(t, int64(1), prompt.evaluates.Load())
				if legacyCase.name == "block" {
					require.Equal(t, DecisionBlock, decision.Kind)
					require.Equal(t, "legacy_exact_code", decision.ErrorCode)
					require.Equal(t, "legacy exact message", decision.ClientMessage)
					require.False(t, decision.AllowNextStage)
					return
				}
				require.Equal(t, promptCase.wantKind, decision.Kind)
				require.Equal(t, promptCase.wantCode, decision.ErrorCode)
				if promptCase.name == "unavailable" {
					require.True(t, decision.AllowNextStage)
				} else {
					require.Equal(t, promptCase.decision.AllowNextStage, decision.AllowNextStage)
				}
			})
		}
	}
}

func TestCoordinatorPreservesIndependentEngineFactsAndMapsOnlyGatewayOutcome(t *testing.T) {
	legacyDecision := &LegacyDecision{
		Allowed: true, Flagged: true, Message: "legacy finding", StatusCode: http.StatusAccepted,
		ErrorCode: "legacy_observation", Action: "legacy_action",
	}
	promptResult := &NormalizedResult{
		Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock,
		Categories: []string{"pii"}, MatchedScanners: []string{"pii"}, ScannerScores: map[string]float64{"pii": 1},
	}
	promptDecision := &PromptDecision{Kind: DecisionBlock, Result: promptResult}
	decision := NewCoordinator(
		&fakeLegacyEngine{decision: legacyDecision},
		&fakePromptEngine{mode: ModeBlocking, decision: promptDecision},
	).Check(context.Background(), Request{})

	require.Same(t, legacyDecision, decision.Legacy)
	require.Same(t, promptDecision, decision.Prompt)
	require.Same(t, promptResult, decision.Prompt.Result)
	require.Equal(t, "legacy finding", decision.Legacy.Message)
	require.Equal(t, []string{"pii"}, decision.Prompt.Result.Categories)
	require.Equal(t, ErrorCodeBlocked, decision.ErrorCode)
	require.Equal(t, "安全审计拒绝了本次请求，命中风险类别：个人敏感信息。风险内容可能来自当前输入、会话上下文、系统指令或插件/工具内容，请检查并移除相关内容后重试", decision.ClientMessage)
}

func TestCoordinatorAsyncEnqueueFailuresNeverChangeResponseOrDownstreamDispatch(t *testing.T) {
	for _, enqueueErr := range []error{ErrQueueFull, ErrQueueAdmissionBusy, errors.New("redis unavailable"), errors.New("publish failed")} {
		prompt := &fakePromptEngine{mode: ModeAsync, err: enqueueErr}
		decision := NewCoordinator(&fakeLegacyEngine{decision: &LegacyDecision{Allowed: true}}, prompt).Check(context.Background(), Request{})
		downstreamDispatches := 0
		status := http.StatusOK
		responseBody := "unchanged-upstream-response"
		if decision.AllowNextStage {
			downstreamDispatches++
		} else {
			status = decision.HTTPStatus
			responseBody = decision.ClientMessage
		}
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, "unchanged-upstream-response", responseBody)
		require.Equal(t, 1, downstreamDispatches)
		require.Equal(t, int64(1), prompt.enqueues.Load())
		require.Zero(t, prompt.evaluates.Load())
	}
}

func TestCoordinatorAsyncReceiptWriteRequiresLegacyAllow(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		legacy    *LegacyDecision
		wantWrite bool
	}{
		{name: "allow", legacy: &LegacyDecision{Allowed: true}, wantWrite: true},
		{name: "block", legacy: &LegacyDecision{Blocked: true, StatusCode: http.StatusForbidden}},
		{name: "unavailable", legacy: &LegacyDecision{Blocked: true, StatusCode: http.StatusServiceUnavailable, ErrorCode: "content_moderation_unavailable", Action: "error"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			prompt := &fakePromptEngine{mode: ModeAsync}
			NewCoordinator(&fakeLegacyEngine{decision: testCase.legacy}, prompt).Check(context.Background(), Request{})
			require.Equal(t, int64(1), prompt.enqueues.Load())
			require.Equal(t, testCase.wantWrite, prompt.lastEnqueue.AllowReceiptWrite)
		})
	}
}

func TestCoordinatorEnqueuesDeepOnlyAfterCombinedBlockingAllow(t *testing.T) {
	prompt := &fakePromptEngine{mode: ModeBlocking, decision: &PromptDecision{
		Kind: DecisionAllow, AllowNextStage: true, AllowReceiptKeys: []string{strings.Repeat("a", 64)},
	}}
	decision := NewCoordinator(&fakeLegacyEngine{decision: &LegacyDecision{Allowed: true}}, prompt).Check(context.Background(), Request{})
	require.True(t, decision.AllowNextStage)
	require.Equal(t, int64(1), prompt.deepEnqueues.Load())
	require.Equal(t, int64(1), prompt.receiptCommits.Load())
	require.Equal(t, prompt.decision.AllowReceiptKeys, prompt.lastDeep.AllowReceiptKeys)
	require.True(t, prompt.lastDeep.AllowReceiptWrite)
	require.False(t, prompt.lastDeep.SuppressReceiptWrite)

	prompt = &fakePromptEngine{mode: ModeBlocking, decision: &PromptDecision{
		Kind: DecisionAllow, ErrorCode: ErrorCodeUnavailable, AllowNextStage: true, FailureAllowed: true,
	}}
	decision = NewCoordinator(&fakeLegacyEngine{decision: &LegacyDecision{Allowed: true}}, prompt).Check(context.Background(), Request{})
	require.True(t, decision.AllowNextStage)
	require.Zero(t, prompt.fenceChecks.Load())
	require.Zero(t, prompt.receiptCommits.Load())
	require.Equal(t, int64(1), prompt.deepEnqueues.Load())
	require.False(t, prompt.lastDeep.AllowReceiptWrite)
	require.True(t, prompt.lastDeep.SuppressReceiptWrite)

	prompt = &fakePromptEngine{mode: ModeBlocking, decision: &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}}
	decision = NewCoordinator(&fakeLegacyEngine{decision: &LegacyDecision{Blocked: true, StatusCode: http.StatusForbidden}}, prompt).Check(context.Background(), Request{})
	require.False(t, decision.AllowNextStage)
	require.Zero(t, prompt.deepEnqueues.Load())
	require.Zero(t, prompt.receiptCommits.Load())

	prompt = &fakePromptEngine{mode: ModeBlocking, decision: &PromptDecision{Kind: DecisionAllow, AllowNextStage: true, DeepReviewed: true}}
	decision = NewCoordinator(&fakeLegacyEngine{decision: &LegacyDecision{Allowed: true}}, prompt).Check(context.Background(), Request{})
	require.True(t, decision.AllowNextStage)
	require.Zero(t, prompt.deepEnqueues.Load())
}

func TestCoordinatorPreservesDeepReviewRequiredBlockCode(t *testing.T) {
	decision := NewCoordinator(
		&fakeLegacyEngine{decision: &LegacyDecision{Allowed: true}},
		&fakePromptEngine{mode: ModeBlocking, decision: &PromptDecision{Kind: DecisionBlock, ErrorCode: ErrorCodeDeepReviewRequired, DeepReviewed: true}},
	).Check(context.Background(), Request{})
	require.Equal(t, DecisionBlock, decision.Kind)
	require.Equal(t, ErrorCodeDeepReviewRequired, decision.ErrorCode)
	require.False(t, decision.AllowNextStage)
}

func TestCoordinatorKeepsRecoveryStateFailureDistinctFromGuardUnavailable(t *testing.T) {
	decision := prioritize(nil, unavailablePromptDecision(ErrorCodeDeepReviewState))
	require.Equal(t, DecisionUnavailable, decision.Kind)
	require.Equal(t, ErrorCodeDeepReviewState, decision.ErrorCode)
	require.Equal(t, "安全审计恢复状态暂时不可用，请稍后重试", decision.ClientMessage)

	guard := NewCoordinator(
		&fakeLegacyEngine{decision: &LegacyDecision{Allowed: true}},
		&fakePromptEngine{mode: ModeBlocking, decision: unavailablePromptDecision(ErrorCodeUnavailable)},
	).Check(context.Background(), Request{})
	require.Equal(t, DecisionAllow, guard.Kind)
	require.True(t, guard.AllowNextStage)
	require.Empty(t, guard.ClientMessage)
	require.True(t, guard.Prompt.FailureAllowed)

	invalid := prioritize(nil, &PromptDecision{Kind: DecisionInvalid, ErrorCode: ErrorCodeInvalidResponse})
	require.Equal(t, "提示词安全审计结果无效，请稍后重试", invalid.ClientMessage)
	extraction := prioritize(nil, unavailablePromptDecision(ErrorCodeExtractionFailed))
	require.Equal(t, "请求内容无法完成提示词安全审计，请检查请求格式后重试", extraction.ClientMessage)
}

func TestCoordinatorContentModerationRemainsAuthoritativeDuringPromptOutage(t *testing.T) {
	for _, legacy := range []*LegacyDecision{
		{Blocked: true, StatusCode: http.StatusForbidden, ErrorCode: "content_policy_violation", Message: "blocked", Action: "block"},
		{Blocked: true, StatusCode: http.StatusServiceUnavailable, ErrorCode: "content_moderation_unavailable", Message: "moderation unavailable", Action: "error"},
	} {
		decision := NewCoordinator(
			&fakeLegacyEngine{decision: legacy},
			&fakePromptEngine{mode: ModeBlocking, err: &GuardError{Code: ErrorCodeUnavailable, HTTPStatus: 400}},
		).Check(context.Background(), Request{})
		require.False(t, decision.AllowNextStage)
		require.Equal(t, legacy.ErrorCode, decision.ErrorCode)
		require.Equal(t, legacy.Message, decision.ClientMessage)
		require.True(t, decision.Prompt.FailureAllowed)
	}
}
