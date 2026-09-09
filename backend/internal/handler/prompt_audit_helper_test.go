//go:build unit

package handler

import (
	"context"
	"testing"

	"github.com/TokenFlux/TokenRouter/internal/securityaudit"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// 阻断替身验证真实 handler 的副作用顺序，不向外部审核服务发送测试内容。
type blockingPromptTestEngine struct {
	requests   []securityaudit.Request
	allowFirst bool
}

func (e *blockingPromptTestEngine) EffectiveMode() securityaudit.Mode {
	return securityaudit.ModeBlocking
}
func (e *blockingPromptTestEngine) Enqueue(context.Context, securityaudit.Request) error { return nil }
func (e *blockingPromptTestEngine) Evaluate(_ context.Context, req securityaudit.Request) (*securityaudit.PromptDecision, error) {
	e.requests = append(e.requests, req)
	if e.allowFirst && len(e.requests) == 1 {
		return &securityaudit.PromptDecision{Kind: securityaudit.DecisionAllow, AllowNextStage: true}, nil
	}
	return &securityaudit.PromptDecision{Kind: securityaudit.DecisionBlock, ErrorCode: securityaudit.ErrorCodeBlocked}, nil
}

func TestPromptAuditBlocksBeforeHistoryAndUpstream(t *testing.T) {
	for _, tc := range []struct {
		path, body string
		handle     func(*OpenAIGatewayHandler, *gin.Context)
	}{
		{"/v1/responses", `{"model":"gpt-5.1","input":"review me"}`, (*OpenAIGatewayHandler).Responses},
		{"/v1/chat/completions", `{"model":"gpt-5.1","messages":[{"role":"user","content":"review me"}]}`, (*OpenAIGatewayHandler).ChatCompletions},
		{"/v1/responses/input_tokens", `{"model":"gpt-5.1","input":"review me"}`, (*OpenAIGatewayHandler).ResponsesInputTokens},
	} {
		t.Run(tc.path, func(t *testing.T) {
			u := &historyHTTPUpstream{}
			h, repo := newHistoryHTTPHandler(t, false, "oauth", u)
			engine := &blockingPromptTestEngine{}
			h.promptAudit = securityaudit.NewCoordinator(nil, engine)
			c, w := historyHTTPContext(t, tc.body)
			c.Request.URL.Path = tc.path
			tc.handle(h, c)
			require.Equal(t, 403, w.Code, w.Body.String())
			require.Len(t, engine.requests, 1)
			require.Equal(t, tc.body, string(engine.requests[0].Body))
			require.Empty(t, u.calls())
			require.Zero(t, repo.writes)
			require.Zero(t, repo.lookups)
		})
	}
}
