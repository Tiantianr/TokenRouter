package handler

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/TokenFlux/TokenRouter/internal/securityaudit"
	middleware "github.com/TokenFlux/TokenRouter/internal/server/middleware"
	"github.com/TokenFlux/TokenRouter/internal/service"
	coderws "github.com/coder/websocket"
	"github.com/gin-gonic/gin"
)

// runPromptAudit 复用已有协议审核调用点，HTTP 和 WS 每轮均在调度前执行。
func runPromptAudit(c *gin.Context, input service.ContentModerationCheckInput, coordinator *securityaudit.Coordinator, contexts ...context.Context) *service.ContentModerationDecision {
	session, source := service.ExtractClientSessionIdentityWithBody(c, input.Body)
	stage := "http"
	if strings.EqualFold(c.GetHeader("Upgrade"), "websocket") {
		stage = "ws"
	}
	req := securityaudit.Request{
		RequestID: input.RequestID, ClientIP: middleware.SecurityClientIP(c),
		UserID: input.UserID, UserEmail: input.UserEmail, BillingUserID: input.BillingUserID, TeamID: input.TeamID,
		APIKeyID: input.APIKeyID, APIKeyName: input.APIKeyName, GroupID: input.GroupID, GroupName: input.GroupName,
		Provider: input.Provider, Endpoint: input.Endpoint, Protocol: input.Protocol, Model: input.Model,
		Body: input.Body, Stage: stage, SessionSource: source,
		SessionKey: securityaudit.HashSessionKey(input.UserID, input.Protocol, source, session),
	}
	ctx := c.Request.Context()
	if len(contexts) > 0 && contexts[0] != nil {
		ctx = contexts[0]
	}
	decision := coordinator.Check(ctx, req)
	if !decision.AllowNextStage {
		// 明确策略命中属于本地请求拒绝，不能被记成平台故障或上游账号错误。
		if decision.Prompt != nil && decision.Prompt.Kind == securityaudit.DecisionBlock {
			c.Set("ops_prompt_audit_blocked", true)
			service.MarkOpsClientBusinessLimited(c, service.OpsClientBusinessLimitedReasonLocalPolicyDenied)
			service.MarkOpsStreamFailure(c, "invalid_request_error", decision.ErrorCode, decision.ClientMessage, decision.HTTPStatus)
		}
		return &service.ContentModerationDecision{
			Blocked: true, Flagged: decision.Kind == securityaudit.DecisionBlock,
			StatusCode: decision.HTTPStatus, ErrorCode: decision.ErrorCode, Message: decision.ClientMessage,
		}
	}
	return nil
}

// promptSidebandAudit 只阻断尚未发送的文本事件；音频本体不被宣称为已完成文本审核。
func (h *OpenAIGatewayHandler) promptSidebandAudit(c *gin.Context, apiKey *service.APIKey, model string, conn *coderws.Conn) func(context.Context, []byte) error {
	return func(ctx context.Context, body []byte) error {
		if h.promptAudit == nil {
			return nil
		}
		subject, _ := middleware.GetAuthSubjectFromContext(c)
		input := buildContentModerationInput(c, apiKey, subject, "openai_live", model, body)
		decision := runPromptAudit(c, input, h.promptAudit, ctx)
		if decision == nil || !decision.Blocked {
			return nil
		}
		code := contentModerationErrorCode(decision)
		service.MarkOpsStreamFailure(c, "prompt_audit", code, decision.Message, decision.StatusCode)
		payload, _ := json.Marshal(gin.H{"type": "error", "error": gin.H{"code": code, "message": decision.Message}})
		_ = conn.Write(ctx, coderws.MessageText, payload)
		return errors.New(code)
	}
}
