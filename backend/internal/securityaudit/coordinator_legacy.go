package securityaudit

import (
	"context"

	"github.com/TokenFlux/TokenRouter/internal/service"
)

type LegacyModerationAdapter struct {
	service *service.ContentModerationService
}

func NewLegacyModerationAdapter(svc *service.ContentModerationService) LegacyEngine {
	return &LegacyModerationAdapter{service: svc}
}

func (a *LegacyModerationAdapter) Check(ctx context.Context, req Request) (*LegacyDecision, error) {
	if a == nil || a.service == nil {
		return nil, nil
	}
	decision, err := a.service.Check(ctx, service.ContentModerationCheckInput{
		RequestID: req.RequestID, UserID: req.UserID, UserEmail: req.UserEmail,
		APIKeyID: req.APIKeyID, APIKeyName: req.APIKeyName, GroupID: cloneInt64Ptr(req.GroupID),
		GroupName: req.GroupName, Endpoint: req.Endpoint, Provider: req.Provider,
		// 提示词豁免仅影响本引擎，TokenRouter 独立内容审核规则继续生效。
		Model: req.Model, Protocol: req.Protocol, Body: req.Body,
		BillingUserID: req.BillingUserID, TeamID: cloneInt64Ptr(req.TeamID),
	})
	if err != nil || decision == nil {
		return nil, err
	}
	errorCode := "content_policy_violation"
	return &LegacyDecision{
		Allowed: decision.Allowed, Blocked: decision.Blocked, Flagged: decision.Flagged,
		Message: decision.Message, StatusCode: decision.StatusCode,
		ErrorCode: errorCode, Action: decision.Action,
	}, nil
}
