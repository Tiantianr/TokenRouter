package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/TokenFlux/TokenRouter/internal/service"
	coderws "github.com/coder/websocket"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const opsOpenAIHistoryErrorKey = "ops_openai_history_error"

// 等待后再次验证，策略变化只否决当前候选，不消耗上游故障转移次数。
func (h *OpenAIGatewayHandler) acquireOpenAIHistoryAccountSlot(c *gin.Context, groupID *int64, sessionHash string, selection *service.AccountSelectionResult, stream bool, started *bool, log *zap.Logger) (func(), bool, bool) {
	release, acquired := h.acquireResponsesAccountSlot(c, groupID, sessionHash, selection, stream, started, log)
	if !acquired {
		return release, false, false
	}
	if err := h.gatewayService.ValidateOpenAIHistoryTurn(c.Request.Context(), selection.Account); err != nil {
		if release != nil {
			release()
		}
		if errors.Is(err, service.ErrOpenAIExternalHistory) {
			return nil, false, true
		}
		h.handleOpenAIHistoryError(c, err, strings.Contains(c.Request.URL.Path, "messages"), *started)
		return nil, false, false
	}
	return release, true, false
}

func (h *OpenAIGatewayHandler) prepareOpenAIHistory(c *gin.Context, apiKey *service.APIKey, protocol string, body []byte, sessionHash string, anthropic bool, readOnly ...bool) bool {
	if openAICompatibleRequestPlatform(apiKey) != service.PlatformOpenAI {
		return true
	}
	if err := h.gatewayService.PrepareOpenAIHistoryRequest(c, protocol, body, sessionHash, readOnly...); err != nil {
		if !h.handleOpenAIHistoryError(c, err, anthropic, false) {
			if anthropic {
				h.anthropicErrorResponse(c, http.StatusBadRequest, "invalid_request_error", "Failed to classify conversation history")
			} else {
				h.errorResponse(c, http.StatusBadRequest, "invalid_request_error", "Failed to classify conversation history")
			}
		}
		return false
	}
	return true
}

func openAIHistoryErrorDetails(err error) (int, string, string, string, bool) {
	switch {
	case errors.Is(err, service.ErrOpenAIExternalHistory):
		return http.StatusBadRequest, "invalid_request_error", "external_history_not_allowed", service.ErrOpenAIExternalHistory.Error(), true
	case errors.Is(err, service.ErrOpenAIHistoryUnavailable):
		return http.StatusServiceUnavailable, "api_error", "conversation_ownership_unavailable", service.ErrOpenAIHistoryUnavailable.Error(), true
	case errors.Is(err, service.ErrOpenAIHistoryConflict):
		return http.StatusConflict, "invalid_request_error", "conversation_routing_conflict", service.ErrOpenAIHistoryConflict.Error(), true
	default:
		return 0, "", "", "", false
	}
}

func (h *OpenAIGatewayHandler) handleOpenAIHistoryError(c *gin.Context, err error, anthropic, streamStarted bool) bool {
	status, errType, code, message, ok := openAIHistoryErrorDetails(err)
	if !ok {
		return false
	}
	markOpenAIHistoryOpsError(c, status, errType, code, message)
	if anthropic {
		h.anthropicStreamingAwareError(c, status, errType, message, streamStarted)
	} else {
		h.handleStreamingAwareErrorWithCode(c, status, errType, code, message, streamStarted, false)
	}
	return true
}

func writeOpenAIHistoryWSError(c *gin.Context, ctx context.Context, conn *coderws.Conn, err error, reconnect bool) bool {
	status, errType, code, message, ok := openAIHistoryErrorDetails(err)
	if !ok {
		return false
	}
	if reconnect && errors.Is(err, service.ErrOpenAIExternalHistory) {
		code = "conversation_reconnect_required"
		message = "This account cannot continue the supplied history; reconnect to select another account."
	}
	markOpenAIHistoryOpsError(c, status, errType, code, message)
	payload, marshalErr := json.Marshal(gin.H{"type": "error", "error": gin.H{
		"type": errType, "code": code, "message": message,
	}})
	if marshalErr == nil {
		writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		_ = conn.Write(writeCtx, coderws.MessageText, payload)
	}
	return true
}

func markOpenAIHistoryOpsError(c *gin.Context, status int, errType, code, message string) {
	c.Set(opsOpenAIHistoryErrorKey, service.OpsStreamError{Code: code, Message: message})
	if isOpsOpenAIHistoryRejection(c, message) {
		service.MarkOpsClientBusinessLimited(c, service.OpsClientBusinessLimitedReasonLocalPolicyDenied)
	}
	// 已开始HTTP 200/101时仍保留逻辑失败状态，业务拒绝不计入可用性指标。
	service.MarkOpsStreamFailure(c, errType, code, message, status)
}

func isOpsOpenAIHistoryRejection(c *gin.Context, message string) bool {
	if c == nil {
		return false
	}
	value, _ := c.Get(opsOpenAIHistoryErrorKey)
	local, ok := value.(service.OpsStreamError)
	return ok && local.Message == message &&
		(local.Code == "external_history_not_allowed" || local.Code == "conversation_reconnect_required")
}
