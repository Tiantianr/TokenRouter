package admin

import (
	"context"
	"strconv"

	"github.com/TokenFlux/TokenRouter/internal/pkg/response"
	"github.com/TokenFlux/TokenRouter/internal/service"
	"github.com/gin-gonic/gin"
)

type codexSessionAdminService interface {
	SetCodexSessionOverride(ctx context.Context, id int64, value service.CodexSessionOverride) (*service.Account, error)
}

// CodexSession 返回可操作性和当前生效 ID，不把账号 seed 暴露给浏览器。
func (h *AccountHandler) CodexSession(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid account ID")
		return
	}
	account, err := h.adminService.GetAccount(c.Request.Context(), id)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, service.CodexSessionConfig(account))
}

// SaveCodexSession 显式保存才改变正式请求使用的会话 ID。
func (h *AccountHandler) SaveCodexSession(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid account ID")
		return
	}
	var value service.CodexSessionOverride
	if err := c.ShouldBindJSON(&value); err != nil {
		response.BadRequest(c, "Invalid session configuration")
		return
	}
	svc, ok := h.adminService.(codexSessionAdminService)
	if !ok {
		response.Error(c, 500, "Codex session configuration unavailable")
		return
	}
	account, err := svc.SetCodexSessionOverride(c.Request.Context(), id, value)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, service.CodexSessionConfig(account))
}
