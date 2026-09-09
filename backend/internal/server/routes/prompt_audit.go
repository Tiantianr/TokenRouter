package routes

import (
	"github.com/TokenFlux/TokenRouter/internal/handler"
	"github.com/gin-gonic/gin"
)

// registerPromptAuditRoutes 继承管理组认证和操作审计，读取证据也禁止缓存。
func registerPromptAuditRoutes(admin *gin.RouterGroup, h *handler.Handlers) {
	if h.Admin.PromptAudit == nil {
		return
	}
	p := admin.Group("/prompt-audit")
	p.Use(func(c *gin.Context) { c.Header("Cache-Control", "no-store"); c.Next() })
	a := h.Admin.PromptAudit
	p.GET("/config", a.GetConfig)
	p.PUT("/config", a.UpdateConfig)
	p.GET("/pass-retention", a.GetPassRetention)
	p.PUT("/pass-retention", a.UpdatePassRetention)
	p.POST("/endpoints/probe", a.ProbeEndpoint)
	p.GET("/runtime", a.GetRuntime)
	p.GET("/events", a.ListEvents)
	p.GET("/sessions", a.ListSessions)
	p.GET("/events/:id", a.GetEvent)
	p.POST("/events/:id/analyze", a.AnalyzeEvent)
	p.GET("/events/:id/context", a.DownloadEventContext)
	p.DELETE("/events/:id", a.DeleteEvent)
	p.POST("/events/batch-delete", a.BatchDelete)
	p.POST("/events/delete-preview", a.DeletePreview)
	p.POST("/events/delete-by-filter", a.DeleteByFilter)
}
