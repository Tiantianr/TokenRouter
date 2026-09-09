package routes

import (
	"github.com/TokenFlux/TokenRouter/internal/handler"
	"github.com/TokenFlux/TokenRouter/internal/securityaudit"
	"github.com/TokenFlux/TokenRouter/internal/server/middleware"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 所有新入口必须继承真实管理路由组的认证链，不能从网关匿名路径访问。
func TestPromptAuditAdminRoutesRequireAdmin(t *testing.T) {
	router := gin.New()
	h := &handler.Handlers{Admin: &handler.AdminHandlers{PromptAudit: securityaudit.NewPromptAdminHandler(nil)}}
	auth := middleware.AdminAuthMiddleware(func(c *gin.Context) {
		if c.GetHeader("Authorization") == "" {
			c.AbortWithStatus(401)
		} else {
			c.AbortWithStatus(403)
		}
	})
	RegisterAdminRoutes(router.Group("/api/v1"), h, auth, middleware.AuditLogMiddleware(func(c *gin.Context) { c.Next() }), middleware.StepUpAuthMiddleware(func(c *gin.Context) { c.Next() }), nil)
	for _, route := range []string{"/config", "/sessions", "/events", "/events/1", "/events/1/context", "/runtime"} {
		for _, authenticated := range []bool{false, true} {
			request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/prompt-audit"+route, nil)
			want := 401
			if authenticated {
				request.Header.Set("Authorization", "Bearer ordinary-user")
				want = 403
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, request)
			require.Equal(t, want, w.Code, route)
		}
	}
}
