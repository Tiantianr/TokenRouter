package securityaudit

import (
	"context"
	"time"

	infraerrors "github.com/TokenFlux/TokenRouter/internal/pkg/errors"
	"github.com/TokenFlux/TokenRouter/internal/pkg/response"
	"github.com/gin-gonic/gin"
)

// SessionSummary 只返回会话元数据，正文仍通过经过审计的事件详情和下载入口读取。
type SessionSummary struct {
	ID            int64     `json:"id"`
	UserID        int64     `json:"user_id"`
	SessionKey    string    `json:"session_key"`
	SessionSource string    `json:"session_source"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	EventCount    int64     `json:"event_count"`
	RiskCount     int64     `json:"risk_count"`
	EvidenceCount int64     `json:"evidence_count"`
}

type SessionPage struct {
	Items    []SessionSummary `json:"items"`
	Total    int64            `json:"total"`
	Page     int              `json:"page"`
	PageSize int              `json:"page_size"`
}

// ListSessions 按用户分页浏览真实会话，过期证据保留检测元数据且不再显示为可下载。
func (s *PromptService) ListSessions(ctx context.Context, userID *int64, page, pageSize int) (*SessionPage, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	result := &SessionPage{Items: []SessionSummary{}, Page: page, PageSize: pageSize}
	if err := s.repo.db.QueryRowContext(ctx, `SELECT count(*) FROM prompt_audit_sessions WHERE ($1::bigint IS NULL OR user_id=$1)`, userID).Scan(&result.Total); err != nil {
		return nil, err
	}
	rows, err := s.repo.db.QueryContext(ctx, `
	 SELECT s.id,s.user_id,s.session_key,s.session_source,s.last_seen_at,
	 (SELECT count(*) FROM prompt_audit_events e WHERE e.user_id=s.user_id AND e.session_key=s.session_key),
	 (SELECT count(*) FROM prompt_audit_events e WHERE e.user_id=s.user_id AND e.session_key=s.session_key AND e.decision IN ('flag','critical')),
	 (SELECT count(*) FROM prompt_audit_chat_records c WHERE c.session_id=s.id AND c.context_ciphertext IS NOT NULL AND (c.retention_until IS NULL OR c.retention_until>NOW()))
	 FROM prompt_audit_sessions s WHERE ($1::bigint IS NULL OR s.user_id=$1)
	 ORDER BY s.last_seen_at DESC,s.id DESC LIMIT $2 OFFSET $3`, userID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var item SessionSummary
		if err := rows.Scan(&item.ID, &item.UserID, &item.SessionKey, &item.SessionSource, &item.LastSeenAt, &item.EventCount, &item.RiskCount, &item.EvidenceCount); err != nil {
			return nil, err
		}
		result.Items = append(result.Items, item)
	}
	return result, rows.Err()
}

func (h *PromptAdminHandler) ListSessions(c *gin.Context) {
	userID, err := optionalPositiveInt64Query(c, "user_id")
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	page, err := positiveIntQuery(c, "page", 1, 100000)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	size, err := positiveIntQuery(c, "page_size", 20, 100)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	result, err := h.service.ListSessions(c.Request.Context(), userID, page, size)
	if err != nil {
		response.ErrorFrom(c, infraerrors.InternalServer("prompt_audit_sessions_unavailable", "会话记录暂时不可用"))
		return
	}
	response.Success(c, result)
}
