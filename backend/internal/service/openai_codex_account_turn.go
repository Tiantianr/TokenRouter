package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	infraerrors "github.com/TokenFlux/TokenRouter/internal/pkg/errors"
	"github.com/TokenFlux/TokenRouter/internal/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CodexAccountTurnExtraKey 只经专用会话接口和成功响应 CAS 修改，不接受通用账号导入。
const CodexAccountTurnExtraKey = "codex_account_turn"
const codexAccountTurnContextKey = "codex_account_turn_snapshot"

// CodexAccountTurnConfiguration 的 revision 同时保护管理员保存和并发响应轮换。
// @project-doc docs/interfaces/openai_upstream.md#codex_account_turn_reuse
type CodexAccountTurnConfiguration struct {
	Enabled   bool   `json:"enabled"`
	TurnID    string `json:"turn_id"`
	TurnState string `json:"turn_state"`
	Revision  string `json:"revision"`
	Identity  string `json:"identity"`
	UpdatedAt string `json:"updated_at"`
}

// CodexSessionCASRepository 在同一数据库写入中比较身份、凭据和状态版本。
type CodexSessionCASRepository interface {
	CompareAndSwapCodexSession(context.Context, *Account, map[string]any) (bool, error)
}

func storedCodexAccountTurn(account *Account) CodexAccountTurnConfiguration {
	var value CodexAccountTurnConfiguration
	if account != nil {
		data, _ := json.Marshal(account.Extra[CodexAccountTurnExtraKey])
		_ = json.Unmarshal(data, &value)
	}
	return value
}

// 绑定稳定 OAuth 身份而非短期 access token，正常刷新不会使已保存状态失效。
func codexAccountTurnIdentity(account *Account) string {
	if account == nil {
		return ""
	}
	return openAICodexTurnStateValueKey(fmt.Sprintf("%d\x00%s\x00%s\x00%s", account.ID, account.Type, codexStateOwner(account), account.GetCredential("email")))
}

func effectiveCodexAccountTurn(account *Account) CodexAccountTurnConfiguration {
	value := storedCodexAccountTurn(account)
	if !supportsCodexSessionOverride(account) || value.Identity != codexAccountTurnIdentity(account) {
		value.Enabled, value.TurnState = false, ""
	}
	return value
}

// InvalidateChangedCodexAccountTurn 在普通账号编辑时废弃旧身份状态，避免关闭后再开启恢复旧值。
func InvalidateChangedCodexAccountTurn(account *Account, extra map[string]any) {
	copy := *account
	copy.Extra = extra
	stored := storedCodexAccountTurn(&copy)
	if stored.Enabled && !effectiveCodexAccountTurn(&copy).Enabled {
		extra[CodexAccountTurnExtraKey] = CodexAccountTurnConfiguration{Revision: uuid.NewString()}
	}
}

func validCodexTurnState(state string) bool {
	// 不透明状态不裁剪、不解码；拒绝所有不合法的 HTTP 字段值。
	if state == "" || len(state) > 8192 || strings.TrimSpace(state) != state {
		return false
	}
	for _, ch := range []byte(state) {
		if ch < 32 || ch == 127 {
			return false
		}
	}
	return true
}

type codexAccountTurnSnapshot struct {
	account *Account
	value   CodexAccountTurnConfiguration
}

// prepareCodexAccountTurn 仅在原生 Responses 入口调用；每次 attempt 清理旧账号快照。
func (s *OpenAIGatewayService) prepareCodexAccountTurn(ctx context.Context, c *gin.Context, account *Account, connectionSnapshot ...bool) error {
	if c == nil {
		return nil
	}
	c.Set(codexAccountTurnContextKey, (*codexAccountTurnSnapshot)(nil))
	if isOpenAIResponsesCompactPath(c) || isOpenAICompatMessagesBridgeContext(c) {
		return nil
	}
	if c.Request != nil && (strings.Contains(c.Request.URL.Path, "/messages") || strings.Contains(c.Request.URL.Path, "/chat/completions")) {
		return nil
	}
	source := codexAccountIdentitySource(c, account)
	if source == nil || source.Extra[CodexAccountTurnExtraKey] == nil {
		return nil
	}
	// 状态轮换不依赖调度快照刷新速度，后续请求从数据库读取最新版本。
	if s.accountRepo != nil {
		fresh, err := s.accountRepo.GetByID(ctx, source.ID)
		if err != nil {
			return err
		}
		frozen := len(connectionSnapshot) > 0 && connectionSnapshot[0]
		oldTurn, newTurn := effectiveCodexAccountTurn(source), effectiveCodexAccountTurn(fresh)
		// 已有 WS 的 turn 身份不能与握手中途分裂；状态轮换只刷新同一身份。
		if !frozen || (codexAccountTurnIdentity(fresh) == codexAccountTurnIdentity(source) && oldTurn.Enabled == newTurn.Enabled && oldTurn.TurnID == newTurn.TurnID) {
			if codexAccountTurnIdentity(fresh) != codexAccountTurnIdentity(source) {
				return nil
			}
			source = fresh
		}
	}
	value := effectiveCodexAccountTurn(source)
	if value.Enabled && validCodexTurnState(value.TurnState) {
		c.Set(codexAccountTurnContextKey, &codexAccountTurnSnapshot{account: source, value: value})
	}
	return nil
}

func stagedCodexAccountTurn(c *gin.Context, account *Account) *codexAccountTurnSnapshot {
	if c == nil || account == nil {
		return nil
	}
	raw, _ := c.Get(codexAccountTurnContextKey)
	snapshot, _ := raw.(*codexAccountTurnSnapshot)
	if snapshot == nil || (snapshot.account.ID != account.ID && (account.ParentAccountID == nil || *account.ParentAccountID != snapshot.account.ID)) {
		return nil
	}
	return snapshot
}

func applyCodexAccountTurnIDs(c *gin.Context, account *Account, ids *codexFingerprintIDs) {
	if snapshot := stagedCodexAccountTurn(c, account); snapshot != nil && ids != nil {
		// 保存的 UUID 就是实际出站值，不再按客户端 Key 二次投影。
		for _, key := range []string{"root_turn_id", "parent_turn_id"} {
			if ids.lineage[key] == ids.turnID {
				ids.lineage[key] = snapshot.value.TurnID
			}
		}
		ids.turnID = snapshot.value.TurnID
		ids.fixedTurn = true
	}
}

func applyCodexAccountTurnHeaders(c *gin.Context, account *Account, headers http.Header) {
	if snapshot := stagedCodexAccountTurn(c, account); snapshot != nil {
		headers.Set("turn-id", snapshot.value.TurnID)
		headers.Set("turn_id", snapshot.value.TurnID)
		headers.Set(openAICodexTurnStateHeader, snapshot.value.TurnState)
	}
}

// rotateCodexAccountTurn 只能在完整成功且客户端未取消之后调用；失败不改变响应结果。
func (s *OpenAIGatewayService) rotateCodexAccountTurn(ctx context.Context, snapshot *codexAccountTurnSnapshot, state string) {
	if snapshot == nil || ctx.Err() != nil || !validCodexTurnState(state) || state == snapshot.value.TurnState {
		return
	}
	repo, ok := s.accountRepo.(CodexSessionCASRepository)
	if !ok {
		return
	}
	next := snapshot.value
	next.TurnState, next.Revision, next.UpdatedAt = state, uuid.NewString(), time.Now().UTC().Format(time.RFC3339Nano)
	updateCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, err := repo.CompareAndSwapCodexSession(updateCtx, snapshot.account, map[string]any{CodexAccountTurnExtraKey: next}); err != nil {
		// 不记录不透明状态或凭据；持久化失败只影响下一请求使用的版本。
		logger.LegacyPrintf("service.openai_gateway", "Codex account turn update failed: account=%d", snapshot.account.ID)
	}
}

func codexSessionConflict() error {
	return infraerrors.Conflict("CODEX_SESSION_CHANGED", "Account identity or turn state changed; reload and test again before saving")
}
