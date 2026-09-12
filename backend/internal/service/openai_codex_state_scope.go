package service

import (
	"crypto/sha256"
	"fmt"
	"strings"

	coderws "github.com/coder/websocket"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const codexClientIdentityContextKey = "openai_codex_original_client_identity"
const codexWSClientIdentityContextKey = "openai_codex_ws_client_identity"

// validateCodexWSThread 不允许在同一入站连接中切换执行线程，以免自动续链混入
// 上一线程的历史；子代理应使用自己的连接，省略 thread 的帧继承首帧。
func validateCodexWSThread(c *gin.Context, body []byte) error {
	if c == nil {
		return nil
	}
	if raw, ok := c.Get(codexWSClientIdentityContextKey); ok {
		if initial, ok := raw.(codexClientIdentity); ok && initial.thread() != "" {
			current := readCodexClientIdentity(nil, body).thread()
			if current != "" && current != initial.thread() {
				return NewOpenAIWSClientCloseError(coderws.StatusPolicyViolation, "thread changed; reconnect for a different thread", nil)
			}
		}
	}
	return nil
}

// stageCodexClientIdentity 保存投影前的身份，状态隔离不能使用账号固定 session。
func stageCodexClientIdentity(c *gin.Context, body []byte) {
	if c != nil {
		c.Set(codexClientIdentityContextKey, readCodexClientIdentity(codexRequestHeaders(c), body))
	}
}

func stagedCodexClientIdentity(c *gin.Context) codexClientIdentity {
	if c != nil {
		if raw, ok := c.Get(codexClientIdentityContextKey); ok {
			if source, ok := raw.(codexClientIdentity); ok {
				return source
			}
		}
	}
	return readCodexClientIdentity(codexRequestHeaders(c), nil)
}

// codexExecutionScope 跨账号调度仍保持同一用户线程；不同子线程不会相互抢占。
func codexExecutionScope(c *gin.Context, source codexClientIdentity) string {
	thread := source.thread()
	if thread == "" {
		thread = source.session()
	}
	if thread == "" {
		thread = source.promptCacheKey
	}
	if thread == "" {
		return ""
	}
	return fmt.Sprintf("exec-v2:%x", sha256.Sum256([]byte(fmt.Sprintf("%d\x00%d\x00%s", getOpenAIGroupIDFromContext(c), getAPIKeyIDFromContext(c), thread))))
}

// codexStateOwner 包含凭据所有者和固定身份配置。刷新 OAuth token 不改变命名空间，
// 修改 seed、收敛模式或保存/禁用 session 后则不再读取旧配置的连接状态。
func codexStateOwner(account *Account) string {
	if account == nil {
		return ""
	}
	seed, _ := codexFingerprintSeed(account.Extra)
	namespace := codexAccountIdentityNamespace(account)
	if namespace == "" {
		namespace = fmt.Sprintf("account:%d", account.ID)
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s", namespace, account.GetCodexFingerprintMode(), seed, configuredCodexSessionID(account), resolveConvergedInstallationID(account, seed)))))
}

func codexWSStateScopeForExecution(account *Account, execution string) string {
	return fmt.Sprintf("ws2:%x", sha256.Sum256([]byte(codexStateOwner(account)+"\x00"+execution)))
}

// 标准 Responses 客户端可能只使用 previous_response_id 而不发送 Codex 线程。
// 这类请求按已认证 Key 保留池内复用，不能随机换作用域而破坏合法续链。
func codexUserExecutionScope(c *gin.Context) string {
	if key := getAPIKeyIDFromContext(c); key > 0 {
		return fmt.Sprintf("key-v2:%d:%d", getOpenAIGroupIDFromContext(c), key)
	}
	return ""
}

// @project-doc docs/architecture/account_scheduling_and_cache.md#websocket_execution_isolation
func codexWSStateScope(c *gin.Context, account *Account) string {
	execution := codexExecutionScope(c, stagedCodexClientIdentity(c))
	if execution == "" {
		execution = codexUserExecutionScope(c)
	}
	if execution == "" {
		// 连已认证用户都不可识别的内部请求，仅与本次重试共享连接。
		const key = "openai_codex_anonymous_execution"
		if c != nil {
			execution = c.GetString(key)
		}
		if execution == "" {
			execution = uuid.NewString()
			if c != nil {
				c.Set(key, execution)
			}
		}
	}
	if snapshot := stagedCodexAccountTurn(c, account); snapshot != nil {
		execution += "\x00fixed-turn:" + snapshot.value.TurnID
	}
	return codexWSStateScopeForExecution(codexAccountIdentitySource(c, account), execution)
}

// codexClientTurnKey 仅在真实 turn 可识别时允许本连接的重连复用状态。
func codexClientTurnKey(c *gin.Context) string {
	source := stagedCodexClientIdentity(c)
	turn := source.text("turn_id", "turn-id")
	if turn == "" {
		return ""
	}
	return codexExecutionScope(c, source) + "\x00" + turn
}

func openAICodexTurnStateValueKey(state string) string {
	return fmt.Sprintf("state-v2:%x", sha256.Sum256([]byte(strings.TrimSpace(state))))
}
