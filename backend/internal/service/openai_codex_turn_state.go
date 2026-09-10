package service

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// openAICodexTurnStateHeader 是 Codex 的回合状态头。上游在响应头中签发该
// 不透明值，客户端会在同一回合的后续请求中原样带回。
const openAICodexTurnStateHeader = "x-codex-turn-state"

// openAICodexTurnStateOrigin 按具体状态值记录来源，不因同一 session 的并发响应
// 覆盖另一条线程的记录。内存表只保存状态哈希与作用域，不保存原始状态。
type openAICodexTurnStateOrigin struct {
	accountID int64
	owner     string
	execution string
	turn      string
	expiresAt time.Time
}

// openAICodexTurnStateSeed 优先使用原始用户线程；标准客户端缺少线程时按认证 Key
// 追踪。不能识别用户或线程时保持未知来源语义。
func openAICodexTurnStateSeed(c *gin.Context) string {
	if execution := codexExecutionScope(c, stagedCodexClientIdentity(c)); execution != "" {
		return execution
	}
	return codexUserExecutionScope(c)
}

// relayOpenAICodexTurnState 将上游状态显式写回客户端，并只在响应真正会送达
// 客户端时记录签发账号。上游缺失时主动清理可能残留的上一次尝试状态。
func (s *OpenAIGatewayService) relayOpenAICodexTurnState(c *gin.Context, account *Account, upstream http.Header) {
	if c == nil || c.Writer == nil {
		return
	}
	canonical := http.CanonicalHeaderKey(openAICodexTurnStateHeader)
	state := extractOpenAICodexTurnState(upstream)
	if state == "" {
		c.Writer.Header().Del(canonical)
		return
	}
	c.Writer.Header().Set(canonical, state)
	s.noteOpenAICodexTurnStateProvenance(c, account, state)
}

// stageOpenAICodexTurnState 暂存首输出守卫中的状态头。守卫阶段尚可能故障转移，
// 因此这里不能记录签发账号，真正提交时才由对应函数记录。
func stageOpenAICodexTurnState(dst *http.Header, upstream http.Header) {
	if dst == nil {
		return
	}
	canonical := http.CanonicalHeaderKey(openAICodexTurnStateHeader)
	state := extractOpenAICodexTurnState(upstream)
	if state == "" {
		if *dst != nil {
			dst.Del(canonical)
		}
		return
	}
	if *dst == nil {
		*dst = http.Header{}
	}
	dst.Set(canonical, state)
}

// noteStagedOpenAICodexTurnStateCommitted 仅在暂存头实际写给客户端后记录来源，
// 避免被首输出超时丢弃的尝试污染后续回放判断。
func (s *OpenAIGatewayService) noteStagedOpenAICodexTurnStateCommitted(c *gin.Context, account *Account, staged http.Header) {
	if staged == nil || strings.TrimSpace(staged.Get(openAICodexTurnStateHeader)) == "" {
		return
	}
	s.noteOpenAICodexTurnStateProvenance(c, account, extractOpenAICodexTurnState(staged))
}

func extractOpenAICodexTurnState(upstream http.Header) string {
	if upstream == nil {
		return ""
	}
	return strings.TrimSpace(upstream.Get(openAICodexTurnStateHeader))
}

// noteOpenAICodexTurnStateProvenance 记录这一不透明状态的实际签发作用域。
func (s *OpenAIGatewayService) noteOpenAICodexTurnStateProvenance(c *gin.Context, account *Account, state string) {
	if s == nil || account == nil || account.ID <= 0 {
		return
	}
	seed := openAICodexTurnStateSeed(c)
	if seed == "" || strings.TrimSpace(state) == "" {
		return
	}
	s.openaiCodexTurnStateOrigins.Store(openAICodexTurnStateValueKey(state), openAICodexTurnStateOrigin{
		accountID: account.ID,
		owner:     codexStateOwner(codexAccountIdentitySource(c, account)),
		execution: seed,
		turn:      codexClientTurnKey(c),
		expiresAt: time.Now().Add(s.openAIWSSessionStickyTTL()),
	})
	s.sweepOpenAICodexTurnStateOrigins()
}

// guardOpenAICodexTurnStateEcho 拒绝已知的跨用户、线程、账号、配置或 turn 回带。
// 未知来源的客户端值仍透传；缓存不自动注入任何跨请求状态。
// @project-doc docs/interfaces/openai_upstream.md#codex_ws_turn_state
func (s *OpenAIGatewayService) guardOpenAICodexTurnStateEcho(c *gin.Context, account *Account, h http.Header) {
	if s == nil || h == nil || account == nil {
		return
	}
	if strings.TrimSpace(h.Get(openAICodexTurnStateHeader)) == "" {
		return
	}
	key := openAICodexTurnStateValueKey(h.Get(openAICodexTurnStateHeader))
	raw, ok := s.openaiCodexTurnStateOrigins.Load(key)
	if !ok {
		return
	}
	origin, ok := raw.(openAICodexTurnStateOrigin)
	if !ok {
		s.openaiCodexTurnStateOrigins.Delete(key)
		return
	}
	if !origin.expiresAt.IsZero() && time.Now().After(origin.expiresAt) {
		s.openaiCodexTurnStateOrigins.Delete(key)
		return
	}
	turn := codexClientTurnKey(c)
	if origin.owner != codexStateOwner(codexAccountIdentitySource(c, account)) || origin.execution != openAICodexTurnStateSeed(c) || (origin.turn != "" && turn != "" && origin.turn != turn) {
		h.Del(openAICodexTurnStateHeader)
	}
}

// sweepOpenAICodexTurnStateOrigins 每 256 次写入清扫一次过期记录，避免只依赖
// 读侧惰性删除造成会话来源表持续增长。
func (s *OpenAIGatewayService) sweepOpenAICodexTurnStateOrigins() {
	if s.openaiCodexTurnStateWrites.Add(1)%256 != 0 {
		return
	}
	now := time.Now()
	s.openaiCodexTurnStateOrigins.Range(func(key, value any) bool {
		origin, ok := value.(openAICodexTurnStateOrigin)
		if !ok || (!origin.expiresAt.IsZero() && now.After(origin.expiresAt)) {
			s.openaiCodexTurnStateOrigins.Delete(key)
		}
		return true
	})
}
