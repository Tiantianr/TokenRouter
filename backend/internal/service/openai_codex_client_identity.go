package service

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"
)

// codexClientIdentity 只读取原始身份小对象。当前帧优先于建连头，不能从已经
// 账号隔离的 body 再次派生，否则同一客户端在 HTTP 和 WS 上会得到不同身份。
type codexClientIdentity struct {
	body, embedded, header gjson.Result
	headers                http.Header
	promptCacheKey         string
}

func readCodexClientIdentity(headers http.Header, body []byte) codexClientIdentity {
	metadata := gjson.GetBytes(body, "client_metadata")
	return codexClientIdentity{
		body: metadata, embedded: gjson.Parse(metadata.Get(openAIWSTurnMetadataHeader).String()),
		header: gjson.Parse(headers.Get(openAIWSTurnMetadataHeader)), headers: headers,
		promptCacheKey: codexIdentityString(gjson.GetBytes(body, "prompt_cache_key")),
	}
}

func codexIdentityString(value gjson.Result) string {
	if value.Type == gjson.String {
		return strings.TrimSpace(value.Str)
	}
	return ""
}

// 顶层 metadata 用字符串，内嵌 JSON 可用数值；读取整数时兼容两种表示，
// 保留数字原文后再校验范围，避免经过 float64 丢失精度。
func codexIdentityIntegerText(value gjson.Result) string {
	if value.Type == gjson.Number {
		return value.Raw
	}
	return codexIdentityString(value)
}

func (s codexClientIdentity) value(names ...string) gjson.Result {
	for _, metadata := range []gjson.Result{s.body, s.embedded} {
		for _, name := range names {
			if value := metadata.Get(name); value.Exists() && value.Type != gjson.Null {
				return value
			}
		}
	}
	for _, name := range names {
		if value := s.header.Get(name); value.Exists() && value.Type != gjson.Null {
			return value
		}
	}
	return gjson.Result{}
}

func (s codexClientIdentity) text(names ...string) string {
	for _, metadata := range []gjson.Result{s.body, s.embedded} {
		for _, name := range names {
			if value := codexIdentityString(metadata.Get(name)); value != "" {
				return value
			}
		}
	}
	for _, name := range names {
		if value := strings.TrimSpace(s.headers.Get(name)); value != "" {
			return value
		}
	}
	for _, name := range names {
		if value := codexIdentityString(s.header.Get(name)); value != "" {
			return value
		}
	}
	return ""
}

func (s codexClientIdentity) session() string { return s.text("session-id", "session_id") }

func (s codexClientIdentity) thread() string {
	for _, metadata := range []gjson.Result{s.body, s.embedded} {
		for _, name := range []string{"thread-id", "thread_id"} {
			if thread := codexIdentityString(metadata.Get(name)); thread != "" {
				return thread
			}
		}
		for _, name := range []string{"x-codex-window-id", "window_id"} {
			if thread, _, ok := splitCodexWindowID(codexIdentityString(metadata.Get(name))); ok {
				return thread
			}
		}
	}
	if thread := s.text("thread-id", "thread_id"); thread != "" {
		return thread
	}
	if thread, _, ok := splitCodexWindowID(s.text("x-codex-window-id", "window_id")); ok {
		return thread
	}
	return ""
}

// splitCodexWindowID 保留复合窗口的序号；异常值不参与身份推导。
func splitCodexWindowID(value string) (string, string, bool) {
	thread, number, ok := strings.Cut(strings.TrimSpace(value), ":")
	if !ok || thread == "" || number == "" {
		return "", "", false
	}
	if _, err := strconv.ParseUint(number, 10, 32); err != nil {
		return "", "", false
	}
	return thread, number, true
}

func (s codexClientIdentity) windowNumber() (string, bool) {
	// 每一层的窗口与序号一起读取，避免当前帧序号被旧握手窗口覆盖。
	for _, metadata := range []gjson.Result{s.body, s.embedded} {
		for _, name := range []string{"x-codex-window-id", "window_id"} {
			if _, number, ok := splitCodexWindowID(codexIdentityString(metadata.Get(name))); ok {
				return number, true
			}
		}
		if raw := codexIdentityIntegerText(metadata.Get("window_number")); raw != "" {
			if n, err := strconv.ParseUint(raw, 10, 32); err == nil {
				return strconv.FormatUint(n, 10), true
			}
		}
	}
	if _, number, ok := splitCodexWindowID(s.headers.Get("x-codex-window-id")); ok {
		return number, true
	}
	if _, number, ok := splitCodexWindowID(codexIdentityString(s.header.Get("window_id"))); ok {
		return number, true
	}
	if raw := codexIdentityIntegerText(s.header.Get("window_number")); raw != "" {
		if n, err := strconv.ParseUint(raw, 10, 32); err == nil {
			return strconv.FormatUint(n, 10), true
		}
	}
	return "0", false
}

// resolveCodexFingerprintIDsForTurn 使用原始线程和回合关系补全现有收敛模式。
// 没有客户端 turn 时仍逐请求生成；有 turn 时稳定映射，工具续轮与父子引用同源。
// @project-doc docs/interfaces/openai_upstream.md#codex_identity_projection
func resolveCodexFingerprintIDsForTurn(account *Account, headers http.Header, body []byte, apiKeyID int64) *codexFingerprintIDs {
	if account == nil {
		return nil
	}
	source := readCodexClientIdentity(headers, body)
	thread := source.thread()
	if thread == "" {
		thread = source.session()
	}
	ids := resolveCodexFingerprintIDs(account, thread, account.GetCodexFingerprintMode())
	if ids == nil || ids.mode == codexFingerprintDevice {
		return ids
	}
	seed, _ := codexFingerprintSeed(account.Extra)
	projectThread := func(raw string) string {
		if ids.mode == codexFingerprintFull {
			return ids.sessionID
		}
		return resolveConvergedThreadID(seed, raw)
	}
	projectTurn := func(raw string) string {
		return scopeCodexAccountIdentityValue(account, apiKeyID, "turn", raw)
	}
	if turn := source.text("turn_id", "turn-id"); turn != "" {
		ids.turnID = projectTurn(turn)
	}
	ids.lineage = make(map[string]any)
	for _, name := range []string{"root_turn_id", "parent_turn_id"} {
		if raw := source.text(name); raw != "" {
			ids.lineage[name] = projectTurn(raw)
		}
	}
	if parent := source.text("parent_thread_id", "x-codex-parent-thread-id"); parent != "" {
		ids.lineage["parent_thread_id"] = projectThread(parent)
		ids.lineage["x-codex-parent-thread-id"] = projectThread(parent)
	}
	if raw := source.text("forked_from_thread_id"); raw != "" {
		ids.lineage["forked_from_thread_id"] = projectThread(raw)
	}
	if raw := source.text("context_window_id"); raw != "" {
		ids.lineage["context_window_id"] = scopeCodexAccountIdentityValue(account, apiKeyID, "context-window", raw)
	}
	if key := codexIdentityString(gjson.GetBytes(body, "prompt_cache_key")); key != "" {
		if prefix, parent, ok := strings.Cut(key, ":"); ok && prefix != "" && len(prefix) <= 64 {
			if id, err := uuid.Parse(parent); err == nil && id.String() == parent {
				ids.scopedCacheKey = scopeCodexAccountIdentityValue(account, apiKeyID, "prompt-cache", key)
				ids.convergedCacheKey = prefix + ":" + projectThread(parent)
			}
		}
	}
	number, known := source.windowNumber()
	ids.windowID = ids.threadID + ":" + number
	if known {
		n, _ := strconv.ParseUint(number, 10, 32)
		ids.lineage["window_number"] = n
	}
	if raw := codexIdentityIntegerText(source.value("turn_started_at_unix_ms")); raw != "" {
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n > 0 {
			ids.turnStartedAtUnixMs = n
		}
	}
	return ids
}

func codexFingerprintMetadataFields(ids *codexFingerprintIDs) map[string]any {
	fields := map[string]any{
		"installation_id": ids.installationID, "session_id": ids.sessionID,
		"thread_id": ids.threadID, "turn_id": ids.turnID, "window_id": ids.windowID,
		"turn_started_at_unix_ms": ids.turnStartedAtUnixMs,
	}
	for name, value := range ids.lineage {
		fields[name] = value
	}
	return fields
}

// 只同步已存在的兼容别名，避免保留与新 canonical 字段冲突的旧身份。
func rewriteCodexIdentityAliases(metadata, fields map[string]any) {
	for alias, canonical := range map[string]string{
		"session-id": "session_id", "thread-id": "thread_id", "turn-id": "turn_id",
		"window-id": "window_id", "x-codex-window-id": "window_id", "x-client-request-id": "thread_id",
		"x-codex-parent-thread-id": "parent_thread_id", "x-codex-installation-id": "installation_id",
	} {
		if _, exists := metadata[alias]; exists {
			if value, ok := fields[canonical]; ok {
				metadata[alias] = value
			}
		}
	}
}

// codexIdentityBodyForMap 只序列化 metadata 小对象，原始 input 不参与解析或重编码。
func codexIdentityBodyForMap(body map[string]any) []byte {
	raw, _ := json.Marshal(map[string]any{"client_metadata": body["client_metadata"]})
	return raw
}

func codexRequestHeaders(c *gin.Context) http.Header {
	if c != nil && c.Request != nil {
		if raw, ok := c.Get(codexWSClientIdentityContextKey); ok {
			if source, ok := raw.(codexClientIdentity); ok {
				// 后续帧省略线程时沿用首帧的真实线程，不回退到较旧的握手值。
				h := c.Request.Header.Clone()
				for name, value := range map[string]string{"thread-id": source.thread(), "session-id": source.session()} {
					if value != "" {
						h.Set(name, value)
					}
				}
				return h
			}
		}
		return c.Request.Header
	}
	return nil
}
