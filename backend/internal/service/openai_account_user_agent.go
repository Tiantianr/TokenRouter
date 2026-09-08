package service

import (
	"strings"

	infraerrors "github.com/TokenFlux/TokenRouter/internal/pkg/errors"
	"github.com/TokenFlux/TokenRouter/internal/pkg/openai"
)

// normalizeOpenAIAccountUserAgent 只校验管理端写入，不改变出站身份的选择优先级。
// @project-doc docs/operations/upstream_transport_security.md#account_codex_user_agent
func normalizeOpenAIAccountUserAgent(account *Account) error {
	if account == nil || account.Platform != PlatformOpenAI || account.Type != AccountTypeOAuth || account.IsCredentialShadow() {
		return nil
	}
	raw, exists := account.Credentials["user_agent"]
	if !exists {
		return nil
	}
	invalid := func() error {
		return infraerrors.BadRequest("OPENAI_ACCOUNT_USER_AGENT_INVALID", "user_agent must be a Codex User-Agent with an X.Y.Z version and at most 1024 printable ASCII characters")
	}
	ua, ok := raw.(string)
	if !ok || len(ua) > 1024 {
		return invalid()
	}
	// 先拒绝控制字符，再去除首尾空格，避免换行被 TrimSpace 隐藏。
	for i := 0; i < len(ua); i++ {
		if ua[i] < 0x20 || ua[i] > 0x7e {
			return invalid()
		}
	}
	ua = strings.TrimSpace(ua)
	if ua == "" {
		delete(account.Credentials, "user_agent")
		return nil
	}
	if _, _, ok := openai.PairCodexClientIdentity(ua); !ok {
		return invalid()
	}
	if _, ok := openai.ParseCodexEngineVersion(ua); !ok {
		return invalid()
	}
	account.Credentials["user_agent"] = ua
	return nil
}
