package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"maps"
	"strings"

	infraerrors "github.com/TokenFlux/TokenRouter/internal/pkg/errors"
)

const OpenAIOAuthRejectExternalHistoryKey = "openai_oauth_reject_external_history"

var (
	ErrOpenAIExternalHistory    = errors.New("当前没有可接续此历史对话的账号，请新建对话后重试。")
	ErrOpenAIHistoryUnavailable = errors.New("conversation ownership is temporarily unavailable, please retry later")
	ErrOpenAIHistoryConflict    = errors.New("conversation routing changed concurrently, please retry the request")
)

// 仅存路由元数据。失效身份与记录缺失不同，旧Redis记录不得恢复失效归属。
type OpenAIConversationBinding struct {
	UserID                   int64
	ScopeGroupID             int64
	Type                     string
	Key                      string
	AccountID                int64
	CredentialOwnerAccountID int64
	APIKeyID                 int64
	OAuthAccountID           string
	OAuthUserID              string
	Revision                 int64
	Valid                    bool
	Confirmed                bool
}

// 归属与账号数据共同持久化，不通过短期缓存补造。
type OpenAIConversationBindingRepository interface {
	GetOpenAIConversationBinding(ctx context.Context, userID, scopeGroupID int64, kind, key string) (*OpenAIConversationBinding, error)
	SaveOpenAIConversationBinding(ctx context.Context, binding *OpenAIConversationBinding, expectedRevision int64) (*OpenAIConversationBinding, error)
}

func (a *Account) IsOpenAIOAuthRejectExternalHistoryEnabled() bool {
	if a == nil || !a.IsOpenAIOAuth() {
		return false
	}
	raw, exists := a.Extra[OpenAIOAuthRejectExternalHistoryKey]
	enabled, valid := raw.(bool)
	if exists && !valid {
		slog.Warn("history_policy_invalid", "account_id", a.ID)
	}
	return valid && enabled
}

func validateOpenAIHistoryExtra(extra map[string]any) error {
	if raw, exists := extra[OpenAIOAuthRejectExternalHistoryKey]; exists {
		if _, valid := raw.(bool); !valid {
			return infraerrors.BadRequest("OPENAI_EXTERNAL_HISTORY_INVALID", "openai_oauth_reject_external_history must be a boolean")
		}
	}
	return nil
}

func normalizeOpenAIHistoryExtra(platform, accountType string, extra map[string]any, current *Account) (map[string]any, error) {
	if platform != PlatformOpenAI || accountType != AccountTypeOAuth {
		return extra, nil
	}
	if err := validateOpenAIHistoryExtra(extra); err != nil {
		return nil, err
	}
	normalized := maps.Clone(extra)
	if normalized == nil {
		normalized = make(map[string]any)
	}
	if _, exists := normalized[OpenAIOAuthRejectExternalHistoryKey]; !exists {
		normalized[OpenAIOAuthRejectExternalHistoryKey] = current != nil && current.IsOpenAIOAuthRejectExternalHistoryEnabled()
	}
	return normalized, nil
}

func openAIConversationBindingKey(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])
}

func (s *OpenAIGatewayService) conversationBindingRepository() OpenAIConversationBindingRepository {
	if s == nil {
		return nil
	}
	repo, _ := s.accountRepo.(OpenAIConversationBindingRepository)
	return repo
}
