package service

import (
	"context"
	"maps"
	"strings"
	"time"

	infraerrors "github.com/TokenFlux/TokenRouter/internal/pkg/errors"
	"github.com/google/uuid"
)

const (
	codexSessionOverrideEnabledKey = "codex_session_override_enabled"
	codexSessionOverrideIDKey      = "codex_session_override_id"
	// CodexSessionTestOverrideKey 仅由管理员测试入口设置，不接受普通网关请求覆盖。
	CodexSessionTestOverrideKey = "admin_codex_session_test_override"
	// CodexTurnStateTestOverrideKey 仅由管理员测试入口设置，不写入账号配置。
	CodexTurnStateTestOverrideKey = "admin_codex_turn_state_test_override"
)

// CodexSessionOverride 将测试草稿与持久化配置共用同一校验契约。
type CodexSessionOverride struct {
	Enabled   bool   `json:"enabled"`
	SessionID string `json:"session_id"`
	// nil 兼容旧客户端；有值时会话与回合配置一起原子保存。
	AccountTurn *CodexAccountTurnConfiguration `json:"account_turn,omitempty"`
}

// CodexTurnStateTestOverride 是测试弹窗的临时回合草稿。
// turn_id 在一次测试会话中固定，turn_state 由上游成功响应后回填。
type CodexTurnStateTestOverride struct {
	TurnID    string `json:"turn_id"`
	TurnState string `json:"turn_state"`
	Identity  string `json:"identity,omitempty"`
	Disabled  bool   `json:"disabled,omitempty"`
}

type CodexSessionConfiguration struct {
	CodexSessionOverride
	Supported          bool   `json:"supported"`
	EffectiveSessionID string `json:"effective_session_id"`
}

func supportsCodexSessionOverride(account *Account) bool {
	if account == nil || !account.IsOpenAIOAuthLike() || account.IsCredentialShadow() {
		return false
	}
	mode := account.GetCodexFingerprintMode()
	return mode == codexFingerprintSession || mode == codexFingerprintFull
}

func validateCodexSessionOverride(account *Account, value CodexSessionOverride) error {
	if !supportsCodexSessionOverride(account) {
		return infraerrors.BadRequest("CODEX_SESSION_UNSUPPORTED", "A credential-owning OpenAI OAuth account in session or full convergence mode is required")
	}
	if value.SessionID != "" || value.Enabled {
		parsed, err := uuid.Parse(value.SessionID)
		if err != nil || parsed == uuid.Nil || parsed.String() != value.SessionID {
			return infraerrors.BadRequest("CODEX_SESSION_INVALID", "Session ID must be a canonical non-zero UUID")
		}
	}
	if value.Enabled {
		if _, ok := codexFingerprintSeed(account.Extra); !ok {
			return infraerrors.BadRequest("CODEX_SESSION_SEED_MISSING", "Save the fingerprint convergence mode before specifying a session ID")
		}
	}
	return nil
}

func validateCodexTurnStateTestOverride(account *Account, value CodexTurnStateTestOverride) error {
	if !supportsCodexSessionOverride(account) {
		return infraerrors.BadRequest("CODEX_TURN_STATE_UNSUPPORTED", "an OpenAI OAuth credential-owning account is required")
	}
	if value.Disabled {
		return nil
	}
	if value.TurnID == "" {
		return infraerrors.BadRequest("CODEX_TURN_ID_REQUIRED", "Turn ID is required")
	}
	parsed, err := uuid.Parse(value.TurnID)
	if err != nil || parsed == uuid.Nil || parsed.String() != value.TurnID {
		return infraerrors.BadRequest("CODEX_TURN_ID_INVALID", "Turn ID must be a canonical non-zero UUID")
	}
	if value.TurnState != "" && !validCodexTurnState(value.TurnState) {
		return infraerrors.BadRequest("CODEX_TURN_STATE_INVALID", "Turn state is not a valid HTTP field value")
	}
	if value.TurnState != "" && value.Identity != codexAccountTurnIdentity(account) {
		return codexSessionConflict()
	}
	return nil
}

func configuredCodexSessionID(account *Account) string {
	if account == nil {
		return ""
	}
	enabled, _ := account.Extra[codexSessionOverrideEnabledKey].(bool)
	id, _ := account.Extra[codexSessionOverrideIDKey].(string)
	parsed, err := uuid.Parse(id)
	if !enabled || err != nil || parsed == uuid.Nil || parsed.String() != id {
		return ""
	}
	return id
}

// CodexSessionConfig 不暴露账号 seed，也不修改旧账号的派生身份。
func CodexSessionConfig(account *Account) CodexSessionConfiguration {
	result := CodexSessionConfiguration{Supported: supportsCodexSessionOverride(account)}
	if account == nil {
		return result
	}
	result.Enabled, _ = account.Extra[codexSessionOverrideEnabledKey].(bool)
	result.SessionID, _ = account.Extra[codexSessionOverrideIDKey].(string)
	turn := effectiveCodexAccountTurn(account)
	result.AccountTurn = &turn
	if ids := resolveCodexFingerprintIDsFromRequest(account, nil); ids != nil {
		result.EffectiveSessionID = ids.sessionID
	}
	return result
}

// SetCodexSessionOverride 只合并专用键；仓储同步调度快照，不覆盖并发写入的配额及配置。
func (s *adminServiceImpl) SetCodexSessionOverride(ctx context.Context, id int64, value CodexSessionOverride) (*Account, error) {
	account, err := s.accountRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := validateCodexSessionOverride(account, value); err != nil {
		return nil, err
	}
	updates := map[string]any{
		codexSessionOverrideEnabledKey: value.Enabled,
		codexSessionOverrideIDKey:      value.SessionID,
	}
	prospective, err := accountWithCodexSessionDraft(account, value)
	if err != nil {
		return nil, err
	}
	current := storedCodexAccountTurn(account)
	if value.AccountTurn != nil {
		next := *value.AccountTurn
		if next.Revision != current.Revision {
			return nil, codexSessionConflict()
		}
		if next.Enabled {
			if !validCodexTurnState(next.TurnState) {
				return nil, infraerrors.BadRequest("CODEX_TURN_STATE_REQUIRED", "Test successfully and capture a turn state before saving")
			}
			if err := validateCodexTurnStateTestOverride(prospective, CodexTurnStateTestOverride{TurnID: next.TurnID, TurnState: next.TurnState, Identity: next.Identity}); err != nil {
				return nil, err
			}
		} else {
			next.TurnState = ""
		}
		next.Identity = codexAccountTurnIdentity(prospective)
		next.Revision, next.UpdatedAt = uuid.NewString(), time.Now().UTC().Format(time.RFC3339Nano)
		updates[CodexAccountTurnExtraKey] = next
	} else if current.Revision != "" && codexAccountTurnIdentity(account) != codexAccountTurnIdentity(prospective) {
		// 旧客户端单独保存会话时，同步废弃原会话签发的回合状态。
		updates[CodexAccountTurnExtraKey] = CodexAccountTurnConfiguration{Revision: uuid.NewString()}
	}
	if repo, ok := s.accountRepo.(CodexSessionCASRepository); ok {
		var saved bool
		saved, err = repo.CompareAndSwapCodexSession(ctx, account, updates)
		if err == nil && !saved {
			err = codexSessionConflict()
		}
	} else if value.AccountTurn != nil || current.Revision != "" {
		err = infraerrors.InternalServer("CODEX_SESSION_STORAGE_UNAVAILABLE", "Atomic session storage is unavailable")
	} else {
		err = s.accountRepo.UpdateExtra(ctx, id, updates)
	}
	if err != nil {
		return nil, err
	}
	return s.accountRepo.GetByID(ctx, id)
}

// 草稿只修改独立副本，不能污染仓储、调度缓存或原账号种子。
func accountWithCodexSessionDraft(account *Account, value CodexSessionOverride) (*Account, error) {
	if err := validateCodexSessionOverride(account, value); err != nil {
		return nil, err
	}
	copy := *account
	copy.Extra = maps.Clone(account.Extra)
	if copy.Extra == nil {
		copy.Extra = make(map[string]any)
	}
	copy.Extra[codexSessionOverrideEnabledKey] = value.Enabled
	copy.Extra[codexSessionOverrideIDKey] = strings.TrimSpace(value.SessionID)
	return &copy, nil
}
