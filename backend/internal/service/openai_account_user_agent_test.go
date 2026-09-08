package service

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const accountUserAgentTestValue = "codex-tui/0.153.4 (Mac OS 26.6.1; arm64) Apple_Terminal/470.2 (codex-tui; 0.153.4)"

func TestCreateAccountCodexUserAgent(t *testing.T) {
	for _, ua := range []string{accountUserAgentTestValue, "  " + accountUserAgentTestValue + "  ", ""} {
		t.Run(ua, func(t *testing.T) {
			repo := &accountServiceTestRepo{}
			account, err := (&adminServiceImpl{accountRepo: repo}).CreateAccount(context.Background(), &CreateAccountInput{
				Name: "codex", Platform: PlatformOpenAI, Type: AccountTypeOAuth,
				Credentials:          map[string]any{"access_token": "access", "refresh_token": "refresh", "user_agent": ua},
				SkipDefaultGroupBind: true,
			})
			require.NoError(t, err)
			require.Equal(t, strings.TrimSpace(ua), account.GetOpenAIUserAgent())
			require.Equal(t, "access", account.Credentials["access_token"])
			if ua == "" {
				require.NotContains(t, account.Credentials, "user_agent")
			}
		})
	}
}

func TestUpdateAccountCodexUserAgentPreservesCredentials(t *testing.T) {
	for _, ua := range []string{accountUserAgentTestValue, "", "   "} {
		t.Run(ua, func(t *testing.T) {
			original := &Account{ID: 5, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Status: StatusActive,
				Credentials: map[string]any{"access_token": "access", "refresh_token": "refresh", "user_agent": "codex-tui/0.144.0", "plan_type": "pro"},
				Extra:       map[string]any{"enable_tls_fingerprint": true, "codex_fingerprint_mode": "device", "codex_fingerprint_seed": "42ea8308-8706-49ff-82ff-171e881d385b"},
			}
			repo := &accountServiceAdminTestRepo{&accountServiceTestRepo{accounts: map[int64]*Account{5: original}}}
			updated, err := (&adminServiceImpl{accountRepo: repo}).UpdateAccount(context.Background(), 5, &UpdateAccountInput{
				Credentials: map[string]any{"user_agent": ua, "plan_type": "pro"},
			})
			require.NoError(t, err)
			require.Equal(t, strings.TrimSpace(ua), updated.GetOpenAIUserAgent())
			require.Equal(t, "access", updated.Credentials["access_token"])
			require.Equal(t, "refresh", updated.Credentials["refresh_token"])
			require.Equal(t, "pro", updated.Credentials["plan_type"])
			require.Equal(t, original.Extra, updated.Extra)
			if strings.TrimSpace(ua) == "" {
				require.NotContains(t, updated.Credentials, "user_agent")
			}
		})
	}
}

func TestAccountCodexUserAgentRejectsInvalidWrites(t *testing.T) {
	for _, ua := range []any{nil, true, "pi/1.0.0", "codex-tui/no-version", "codex-tui/0.153.4\r\nX-Test: injected", "\tcodex-tui/0.153.4", "codex-tui/0.153.4 中文", "codex-tui/0.153.4 " + strings.Repeat("x", 1024)} {
		repo := &accountServiceAdminTestRepo{&accountServiceTestRepo{accounts: map[int64]*Account{
			5: {ID: 5, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Credentials: map[string]any{"user_agent": accountUserAgentTestValue}},
		}}}
		svc := &adminServiceImpl{accountRepo: repo}
		_, err := svc.CreateAccount(context.Background(), &CreateAccountInput{
			Platform: PlatformOpenAI, Type: AccountTypeOAuth, SkipDefaultGroupBind: true,
			Credentials: map[string]any{"user_agent": ua},
		})
		require.Error(t, err)
		require.Len(t, repo.accounts, 1)
		_, err = svc.UpdateAccount(context.Background(), 5, &UpdateAccountInput{Credentials: map[string]any{"user_agent": ua}})
		require.Error(t, err)
		require.Equal(t, accountUserAgentTestValue, repo.accounts[5].GetOpenAIUserAgent())
	}
}

func TestAccountCodexUserAgentScope(t *testing.T) {
	for _, account := range []*Account{
		{Platform: PlatformAnthropic, Type: AccountTypeOAuth},
		{Platform: PlatformOpenAI, Type: AccountTypeAPIKey},
		{Platform: PlatformOpenAI, Type: AccountTypeSetupToken},
	} {
		account.Credentials = map[string]any{"user_agent": "custom/1"}
		require.NoError(t, normalizeOpenAIAccountUserAgent(account))
		require.Equal(t, "custom/1", account.Credentials["user_agent"])
	}
	parentID := int64(5)
	repo := &accountServiceTestRepo{accounts: map[int64]*Account{
		12: {ID: 12, Platform: PlatformOpenAI, Type: AccountTypeOAuth, ParentAccountID: &parentID},
	}}
	_, err := (&adminServiceImpl{accountRepo: repo}).UpdateAccount(context.Background(), 12, &UpdateAccountInput{
		Credentials: map[string]any{"user_agent": accountUserAgentTestValue},
	})
	require.Error(t, err)
}
