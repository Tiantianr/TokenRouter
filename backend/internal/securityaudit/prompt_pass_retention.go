package securityaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	infraerrors "github.com/TokenFlux/TokenRouter/internal/pkg/errors"
)

// ponytail: selected users are exception policy; add a batch user resolver before raising this cap.
const maxPassRetentionUsers = 100

type passEvidenceRetentionDecider interface {
	ShouldRetainPassEvidence(userID int64) bool
}

type passRetentionStorage struct {
	Revision  int64     `json:"revision"`
	UserIDs   []int64   `json:"user_ids"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy int64     `json:"updated_by"`
}

type PassRetentionConfig struct {
	Revision  int64     `json:"revision"`
	UserIDs   []int64   `json:"user_ids"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy int64     `json:"updated_by"`
	LoadError string    `json:"load_error,omitempty"`
}

type UpdatePassRetentionRequest struct {
	ExpectedRevision int64   `json:"expected_revision" binding:"required"`
	UserIDs          []int64 `json:"user_ids"`
}

func defaultPassRetentionStorage() passRetentionStorage {
	return passRetentionStorage{Revision: 1, UserIDs: []int64{}}
}

func parsePassRetentionStorage(raw string) (passRetentionStorage, error) {
	if raw == "" {
		return defaultPassRetentionStorage(), nil
	}
	var stored passRetentionStorage
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		return passRetentionStorage{}, err
	}
	if stored.Revision < 1 {
		return passRetentionStorage{}, errors.New("prompt audit Pass retention revision is invalid")
	}
	if len(stored.UserIDs) > maxPassRetentionUsers {
		return passRetentionStorage{}, errors.New("prompt audit Pass retention user limit exceeded")
	}
	for _, userID := range stored.UserIDs {
		if userID <= 0 {
			return passRetentionStorage{}, errors.New("prompt audit Pass retention user ID is invalid")
		}
	}
	stored.UserIDs = canonicalInt64s(stored.UserIDs)
	return stored, nil
}

func validatePassRetentionUpdate(req UpdatePassRetentionRequest) ([]int64, error) {
	if req.ExpectedRevision < 1 {
		return nil, infraerrors.BadRequest("prompt_audit_pass_retention_expected_revision_required", "必须提供有效的 Pass 完整证据留存版本")
	}
	if len(req.UserIDs) > maxPassRetentionUsers {
		return nil, infraerrors.BadRequest("prompt_audit_pass_retention_user_limit", "Pass 完整证据留存用户数量超出限制")
	}
	for _, userID := range req.UserIDs {
		if userID <= 0 {
			return nil, infraerrors.BadRequest("prompt_audit_pass_retention_invalid_user", "Pass 完整证据留存用户 ID 无效")
		}
	}
	return canonicalInt64s(req.UserIDs), nil
}

func publicPassRetention(stored passRetentionStorage, loadError string) PassRetentionConfig {
	return PassRetentionConfig{
		Revision: stored.Revision, UserIDs: append([]int64{}, stored.UserIDs...),
		UpdatedAt: stored.UpdatedAt, UpdatedBy: stored.UpdatedBy, LoadError: loadError,
	}
}

func passRetentionDigest(userIDs []int64) string {
	raw, _ := json.Marshal(userIDs)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func (cfg ActiveConfig) ShouldRetainPassEvidence(userID int64) bool {
	if userID <= 0 {
		return false
	}
	index := sort.Search(len(cfg.PassRetentionUserIDs), func(index int) bool {
		return cfg.PassRetentionUserIDs[index] >= userID
	})
	return index < len(cfg.PassRetentionUserIDs) && cfg.PassRetentionUserIDs[index] == userID
}
