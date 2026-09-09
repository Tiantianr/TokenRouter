package securityaudit

import (
	"encoding/json"
	"testing"

	infraerrors "github.com/TokenFlux/TokenRouter/internal/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestPassRetentionDefaultsCanonicalizesAndIgnoresLegacyGlobalSwitch(t *testing.T) {
	stored, err := parsePassRetentionStorage("")
	require.NoError(t, err)
	require.Equal(t, int64(1), stored.Revision)
	require.Empty(t, stored.UserIDs)
	defaultJSON, err := json.Marshal(publicPassRetention(clonePassRetentionStorage(stored), ""))
	require.NoError(t, err)
	require.Contains(t, string(defaultJSON), `"user_ids":[]`)

	stored, err = parsePassRetentionStorage(`{"revision":4,"user_ids":[9,3,9]}`)
	require.NoError(t, err)
	require.Equal(t, []int64{3, 9}, stored.UserIDs)

	main, err := ParseStorageConfig(`{"store_pass_events":true,"config_version":7,"worker_count":4,"queue_capacity":10,"scanners":["pii"],"all_groups":true}`)
	require.NoError(t, err)
	publicJSON, err := json.Marshal(PublicFromStorage(main, true, nil))
	require.NoError(t, err)
	require.NotContains(t, string(publicJSON), "store_pass_events")
}

func TestActiveConfigRetainsFullPassEvidenceOnlyForSelectedUsers(t *testing.T) {
	cfg := ActiveConfig{PassRetentionUserIDs: []int64{3, 9}}
	require.False(t, cfg.ShouldRetainPassEvidence(0))
	require.False(t, cfg.ShouldRetainPassEvidence(2))
	require.True(t, cfg.ShouldRetainPassEvidence(3))
	require.True(t, cfg.ShouldRetainPassEvidence(9))
	require.False(t, cfg.ShouldRetainPassEvidence(10))
}

func TestPassRetentionUpdateValidation(t *testing.T) {
	ids, err := validatePassRetentionUpdate(UpdatePassRetentionRequest{ExpectedRevision: 2, UserIDs: []int64{7, 4, 7}})
	require.NoError(t, err)
	require.Equal(t, []int64{4, 7}, ids)

	_, err = validatePassRetentionUpdate(UpdatePassRetentionRequest{ExpectedRevision: 0})
	require.Equal(t, "prompt_audit_pass_retention_expected_revision_required", infraerrors.Reason(err))
	_, err = validatePassRetentionUpdate(UpdatePassRetentionRequest{ExpectedRevision: 1, UserIDs: []int64{-1}})
	require.Equal(t, "prompt_audit_pass_retention_invalid_user", infraerrors.Reason(err))
	tooMany := make([]int64, maxPassRetentionUsers+1)
	for index := range tooMany {
		tooMany[index] = int64(index + 1)
	}
	_, err = validatePassRetentionUpdate(UpdatePassRetentionRequest{ExpectedRevision: 1, UserIDs: tooMany})
	require.Equal(t, "prompt_audit_pass_retention_user_limit", infraerrors.Reason(err))
}
