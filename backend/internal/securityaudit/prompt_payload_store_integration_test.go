package securityaudit

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestRedisPayloadStoreRoundTripTTLNamespaceAndDelete(t *testing.T) {
	address := strings.TrimSpace(os.Getenv(promptAuditRedisTestEnv))
	if address == "" {
		t.Skip(promptAuditRedisTestEnv + " is not set")
	}
	client := redis.NewClient(&redis.Options{Addr: address})
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	store := NewRedisPayloadStore(client)
	ctx := context.Background()
	const jobID int64 = 987654321
	const canary = "PROMPT_CANARY_REDIS_ONLY_PAYLOAD"
	_ = store.Delete(ctx, jobID)
	require.NoError(t, store.Set(ctx, jobID, canary, 2*DefaultPayloadTTL))
	require.Equal(t, PayloadKeyPrefix+"987654321", payloadKey(jobID))
	value, err := store.Get(ctx, jobID)
	require.NoError(t, err)
	require.Equal(t, canary, value)
	ttl, err := client.TTL(ctx, payloadKey(jobID)).Result()
	require.NoError(t, err)
	require.Greater(t, ttl, time.Duration(0))
	require.LessOrEqual(t, ttl, DefaultPayloadTTL)
	require.NoError(t, store.Delete(ctx, jobID))
	_, err = store.Get(ctx, jobID)
	require.ErrorIs(t, err, redis.Nil)
}

func TestRedisDeepReviewStateSeparatesFindingAndBoundedClaim(t *testing.T) {
	address := strings.TrimSpace(os.Getenv(promptAuditRedisTestEnv))
	if address == "" {
		t.Skip(promptAuditRedisTestEnv + " is not set")
	}
	client := redis.NewClient(&redis.Options{Addr: address})
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	store := NewRedisPayloadStore(client)
	ctx := context.Background()
	const userID int64 = 987654322
	defer func() { _ = client.Del(ctx, deepReviewStateKey(userID), deepReviewClaimKey(userID)).Err() }()

	require.NoError(t, store.Require(ctx, userID, "version-1"))
	token, required, err := store.Required(ctx, userID)
	require.NoError(t, err)
	require.True(t, required)
	require.Equal(t, "version-1", token)
	ttl, err := client.TTL(ctx, deepReviewStateKey(userID)).Result()
	require.NoError(t, err)
	require.Equal(t, time.Duration(-1), ttl)
	finding, claimStatus, err := store.Claim(ctx, userID, "claim-1", 250*time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, DeepReviewClaimAcquired, claimStatus)
	require.Equal(t, "version-1", finding)
	_, claimStatus, err = store.Claim(ctx, userID, "claim-2", 250*time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, DeepReviewClaimBusy, claimStatus)
	claimTTL, err := client.PTTL(ctx, deepReviewClaimKey(userID)).Result()
	require.NoError(t, err)
	require.Greater(t, claimTTL, time.Duration(0))
	cleared, err := store.ClearClaimed(ctx, userID, "version-1", "stale-claim")
	require.NoError(t, err)
	require.False(t, cleared)
	cleared, err = store.ClearClaimed(ctx, userID, "stale-finding", "claim-1")
	require.NoError(t, err)
	require.False(t, cleared)
	cleared, err = store.ClearClaimed(ctx, userID, "version-1", "claim-1")
	require.NoError(t, err)
	require.True(t, cleared)
	_, required, err = store.Required(ctx, userID)
	require.NoError(t, err)
	require.False(t, required)
	released, err := store.ReleaseClaim(ctx, userID, "stale-claim")
	require.NoError(t, err)
	require.False(t, released)
	released, err = store.ReleaseClaim(ctx, userID, "claim-1")
	require.NoError(t, err)
	require.True(t, released)
	_, claimStatus, err = store.Claim(ctx, userID, "missing-finding", time.Second)
	require.NoError(t, err)
	require.Equal(t, DeepReviewClaimMissing, claimStatus)
	require.NoError(t, store.Require(ctx, userID, "version-2"))
	_, claimStatus, err = store.Claim(ctx, userID, "expiring-claim", 50*time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, DeepReviewClaimAcquired, claimStatus)
	require.Eventually(t, func() bool {
		_, status, claimErr := store.Claim(ctx, userID, "replacement-claim", time.Second)
		return claimErr == nil && status == DeepReviewClaimAcquired
	}, time.Second, 20*time.Millisecond)
	cleared, err = store.ClearClaimed(ctx, userID, "version-2", "expiring-claim")
	require.NoError(t, err)
	require.False(t, cleared, "expired owner must not clear a finding claimed by another request")
	cleared, err = store.ClearClaimed(ctx, userID, "version-2", "replacement-claim")
	require.NoError(t, err)
	require.True(t, cleared)
	released, err = store.ReleaseClaim(ctx, userID, "replacement-claim")
	require.NoError(t, err)
	require.True(t, released)
	_, required, err = store.Required(ctx, userID)
	require.NoError(t, err)
	require.False(t, required)
}

func TestRedisAllowReceiptTTLAndUserIsolation(t *testing.T) {
	address := strings.TrimSpace(os.Getenv(promptAuditRedisTestEnv))
	if address == "" {
		t.Skip(promptAuditRedisTestEnv + " is not set")
	}
	client := redis.NewClient(&redis.Options{Addr: address})
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	store := NewRedisPayloadStore(client)
	ctx := context.Background()
	const userID int64 = 987654323
	const otherUserID int64 = 987654324
	keys := []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	defer func() {
		_ = client.Del(ctx,
			allowReceiptRedisKey(userID, keys[0]), allowReceiptRedisKey(userID, keys[1]),
			allowReceiptRedisKey(otherUserID, keys[0]), allowReceiptRedisKey(otherUserID, keys[1]),
		).Err()
	}()

	allowed, err := store.ReceiptsAllowed(ctx, userID, keys)
	require.NoError(t, err)
	require.Equal(t, []bool{false, false}, allowed)
	require.NoError(t, store.StoreAllowReceipts(ctx, userID, keys, 250*time.Millisecond))
	allowed, err = store.ReceiptsAllowed(ctx, userID, keys)
	require.NoError(t, err)
	require.Equal(t, []bool{true, true}, allowed)
	allowed, err = store.ReceiptsAllowed(ctx, otherUserID, keys)
	require.NoError(t, err)
	require.Equal(t, []bool{false, false}, allowed)
	ttl, err := client.PTTL(ctx, allowReceiptRedisKey(userID, keys[0])).Result()
	require.NoError(t, err)
	require.Greater(t, ttl, time.Duration(0))
	require.LessOrEqual(t, ttl, 250*time.Millisecond)
	require.Eventually(t, func() bool {
		allowed, lookupErr := store.ReceiptsAllowed(ctx, userID, keys)
		return lookupErr == nil && len(allowed) == 2 && !allowed[0] && !allowed[1]
	}, 2*time.Second, 25*time.Millisecond)
}

func TestPromptRuntimeAggregatesConfigWorkersQueueRedisEndpointsAndGuardMetrics(t *testing.T) {
	address := strings.TrimSpace(os.Getenv(promptAuditRedisTestEnv))
	if address == "" {
		t.Skip(promptAuditRedisTestEnv + " is not set")
	}
	db := openPromptAuditIntegrationDB(t)
	client := redis.NewClient(&redis.Options{Addr: address})
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	config := &fakeConfigStore{active: true, cfg: ActiveConfig{
		RiskControlEnabled: true, Enabled: true, WorkerCount: 3, QueueCapacity: 123,
		ConfigVersion: 9, AllGroups: true,
	}}
	metrics := NewAtomicMetrics()
	metrics.Observe(DecisionBlock, 25*time.Millisecond)
	metrics.IncFailover()
	metrics.IncEnqueued()
	metrics.IncDropped()
	metrics.IncAllowReceiptHit()
	metrics.IncAllowReceiptMiss()
	metrics.IncAllowReceiptWrite()
	metrics.IncAllowReceiptError()
	metrics.IncRecoveryRequired(ModeBlocking)
	metrics.IncRecoveryRequired(ModeAsyncDeep)
	metrics.IncRecoveryCleared()
	metrics.IncRecoveryRetained()
	metrics.IncRecoveryError()
	service := NewPromptService(
		config,
		NewPostgreSQLRepository(db),
		NewRedisPayloadStore(client),
		NewOpenAICompatibleScanner(),
		metrics,
	)
	service.probes["guard-1"] = ProbeResult{OK: true, Status: "healthy", HTTPStatus: 200}

	runtime := service.Runtime(context.Background())
	require.Equal(t, ModeAsync, runtime.EffectiveMode)
	require.Equal(t, int64(9), runtime.ExpectedConfigVersion)
	require.Equal(t, int64(9), runtime.ActiveConfigVersion)
	require.Equal(t, 3, runtime.WorkerTotal)
	require.Equal(t, 123, runtime.QueueCapacity)
	require.Equal(t, "ok", runtime.DatabaseStatus)
	require.Equal(t, "ok", runtime.RedisStatus)
	require.Contains(t, runtime.Endpoints, "guard-1")
	require.Equal(t, int64(1), runtime.GuardMetrics.Total)
	require.Equal(t, int64(1), runtime.GuardMetrics.Blocked)
	require.Equal(t, int64(1), runtime.GuardMetrics.Failovers)
	require.Equal(t, int64(25), runtime.GuardMetrics.LatencyP95MS)
	require.Equal(t, int64(1), runtime.EnqueuedTotal)
	require.Equal(t, int64(1), runtime.DroppedTotal)
	require.Equal(t, int64(1), runtime.AllowReceiptHits)
	require.Equal(t, int64(1), runtime.AllowReceiptMisses)
	require.Equal(t, int64(1), runtime.AllowReceiptWrites)
	require.Equal(t, int64(1), runtime.AllowReceiptErrors)
	require.Equal(t, int64(1), runtime.RecoveryRequiredSync)
	require.Equal(t, int64(1), runtime.RecoveryRequiredAsync)
	require.Equal(t, int64(1), runtime.RecoveryCleared)
	require.Equal(t, int64(1), runtime.RecoveryRetained)
	require.Equal(t, int64(1), runtime.RecoveryErrors)
	// The runner has not been started in this integration test, so the honest
	// process status is degraded rather than a fabricated running heartbeat.
	require.Equal(t, "degraded", runtime.ProcessStatus)
}
