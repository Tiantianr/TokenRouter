package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// 嵌入既有仓库替身，仅增加展示观测的持久化能力。
type weeklyLimitEstimateStoreStub struct{ snapshotUpdateAccountRepo }

func (r *weeklyLimitEstimateStoreStub) StoreAccountUsageObservation(ctx context.Context, id int64, updates map[string]any) error {
	return r.UpdateExtra(ctx, id, updates)
}

func TestObserveOpenAIWeeklyLimitEstimateLifecycle(t *testing.T) {
	now := time.Now().UTC()
	reset := now.Add(7 * 24 * time.Hour)
	weekly := &UsageProgress{Utilization: 6, ResetsAt: &reset, WindowStats: &WindowStats{Cost: 100, UserCost: 900}}
	estimate, baseline, changed := observeOpenAIWeeklyLimitEstimate(nil, weekly, now)
	require.Nil(t, estimate)
	require.True(t, changed)
	weekly.Utilization = 7
	weekly.WindowStats.Cost = 120
	extra := map[string]any{openAIWeeklyLimitEstimateExtraKey: baseline}
	estimate, snapshot, changed := observeOpenAIWeeklyLimitEstimate(extra, weekly, now)
	require.True(t, changed)
	require.Equal(t, 2000.0, estimate.EstimatedCost)
	require.Equal(t, 6, estimate.BasisPercent)
	extra[openAIWeeklyLimitEstimateExtraKey] = snapshot
	weekly.WindowStats.Cost = 140
	estimate, _, changed = observeOpenAIWeeklyLimitEstimate(extra, weekly, now)
	require.False(t, changed)
	require.Equal(t, 120.0, estimate.SampledCost)
	// 跳过百分比仍使用上次实际观测值，不使用当前百分比减一。
	weekly.Utilization = 9
	estimate, _, _ = observeOpenAIWeeklyLimitEstimate(extra, weekly, now)
	require.Equal(t, 7, estimate.BasisPercent)
	weekly.Utilization = 1
	estimate, _, changed = observeOpenAIWeeklyLimitEstimate(extra, weekly, now)
	require.Nil(t, estimate)
	require.True(t, changed)
	weekly.Utilization = 8
	reset = reset.Add(7 * 24 * time.Hour)
	estimate, _, changed = observeOpenAIWeeklyLimitEstimate(extra, weekly, now)
	require.Nil(t, estimate)
	require.True(t, changed)
}

func TestAttachOpenAIWeeklyLimitEstimatePersistsAndFreezes(t *testing.T) {
	updates := make(chan map[string]any, 3)
	repo := &weeklyLimitEstimateStoreStub{snapshotUpdateAccountRepo{updateExtraCalls: updates}}
	svc := &AccountUsageService{accountRepo: repo}
	now := time.Now().UTC()
	reset := now.Add(7 * 24 * time.Hour)
	account := &Account{ID: 42}
	weekly := &UsageProgress{Utilization: 6, ResetsAt: &reset, WindowStats: &WindowStats{Cost: 100}}
	svc.attachOpenAIWeeklyLimitEstimate(context.Background(), account, weekly, now)
	require.Len(t, updates, 1)
	weekly.Utilization = 7
	weekly.WindowStats.Cost = 120
	svc.attachOpenAIWeeklyLimitEstimate(context.Background(), account, weekly, now)
	require.Equal(t, 2000.0, weekly.AccountCostLimitEstimate.EstimatedCost)
	// 旧账号对象不应使相同百分比的成本增长重新采样。
	weekly.WindowStats.Cost = 150
	svc.attachOpenAIWeeklyLimitEstimate(context.Background(), &Account{ID: 42}, weekly, now)
	require.Len(t, updates, 2)
	require.Equal(t, 120.0, weekly.AccountCostLimitEstimate.SampledCost)
}
