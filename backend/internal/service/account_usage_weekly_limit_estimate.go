package service

import (
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"strings"
	"time"
)

const openAIWeeklyLimitEstimateExtraKey = "codex_7d_limit_estimate"

// AccountCostLimitEstimate 只使用账号成本 A，不混用用户扣费或标准成本。
type AccountCostLimitEstimate struct {
	EstimatedCost   float64 `json:"estimated_cost"`
	SampledCost     float64 `json:"sampled_cost"`
	BasisPercent    int     `json:"basis_percent"`
	ObservedPercent int     `json:"observed_percent"`
	SampledAt       string  `json:"sampled_at"`
}

type openAIWeeklyLimitEstimateSnapshot struct {
	WindowResetAt       string                    `json:"window_reset_at"`
	LastObservedPercent int                       `json:"last_observed_percent"`
	Estimate            *AccountCostLimitEstimate `json:"estimate,omitempty"`
}

// 观测数据使用可选持久化能力，不扩大账号仓库的通用接口。
type accountUsageObservationStore interface {
	StoreAccountUsageObservation(context.Context, int64, map[string]any) error
}

// @project-doc docs/interfaces/openai_upstream.md#openai_quota_and_scheduling
func (s *AccountUsageService) attachOpenAIWeeklyLimitEstimate(ctx context.Context, account *Account, weekly *UsageProgress, now time.Time) {
	if s == nil || s.accountRepo == nil || account == nil || weekly == nil || weekly.WindowStats == nil || weekly.ResetsAt == nil {
		return
	}
	store, canPersist := s.accountRepo.(accountUsageObservationStore)
	if !canPersist {
		weekly.AccountCostLimitEstimate, _, _ = observeOpenAIWeeklyLimitEstimate(account.Extra, weekly, now)
		return
	}
	// 串行化同账号观测，避免并发请求拿旧快照重复更新同一百分比。
	lock := &s.openAIWeeklyEstimateMu[uint64(account.ID)%64]
	lock.Lock()
	defer lock.Unlock()
	extra := account.Extra
	if cached, ok := s.openAIWeeklyEstimate.Load(account.ID); ok {
		extra = map[string]any{openAIWeeklyLimitEstimateExtraKey: cached}
	}
	estimate, snapshot, changed := observeOpenAIWeeklyLimitEstimate(extra, weekly, now)
	weekly.AccountCostLimitEstimate = estimate
	if !changed || snapshot == nil {
		if snapshot != nil {
			s.openAIWeeklyEstimate.Store(account.ID, snapshot)
		}
		return
	}
	if err := store.StoreAccountUsageObservation(ctx, account.ID, map[string]any{openAIWeeklyLimitEstimateExtraKey: snapshot}); err != nil {
		slog.Warn("openai_weekly_limit_estimate_persist_failed", "account_id", account.ID, "error", err)
		return
	}
	s.openAIWeeklyEstimate.Store(account.ID, snapshot)
	if account.Extra == nil {
		account.Extra = make(map[string]any)
	}
	account.Extra[openAIWeeklyLimitEstimateExtraKey] = snapshot
}

func observeOpenAIWeeklyLimitEstimate(extra map[string]any, weekly *UsageProgress, now time.Time) (*AccountCostLimitEstimate, *openAIWeeklyLimitEstimateSnapshot, bool) {
	if weekly == nil || weekly.WindowStats == nil || weekly.ResetsAt == nil || math.IsNaN(weekly.Utilization) || math.IsInf(weekly.Utilization, 0) || weekly.Utilization < 0 {
		return nil, nil, false
	}
	observedPercent := int(math.Min(math.Round(weekly.Utilization), 100))
	resetAt := weekly.ResetsAt.UTC()
	snapshot := decodeOpenAIWeeklyLimitEstimateSnapshot(extra)
	if snapshot == nil || !sameOpenAIWeeklyEstimateWindow(snapshot.WindowResetAt, resetAt) || observedPercent < snapshot.LastObservedPercent {
		return nil, &openAIWeeklyLimitEstimateSnapshot{WindowResetAt: resetAt.Format(time.RFC3339), LastObservedPercent: observedPercent}, true
	}
	if observedPercent == snapshot.LastObservedPercent {
		return cloneAccountCostLimitEstimate(snapshot.Estimate), snapshot, false
	}
	// 百分比上升时，以当前累计成本除以上次观测百分比；其余时间冻结估值。
	basisPercent := snapshot.LastObservedPercent
	sampledCost := weekly.WindowStats.Cost
	snapshot.LastObservedPercent = observedPercent
	if basisPercent <= 0 || sampledCost <= 0 || math.IsNaN(sampledCost) || math.IsInf(sampledCost, 0) {
		snapshot.Estimate = nil
		return nil, snapshot, true
	}
	snapshot.Estimate = &AccountCostLimitEstimate{
		EstimatedCost: sampledCost / float64(basisPercent) * 100,
		SampledCost:   sampledCost, BasisPercent: basisPercent, ObservedPercent: observedPercent,
		SampledAt: now.UTC().Format(time.RFC3339),
	}
	return cloneAccountCostLimitEstimate(snapshot.Estimate), snapshot, true
}

func decodeOpenAIWeeklyLimitEstimateSnapshot(extra map[string]any) *openAIWeeklyLimitEstimateSnapshot {
	raw := extra[openAIWeeklyLimitEstimateExtraKey]
	if raw == nil {
		return nil
	}
	payload, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var snapshot openAIWeeklyLimitEstimateSnapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil || snapshot.WindowResetAt == "" || snapshot.LastObservedPercent < 0 || snapshot.LastObservedPercent > 100 {
		return nil
	}
	if !validAccountCostLimitEstimate(snapshot.Estimate) {
		snapshot.Estimate = nil
	}
	return &snapshot
}

func sameOpenAIWeeklyEstimateWindow(raw string, resetAt time.Time) bool {
	stored, err := time.Parse(time.RFC3339, strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	// 上游 reset_after 换算可能有轻微抖动，沿用旧工程的十五分钟容差。
	delta := stored.Sub(resetAt)
	if delta < 0 {
		delta = -delta
	}
	return delta <= 15*time.Minute
}

func validAccountCostLimitEstimate(estimate *AccountCostLimitEstimate) bool {
	return estimate != nil && estimate.EstimatedCost > 0 && estimate.SampledCost > 0 &&
		estimate.BasisPercent > 0 && estimate.ObservedPercent > estimate.BasisPercent &&
		!math.IsNaN(estimate.EstimatedCost) && !math.IsInf(estimate.EstimatedCost, 0) &&
		!math.IsNaN(estimate.SampledCost) && !math.IsInf(estimate.SampledCost, 0) && strings.TrimSpace(estimate.SampledAt) != ""
}

func cloneAccountCostLimitEstimate(estimate *AccountCostLimitEstimate) *AccountCostLimitEstimate {
	if !validAccountCostLimitEstimate(estimate) {
		return nil
	}
	copy := *estimate
	return &copy
}
