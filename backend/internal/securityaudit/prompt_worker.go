package securityaudit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

type WorkerRuntime struct {
	active           atomic.Int64
	processed        atomic.Int64
	failed           atomic.Int64
	heartbeatNS      atomic.Int64
	lastProcessedNS  atomic.Int64
	lastErrorNS      atomic.Int64
	lastErrorMu      sync.RWMutex
	lastErrorCode    string
	lastErrorMessage string
}

type Runner struct {
	config   ConfigStore
	repo     JobRepository
	payload  PayloadStore
	state    DeepReviewStateStore
	receipts AllowReceiptStore
	scanner  PromptScanner
	metrics  Metrics
	clock    Clock
	runtime  WorkerRuntime

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewRunner(config ConfigStore, repo JobRepository, payload PayloadStore, scanner PromptScanner, metrics Metrics) *Runner {
	state, _ := payload.(DeepReviewStateStore)
	receipts, _ := payload.(AllowReceiptStore)
	return &Runner{config: config, repo: repo, payload: payload, state: state, receipts: receipts, scanner: scanner, metrics: metrics, clock: realClock{}}
}

func (r *Runner) Start(ctx context.Context) error {
	if r == nil || r.config == nil || r.repo == nil || r.payload == nil || r.scanner == nil {
		logPromptRuntimeFailure(EventProcessFailed, "worker_dependencies_unavailable")
		return errors.New("prompt audit worker dependencies unavailable")
	}
	r.mu.Lock()
	if r.cancel != nil {
		r.mu.Unlock()
		return nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.mu.Unlock()
	if err := r.payload.Ping(runCtx); err != nil {
		r.setLastError("payload_store_unavailable", err.Error())
		logPromptRuntimeFailure(EventProcessFailed, "payload_store_unavailable")
	}
	for workerID := 0; workerID < MaxWorkerCount; workerID++ {
		r.wg.Add(1)
		go r.worker(runCtx, workerID)
	}
	r.wg.Add(1)
	go r.reclaimer(runCtx)
	return nil
}

func (r *Runner) Shutdown(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	cancel := r.cancel
	r.cancel = nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		LogWarn(EventProcessFailed, mergeLogFields(promptRuntimeLogFields(), map[string]any{
			"status": "shutdown_timeout", "error_code": "worker_shutdown_timeout", "error_kind": "audit_dependency",
		}))
		return ctx.Err()
	}
}

func (r *Runner) worker(ctx context.Context, workerID int) {
	defer r.wg.Done()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.runtime.heartbeatNS.Store(r.clock.Now().UnixNano())
			cfg, ok := r.config.Active()
			if !ok || !cfg.RiskControlEnabled || !cfg.Enabled || workerID >= cfg.WorkerCount {
				continue
			}
			for {
				job, claimed, err := r.repo.ClaimNextJob(ctx, r.clock.Now())
				if err != nil {
					r.setLastError("claim_job_failed", err.Error())
					logPromptRuntimeFailure(EventProcessFailed, "claim_job_failed")
					break
				}
				if !claimed {
					break
				}
				processConfig, active := r.config.Active()
				if !active {
					processConfig = ActiveConfig{}
				}
				r.runtime.active.Add(1)
				r.processSafely(ctx, workerID, processConfig, job)
				r.runtime.active.Add(-1)
			}
		}
	}
}

func (r *Runner) processSafely(ctx context.Context, workerID int, cfg ActiveConfig, job *Job) {
	defer func() {
		if recovered := recover(); recovered != nil {
			r.runtime.failed.Add(1)
			// Panic values may contain scanner response fragments or prompt data.
			// Keep only a stable generic message in runtime state and logs.
			r.setLastError("worker_panic", "worker panic recovered")
			if err := r.repo.Fail(ctx, job.ID, job.ClaimVersion, "worker_panic", "worker panic recovered"); err == nil {
				r.recordFailureEvent(ctx, job, "worker_panic")
			}
			LogError(EventProcessFailed, mergeLogFields(jobLogFields(job), map[string]any{"worker_id": workerID, "status": "failed", "error_code": "worker_panic"}))
		}
	}()
	if err := r.processJob(ctx, workerID, cfg, job); err != nil {
		r.runtime.failed.Add(1)
	} else {
		r.runtime.processed.Add(1)
		r.runtime.lastProcessedNS.Store(r.clock.Now().UnixNano())
	}
}

func (r *Runner) processJob(ctx context.Context, workerID int, cfg ActiveConfig, job *Job) error {
	baseFields := jobLogFields(job)
	LogInfo(EventAuditStarted, mergeLogFields(baseFields, map[string]any{"worker_id": workerID, "attempts": job.Attempts, "status": "processing"}))
	if cfg.ConfigVersion > 0 && !cfg.IncludesGroup(job.Snapshot.GroupID) {
		if err := r.repo.Fail(ctx, job.ID, job.ClaimVersion, "group_out_of_scope", "prompt audit group out of scope"); err != nil {
			r.setLastError("job_scope_discard_failed", err.Error())
			return err
		}
		_ = r.payload.Delete(ctx, job.ID)
		LogInfo(EventEnqueueSkipped, mergeLogFields(baseFields, map[string]any{
			"worker_id": workerID, "status": "skipped", "error_code": "group_out_of_scope",
		}))
		return nil
	}
	if job.ConfigVersion != cfg.ConfigVersion {
		return r.finishFailure(ctx, job, &GuardError{Code: "config_version_changed", Retryable: false})
	}
	storedPayload, err := r.payload.Get(ctx, job.ID)
	if err != nil {
		return r.finishFailure(ctx, job, &GuardError{Code: "payload_missing", Retryable: false, Cause: err})
	}
	payload := decodeTransientPromptPayload(storedPayload)
	scanText := payload.ScanText
	job.Snapshot.FullContextCiphertext = payload.ContextCiphertext
	job.Snapshot.FullContextHash = payload.ContextHash
	job.Snapshot.FullContextBytes = payload.ContextBytes
	job.Snapshot.FullContextSegmentCount = payload.ContextSegmentCount
	job.Snapshot.AllowReceiptKeys = append([]string(nil), payload.AllowReceiptKeys...)
	job.Snapshot.AllowReceiptHitCount = payload.AllowReceiptHitCount
	job.Snapshot.AllowReceiptWrite = payload.AllowReceiptWrite
	// The job row only carries redacted metadata; the full prompt for the audit
	// event is reconstructed here from the transient scan payload.
	job.Snapshot.FullPrompt = FullPromptFromScanText(scanText)
	job.Snapshot.FullPromptTruncated = utf8.RuneCountInString(job.Snapshot.FullPrompt) < job.Snapshot.PromptLength
	endpoints := cfg.EnabledEndpoints()
	if len(endpoints) == 0 {
		observeGuardOutcome(r.metrics, DecisionUnavailable, 0, true)
		return r.finishFailure(ctx, job, &GuardError{Code: "no_enabled_endpoint", Retryable: true})
	}
	inputLimit := minimumInputLimit(endpoints)
	chunks := SplitRunes(scanText, inputLimit)
	results := make([]*NormalizedResult, 0, len(chunks))
	started := r.clock.Now()
	for index, chunk := range chunks {
		if err := r.repo.RefreshLease(ctx, job.ID, job.ClaimVersion, r.clock.Now()); err != nil {
			r.setLastError("lease_refresh_failed", err.Error())
			LogWarn(EventProcessFailed, mergeLogFields(baseFields, map[string]any{
				"worker_id": workerID, "status": "failed", "error_code": "lease_refresh_failed", "error_kind": "audit_dependency",
			}))
			return err
		}
		chunkStarted := r.clock.Now()
		LogInfo(EventChunkStarted, mergeLogFields(baseFields, map[string]any{"worker_id": workerID, "chunk_index": index + 1, "chunk_total": len(chunks), "chunk_chars": utf8.RuneCountInString(chunk), "input_chars": job.Snapshot.PromptLength, "input_limit": inputLimit, "status": "started"}))
		result, scanErr := scanWithFailover(ctx, r.scanner, cfg.Scanners, endpoints, chunk, r.metrics)
		if scanErr != nil {
			LogWarn(EventChunkFailed, mergeLogFields(baseFields, map[string]any{
				"worker_id": workerID, "chunk_index": index + 1, "chunk_total": len(chunks),
				"chunk_chars": utf8.RuneCountInString(chunk), "input_chars": job.Snapshot.PromptLength,
				"input_limit": inputLimit, "latency_ms": r.clock.Now().Sub(chunkStarted).Milliseconds(),
				"error_code": guardErrorCode(scanErr), "status": "failed",
			}))
			r.observeAsyncFailure(ctx, scanErr, r.clock.Now().Sub(started))
			return r.finishFailure(ctx, job, scanErr)
		}
		result.InputLimit = inputLimit
		result.MatchedChunkIndex = index + 1
		results = append(results, result)
		LogInfo(EventChunkCompleted, mergeLogFields(baseFields, map[string]any{"worker_id": workerID, "chunk_index": index + 1, "chunk_total": len(chunks), "guard_endpoint_id": result.GuardEndpointID, "action": result.Action, "latency_ms": r.clock.Now().Sub(chunkStarted).Milliseconds(), "status": "completed"}))
		if result.Action == ActionBlock {
			break
		}
	}
	aggregated, err := AggregateResults(results, r.clock.Now().Sub(started))
	if err != nil {
		observeGuardOutcome(r.metrics, DecisionInvalid, r.clock.Now().Sub(started), true)
		return r.finishFailure(ctx, job, &GuardError{Code: ErrorCodeInvalidResponse, Cause: err})
	}
	aggregated.InputLimit = inputLimit
	aggregated.ChunkTotal = len(chunks)
	observeGuardOutcome(r.metrics, decisionKindForResult(aggregated), r.clock.Now().Sub(started), true)
	LogInfo(EventChunksAggregated, mergeLogFields(baseFields, map[string]any{
		"worker_id": workerID, "decision": aggregated.Decision, "risk_level": aggregated.RiskLevel,
		"action": aggregated.Action, "chunk_total": aggregated.ChunkTotal,
		"latency_ms": aggregated.LatencyMS, "guard_endpoint_id": aggregated.GuardEndpointID, "status": "completed",
	}))
	if job.ExecutionMode == ModeAsyncDeep && aggregated.Action == ActionBlock && job.Snapshot.UserID > 0 &&
		!job.Snapshot.BlockingExemptAtRequest && !cfg.IsBlockingExempt(job.Snapshot.UserID) {
		token := fmt.Sprintf("async:%d:%d", job.ID, job.ClaimVersion)
		if err := markDeepReviewRequired(ctx, r.state, r.metrics, job.Snapshot.UserID, token, ModeAsyncDeep, baseFields); err != nil {
			return r.finishFailure(ctx, job, &GuardError{Code: ErrorCodeDeepReviewState, Retryable: true, Cause: err})
		}
	}
	retainPassEvidence := cfg.ShouldRetainPassEvidence(job.Snapshot.UserID)
	if retention, ok := r.config.(passEvidenceRetentionDecider); ok {
		retainPassEvidence = retention.ShouldRetainPassEvidence(job.Snapshot.UserID)
	}
	event, err := r.repo.Complete(ctx, job, aggregated, retainPassEvidence)
	if err != nil {
		r.setLastError("job_complete_failed", err.Error())
		LogWarn(EventProcessFailed, mergeLogFields(baseFields, map[string]any{
			"worker_id": workerID, "status": "failed", "error_code": "job_complete_failed", "error_kind": "audit_dependency",
		}))
		return err
	}
	if aggregated.Action == ActionAllow && job.Snapshot.AllowReceiptWrite {
		storeAllowReceipts(ctx, r.receipts, r.metrics, cfg, job.Snapshot)
	}
	if deleteErr := r.payload.Delete(ctx, job.ID); deleteErr != nil {
		LogWarn(EventProcessFailed, mergeLogFields(baseFields, map[string]any{"worker_id": workerID, "status": "payload_delete_deferred", "error_code": "payload_delete_failed"}))
	}
	LogInfo(EventProcessed, mergeLogFields(baseFields, map[string]any{"worker_id": workerID, "event_id": eventID(event), "decision": aggregated.Decision, "risk_level": aggregated.RiskLevel, "action": aggregated.Action, "guard_endpoint_id": aggregated.GuardEndpointID, "latency_ms": aggregated.LatencyMS, "status": "done"}))
	if event != nil && aggregated.Decision != EventPass {
		LogWarn(EventFindingRecorded, mergeLogFields(baseFields, map[string]any{"worker_id": workerID, "event_id": event.ID, "decision": aggregated.Decision, "risk_level": aggregated.RiskLevel, "action": aggregated.Action, "guard_endpoint_id": aggregated.GuardEndpointID, "status": "recorded"}))
	}
	return nil
}

func (r *Runner) observeAsyncFailure(ctx context.Context, err error, latency time.Duration) {
	if r == nil || r.metrics == nil {
		return
	}
	kind := DecisionUnavailable
	if guardErrorCode(err) == ErrorCodeInvalidResponse {
		kind = DecisionInvalid
	}
	observeGuardOutcome(r.metrics, kind, latency, ctx.Err() == nil)
	var guardErr *GuardError
	if errors.As(err, &guardErr) && guardErr.Timeout {
		r.metrics.IncTimeout()
	}
}

func decisionKindForResult(result *NormalizedResult) DecisionKind {
	if result == nil {
		return DecisionInvalid
	}
	switch result.Action {
	case ActionBlock:
		return DecisionBlock
	case ActionWarn:
		return DecisionFlag
	default:
		return DecisionAllow
	}
}

func (r *Runner) finishFailure(ctx context.Context, job *Job, err error) error {
	baseFields := jobLogFields(job)
	code := guardErrorCode(err)
	var guardErr *GuardError
	retryable := errors.As(err, &guardErr) && guardErr.Retryable
	if retryable && job.Attempts < job.MaxAttempts {
		next := r.clock.Now().Add(retryBackoff(job.Attempts))
		if updateErr := r.repo.Retry(ctx, job.ID, job.ClaimVersion, next, code, "prompt guard temporarily unavailable"); updateErr != nil {
			r.setLastError("job_retry_failed", updateErr.Error())
			LogWarn(EventProcessFailed, mergeLogFields(baseFields, map[string]any{
				"attempts": job.Attempts, "max_attempts": job.MaxAttempts, "status": "failed",
				"error_code": "job_retry_failed", "error_kind": "audit_dependency",
			}))
			return updateErr
		}
		LogWarn(EventProcessFailed, mergeLogFields(baseFields, map[string]any{"attempts": job.Attempts, "max_attempts": job.MaxAttempts, "status": "retry", "error_code": code, "retryable": true}))
	} else {
		if updateErr := r.repo.Fail(ctx, job.ID, job.ClaimVersion, code, "prompt guard processing failed"); updateErr != nil {
			r.setLastError("job_fail_failed", updateErr.Error())
			LogWarn(EventProcessFailed, mergeLogFields(baseFields, map[string]any{
				"attempts": job.Attempts, "max_attempts": job.MaxAttempts, "status": "failed",
				"error_code": "job_fail_failed", "error_kind": "audit_dependency",
			}))
			return updateErr
		}
		r.recordFailureEvent(ctx, job, code)
		_ = r.payload.Delete(ctx, job.ID)
		LogError(EventProcessFailed, mergeLogFields(baseFields, map[string]any{"attempts": job.Attempts, "max_attempts": job.MaxAttempts, "status": "failed", "error_code": code, "retryable": false}))
	}
	r.setLastError(code, err.Error())
	return err
}

func (r *Runner) recordFailureEvent(ctx context.Context, job *Job, code string) {
	if r == nil || r.repo == nil || job == nil || ctx.Err() != nil {
		return
	}
	if _, err := r.repo.RecordFailureEvent(ctx, job, code); err == nil {
		return
	}
	if r.metrics != nil {
		r.metrics.IncRecordFailed()
	}
	LogWarn(EventFailureRecordFailed, mergeLogFields(jobLogFields(job), map[string]any{
		"status": "failed", "error_code": "failure_event_record_failed", "error_kind": "audit_dependency",
	}))
}

func (r *Runner) reclaimer(ctx context.Context) {
	defer r.wg.Done()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := r.clock.Now()
			count, err := r.repo.ReclaimStale(ctx, now.Add(-2*time.Minute), now.Add(-90*time.Second), 100)
			if err != nil {
				r.setLastError("reclaim_failed", err.Error())
				logPromptRuntimeFailure(EventProcessFailed, "reclaim_failed")
				continue
			}
			if count > 0 {
				LogWarn(EventProcessingReclaimed, map[string]any{"reclaimed_total": count, "status": "reclaimed"})
			}
		}
	}
}

func (r *Runner) Snapshot() (active, processed, failed int64, heartbeat, lastProcessed *time.Time, code, message string) {
	if r == nil {
		return
	}
	active, processed, failed = r.runtime.active.Load(), r.runtime.processed.Load(), r.runtime.failed.Load()
	if ns := r.runtime.heartbeatNS.Load(); ns > 0 {
		value := time.Unix(0, ns).UTC()
		heartbeat = &value
	}
	if ns := r.runtime.lastProcessedNS.Load(); ns > 0 {
		value := time.Unix(0, ns).UTC()
		lastProcessed = &value
	}
	r.runtime.lastErrorMu.RLock()
	code, message = r.runtime.lastErrorCode, r.runtime.lastErrorMessage
	r.runtime.lastErrorMu.RUnlock()
	return
}

func (r *Runner) LastErrorAt() *time.Time {
	if r == nil {
		return nil
	}
	if ns := r.runtime.lastErrorNS.Load(); ns > 0 {
		value := time.Unix(0, ns).UTC()
		return &value
	}
	return nil
}

func (r *Runner) setLastError(code, _ string) {
	code, message := sanitizeStoredError(code)
	r.runtime.lastErrorMu.Lock()
	r.runtime.lastErrorCode = code
	r.runtime.lastErrorMessage = message
	r.runtime.lastErrorNS.Store(r.clock.Now().UnixNano())
	r.runtime.lastErrorMu.Unlock()
}

func scanWithFailover(ctx context.Context, scanner PromptScanner, scanners []string, endpoints []ActiveEndpoint, chunk string, metrics Metrics) (*NormalizedResult, error) {
	var lastErr error
	for index, endpoint := range endpoints {
		result, err := scanner.Scan(ctx, endpoint, chunk, scanners)
		if err == nil && result != nil {
			return result, nil
		}
		if err == nil {
			err = &GuardError{Code: ErrorCodeInvalidResponse, Retryable: false}
		}
		lastErr = err
		var guardErr *GuardError
		if !errors.As(err, &guardErr) || !guardErr.Retryable {
			return nil, err
		}
		if index < len(endpoints)-1 && metrics != nil {
			metrics.IncFailover()
		}
	}
	if lastErr == nil {
		lastErr = &GuardError{Code: ErrorCodeUnavailable}
	}
	return nil, lastErr
}

func retryBackoff(attempt int) time.Duration {
	switch attempt {
	case 1:
		return 5 * time.Second
	case 2:
		return 30 * time.Second
	default:
		return 2 * time.Minute
	}
}

func eventID(event *Event) int64 {
	if event == nil {
		return 0
	}
	return event.ID
}
