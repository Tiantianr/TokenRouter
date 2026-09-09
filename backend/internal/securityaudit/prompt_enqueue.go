package securityaudit

import (
	"context"
	"errors"
)

type Enqueuer struct {
	config   ConfigStore
	repo     JobRepository
	payload  PayloadStore
	receipts AllowReceiptStore
	metrics  Metrics
}

func NewEnqueuer(config ConfigStore, repo JobRepository, payload PayloadStore, metrics ...Metrics) *Enqueuer {
	var metric Metrics
	if len(metrics) > 0 {
		metric = metrics[0]
	}
	receipts, _ := payload.(AllowReceiptStore)
	return &Enqueuer{config: config, repo: repo, payload: payload, receipts: receipts, metrics: metric}
}

func (e *Enqueuer) Enqueue(ctx context.Context, req Request) error {
	return e.enqueue(ctx, req, ModeAsync)
}

func (e *Enqueuer) EnqueueDeep(ctx context.Context, req Request) error {
	if !req.SuppressReceiptWrite {
		req.AllowReceiptWrite = true
	}
	return e.enqueue(ctx, req, ModeAsyncDeep)
}

func (e *Enqueuer) EnqueueBlockingExempt(ctx context.Context, req Request, cfg ActiveConfig) error {
	req.AllowReceiptWrite = false
	req.SuppressReceiptWrite = true
	return e.enqueueWithConfig(ctx, req, ModeAsyncDeep, cfg, true)
}

func (e *Enqueuer) enqueue(ctx context.Context, req Request, mode Mode) error {
	if e == nil || e.config == nil || e.repo == nil || e.payload == nil {
		LogWarn(EventEnqueueDropped, mergeLogFields(requestLogFields(req), map[string]any{
			"status": "dropped", "error_code": "enqueuer_unavailable", "error_kind": "audit_dependency",
		}))
		if e != nil {
			e.recordDropped()
		}
		return errors.New("prompt audit enqueuer unavailable")
	}
	cfg, ok := e.config.Active()
	baseFields := requestLogFields(req)
	baseFields["execution_mode"] = mode
	expectedMode := ModeAsync
	if mode == ModeAsyncDeep {
		expectedMode = ModeBlocking
	}
	if !ok || cfg.EffectiveMode() != expectedMode {
		LogInfo(EventEnqueueSkipped, mergeLogFields(baseFields, map[string]any{"status": "skipped", "error_code": "mode_not_async"}))
		return nil
	}
	return e.enqueueWithConfig(ctx, req, mode, cfg, false)
}

func (e *Enqueuer) enqueueWithConfig(ctx context.Context, req Request, mode Mode, cfg ActiveConfig, required bool) error {
	if e == nil || e.config == nil || e.repo == nil || e.payload == nil {
		LogWarn(EventEnqueueDropped, mergeLogFields(requestLogFields(req), map[string]any{
			"status": "dropped", "error_code": "enqueuer_unavailable", "error_kind": "audit_dependency",
		}))
		if e != nil {
			e.recordDropped()
		}
		if required {
			return &GuardError{Code: ErrorCodeUnavailable}
		}
		return errors.New("prompt audit enqueuer unavailable")
	}
	baseFields := requestLogFields(req)
	baseFields["execution_mode"] = mode
	baseFields["config_version"] = cfg.ConfigVersion
	if !cfg.IncludesGroup(req.GroupID) {
		LogInfo(EventEnqueueSkipped, mergeLogFields(baseFields, map[string]any{"status": "skipped", "error_code": "group_out_of_scope"}))
		if required {
			return &GuardError{Code: ErrorCodeConfigUnavailable}
		}
		return nil
	}
	if len(cfg.EnabledEndpoints()) == 0 {
		e.recordDropped()
		LogWarn(EventEnqueueDropped, mergeLogFields(baseFields, map[string]any{"status": "dropped", "error_code": "no_enabled_endpoint"}))
		if required {
			return &GuardError{Code: ErrorCodeUnavailable}
		}
		return nil
	}
	snapshot, diagnostic, err := extractDeepPromptSnapshotWithDiagnostics(req, cfg.DeepReviewModules)
	snapshot.BlockingExemptAtRequest = required
	if diagnostic.Failed {
		e.recordExtraction(ExtractionFailed)
		logPromptExtractionFailure(req, diagnostic)
		if required {
			return &GuardError{Code: ErrorCodeExtractionFailed, Cause: err}
		}
	}
	if errors.Is(err, ErrNoPromptText) {
		if !diagnostic.Failed {
			e.recordExtraction(ExtractionEmpty)
		}
		code := "no_user_text"
		if diagnostic.Failed {
			code = "no_extracted_content"
		}
		LogInfo(EventEnqueueSkipped, mergeLogFields(baseFields, map[string]any{"status": "skipped", "error_code": code}))
		return nil
	}
	if err != nil {
		if !diagnostic.Failed {
			e.recordExtraction(ExtractionFailed)
			logPromptExtractionFailure(req, promptExtractionDiagnostic{Failed: true, ErrorCode: "content_extraction_failed"})
		}
		LogInfo(EventEnqueueSkipped, mergeLogFields(baseFields, map[string]any{"status": "skipped", "error_code": "snapshot_invalid"}))
		if required {
			return &GuardError{Code: ErrorCodeExtractionFailed, Cause: err}
		}
		return nil
	}
	if !diagnostic.Failed {
		e.recordExtraction(ExtractionSucceeded)
	}
	prepareAllowReceipts(ctx, e.receipts, e.metrics, cfg, &snapshot, req.AllowReceiptKeys, required)
	if snapshot.ScanText == "" {
		LogInfo(EventEnqueueSkipped, mergeLogFields(baseFields, map[string]any{"status": "skipped", "error_code": "all_segments_allowed"}))
		return nil
	}
	ciphertext, err := encryptCompletePromptContext(e.config, snapshot.CompleteContext)
	if err != nil {
		LogWarn(EventEnqueueDropped, mergeLogFields(baseFields, map[string]any{
			"status": "dropped", "error_code": "context_encryption_failed",
		}))
		e.recordDropped()
		if required {
			return &GuardError{Code: ErrorCodeEncryptionKeyRequired, Cause: err}
		}
		return err
	}
	snapshot.FullContextCiphertext = ciphertext
	snapshot.CompleteContext = ""
	transientPayload, err := encodeTransientPromptPayload(snapshot)
	if err != nil {
		e.recordDropped()
		if required {
			return &GuardError{Code: ErrorCodeUnavailable, Cause: err}
		}
		return err
	}
	job, err := e.repo.CreateStagingWithCapacity(ctx, snapshot.Redacted(), mode, cfg.ConfigVersion, 3, cfg.QueueCapacity)
	if err != nil {
		code := "database_unavailable"
		if errors.Is(err, ErrQueueFull) {
			code = "queue_full"
		}
		if errors.Is(err, ErrQueueAdmissionBusy) {
			code = "queue_admission_busy"
		}
		LogWarn(EventEnqueueDropped, mergeLogFields(baseFields, map[string]any{
			"queue_capacity": cfg.QueueCapacity, "status": "dropped", "error_code": code,
		}))
		e.recordDropped()
		if required {
			return &GuardError{Code: ErrorCodeUnavailable, Cause: err}
		}
		return err
	}
	if err := e.payload.Set(ctx, job.ID, transientPayload, DefaultPayloadTTL); err != nil {
		e.recordStagingFailure(ctx, job, "payload_store_failed", "payload store unavailable")
		LogWarn(EventEnqueueDropped, mergeLogFields(baseFields, map[string]any{
			"job_id": job.ID, "status": "dropped", "error_code": "payload_store_failed",
		}))
		e.recordDropped()
		if required {
			return &GuardError{Code: ErrorCodeUnavailable, Cause: err}
		}
		return err
	}
	if err := e.repo.PublishQueued(ctx, job.ID); err != nil {
		_ = e.payload.Delete(ctx, job.ID)
		e.recordStagingFailure(ctx, job, "queue_publish_failed", "queue publish failed")
		LogWarn(EventEnqueueDropped, mergeLogFields(baseFields, map[string]any{
			"job_id": job.ID, "status": "dropped", "error_code": "queue_publish_failed",
		}))
		e.recordDropped()
		if required {
			return &GuardError{Code: ErrorCodeUnavailable, Cause: err}
		}
		return err
	}
	LogInfo(EventJobEnqueued, mergeLogFields(baseFields, map[string]any{
		"job_id":         job.ID,
		"queue_capacity": cfg.QueueCapacity, "status": "queued",
	}))
	if e.metrics != nil {
		e.metrics.IncEnqueued()
	}
	return nil
}

func (e *Enqueuer) recordStagingFailure(ctx context.Context, job *Job, code, message string) {
	if e == nil || e.repo == nil || job == nil || ctx.Err() != nil {
		return
	}
	if err := e.repo.MarkStagingFailed(ctx, job.ID, code, message); err != nil {
		return
	}
	if _, err := e.repo.RecordFailureEvent(ctx, job, code); err == nil {
		return
	}
	if e.metrics != nil {
		e.metrics.IncRecordFailed()
	}
	LogWarn(EventFailureRecordFailed, mergeLogFields(jobLogFields(job), map[string]any{
		"status": "failed", "error_code": "failure_event_record_failed", "error_kind": "audit_dependency",
	}))
}

func (e *Enqueuer) recordDropped() {
	if e != nil && e.metrics != nil {
		e.metrics.IncDropped()
	}
}

func (e *Enqueuer) recordExtraction(outcome ExtractionOutcome) {
	if e.metrics != nil {
		e.metrics.ObserveExtraction(outcome)
	}
}
