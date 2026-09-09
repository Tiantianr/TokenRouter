package securityaudit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	infraerrors "github.com/TokenFlux/TokenRouter/internal/pkg/errors"
)

const (
	deepReviewClaimPollMin = 100 * time.Millisecond
	deepReviewClaimPollMax = time.Second
)

type PromptService struct {
	config    ConfigStore
	repo      *PostgreSQLRepository
	payload   PayloadStore
	state     DeepReviewStateStore
	receipts  AllowReceiptStore
	enqueuer  *Enqueuer
	runner    *Runner
	evaluator *GuardEvaluator
	scanner   PromptScanner
	metrics   *AtomicMetrics
	clock     Clock

	lifecycleMu  sync.Mutex
	cancel       context.CancelFunc
	background   context.Context
	enqueueWG    sync.WaitGroup
	cleanupWG    sync.WaitGroup
	enqueueSlots chan struct{}
	probeMu      sync.RWMutex
	probes       map[string]ProbeResult
}

type passRetentionConfigStore interface {
	PublicPassRetention() (PassRetentionConfig, error)
	SavePassRetention(context.Context, UpdatePassRetentionRequest, int64) (PassRetentionConfig, error)
}

func NewPromptService(
	config ConfigStore,
	repo *PostgreSQLRepository,
	payload PayloadStore,
	scanner *OpenAICompatibleScanner,
	metrics *AtomicMetrics,
) *PromptService {
	state, _ := payload.(DeepReviewStateStore)
	receipts, _ := payload.(AllowReceiptStore)
	var jobRepo JobRepository
	if repo != nil {
		jobRepo = repo
	}
	enqueuer := NewEnqueuer(config, jobRepo, payload, metrics)
	var retention passEvidenceRetentionDecider
	if configured, ok := config.(passEvidenceRetentionDecider); ok {
		retention = configured
	}
	evaluator := NewGuardEvaluator(scanner, jobRepo, metrics, retention)
	runner := NewRunner(config, jobRepo, payload, scanner, metrics)
	return &PromptService{
		config: config, repo: repo, payload: payload, state: state, receipts: receipts, scanner: scanner, metrics: metrics,
		enqueuer: enqueuer, evaluator: evaluator, runner: runner, clock: realClock{},
		enqueueSlots: make(chan struct{}, 128), probes: map[string]ProbeResult{},
	}
}

func (s *PromptService) Start(ctx context.Context) error {
	if s == nil || s.config == nil || s.runner == nil {
		logPromptRuntimeFailure(EventProcessFailed, "service_dependencies_unavailable")
		return errors.New("prompt audit service unavailable")
	}
	s.lifecycleMu.Lock()
	if s.cancel != nil {
		s.lifecycleMu.Unlock()
		return nil
	}
	background, cancel := context.WithCancel(ctx)
	s.background, s.cancel = background, cancel
	s.lifecycleMu.Unlock()
	configErr := s.config.Start(background)
	workerErr := s.runner.Start(background)
	if s.repo != nil && s.repo.db != nil {
		s.cleanupWG.Add(1)
		go s.chatRetentionLoop(background)
	}
	if configErr != nil {
		logPromptRuntimeFailure(EventConfigReloadDegraded, "config_start_failed")
	}
	if workerErr != nil {
		logPromptRuntimeFailure(EventProcessFailed, "worker_start_failed")
	}
	return errors.Join(configErr, workerErr)
}

func (s *PromptService) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.lifecycleMu.Lock()
	cancel := s.cancel
	s.cancel = nil
	s.lifecycleMu.Unlock()
	if cancel != nil {
		cancel()
	}
	var workerErr error
	if s.runner != nil {
		workerErr = s.runner.Shutdown(ctx)
	}
	done := make(chan struct{})
	go func() { s.enqueueWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		if workerErr == nil {
			workerErr = ctx.Err()
		}
	}
	done = make(chan struct{})
	go func() { s.cleanupWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		if workerErr == nil {
			workerErr = ctx.Err()
		}
	}
	var configErr error
	if s.config != nil {
		configErr = s.config.Shutdown(ctx)
	}
	if workerErr != nil {
		logPromptRuntimeFailure(EventProcessFailed, "worker_shutdown_failed")
		return workerErr
	}
	if configErr != nil {
		logPromptRuntimeFailure(EventConfigReloadDegraded, "config_shutdown_failed")
	}
	return configErr
}

func (s *PromptService) EffectiveMode() Mode {
	if s == nil || s.config == nil {
		return ModeOff
	}
	return s.config.EffectiveMode()
}

func (s *PromptService) chatRetentionLoop(ctx context.Context) {
	defer s.cleanupWG.Done()
	cleanup := func() {
		if ctx.Err() != nil || s.repo == nil || s.repo.db == nil {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		now := time.Now().UTC()
		if s.clock != nil {
			now = s.clock.Now()
		}
		var deletedTotal int64
		for cleanupCtx.Err() == nil {
			deleted, err := s.repo.DeleteExpiredChatRecords(cleanupCtx, now, 500)
			if err != nil {
				LogWarn(EventChatRetentionCleanupFailed, map[string]any{"status": "failed", "error_code": "chat_retention_cleanup_failed"})
				return
			}
			deletedTotal += deleted
			if deleted < 500 {
				break
			}
		}
		var orphanedTotal int64
		for cleanupCtx.Err() == nil {
			orphaned, err := s.repo.DeleteOrphanChatRecords(cleanupCtx, 500)
			if err != nil {
				LogWarn(EventChatRetentionCleanupFailed, map[string]any{"status": "failed", "error_code": "chat_orphan_cleanup_failed"})
				return
			}
			orphanedTotal += orphaned
			if orphaned < 500 {
				break
			}
		}
		if deletedTotal > 0 || orphanedTotal > 0 {
			LogInfo(EventChatRetentionCleaned, map[string]any{"status": "deleted", "deleted_count": deletedTotal + orphanedTotal})
		}
	}
	cleanup()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanup()
		}
	}
}

func (s *PromptService) BlockingApplies(req Request) bool {
	policy := s.blockingPolicy(req)
	return policy.Applies && !policy.BlockingExempt
}

type promptBlockingPolicy struct {
	ConfigVersion  int64
	Applies        bool
	BlockingExempt bool
}

func (s *PromptService) blockingPolicy(req Request) promptBlockingPolicy {
	if s == nil || s.config == nil || s.config.BlockingActivationDegraded() {
		return promptBlockingPolicy{}
	}
	cfg, ok := s.config.Active()
	if !ok {
		return promptBlockingPolicy{}
	}
	policy := promptBlockingPolicy{ConfigVersion: cfg.ConfigVersion}
	policy.Applies = cfg.EffectiveMode() == ModeBlocking && cfg.IncludesGroup(req.GroupID)
	policy.BlockingExempt = policy.Applies && cfg.IsBlockingExempt(req.UserID)
	return policy
}

func (s *PromptService) Enqueue(_ context.Context, req Request) error {
	return s.enqueue(req, ModeAsync)
}

func (s *PromptService) EnqueueDeep(_ context.Context, req Request) error {
	return s.enqueue(req, ModeAsyncDeep)
}

func (s *PromptService) enqueue(req Request, mode Mode) error {
	expectedMode := ModeAsync
	if mode == ModeAsyncDeep {
		expectedMode = ModeBlocking
	}
	if s == nil || s.EffectiveMode() != expectedMode {
		return nil
	}
	if s.enqueuer == nil {
		if s.metrics != nil {
			s.metrics.IncDropped()
		}
		LogWarn(EventEnqueueDropped, mergeLogFields(requestLogFields(req), map[string]any{"status": "dropped", "error_code": "enqueuer_unavailable", "error_kind": "audit_dependency"}))
		return nil
	}
	select {
	case s.enqueueSlots <- struct{}{}:
	default:
		if s.metrics != nil {
			s.metrics.IncDropped()
		}
		LogWarn(EventEnqueueDropped, mergeLogFields(requestLogFields(req), map[string]any{"status": "dropped", "error_code": "local_enqueue_busy", "error_kind": "audit_dependency"}))
		return nil
	}
	s.lifecycleMu.Lock()
	background := s.background
	s.lifecycleMu.Unlock()
	if background == nil {
		<-s.enqueueSlots
		LogWarn(EventEnqueueDropped, mergeLogFields(requestLogFields(req), map[string]any{"status": "dropped", "error_code": "service_not_started", "error_kind": "audit_dependency"}))
		return errors.New("prompt audit service not started")
	}
	requestCopy := req.Clone()
	s.enqueueWG.Add(1)
	go func() {
		defer s.enqueueWG.Done()
		defer func() { <-s.enqueueSlots }()
		ctx, cancel := context.WithTimeout(background, 2*time.Second)
		defer cancel()
		if mode == ModeAsyncDeep {
			_ = s.enqueuer.EnqueueDeep(ctx, requestCopy)
		} else {
			_ = s.enqueuer.Enqueue(ctx, requestCopy)
		}
	}()
	return nil
}

func (s *PromptService) Evaluate(ctx context.Context, req Request) (*PromptDecision, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil {
		return failureAllowedPromptDecision(), nil
	}
	if s.config == nil || s.evaluator == nil {
		logPromptRequestFailure(req, DecisionUnavailable, ErrorCodeUnavailable)
		return s.allowPromptUnavailable(req, 0, false, false), nil
	}
	if s.config.BlockingActivationDegraded() {
		logPromptRequestFailure(req, DecisionUnavailable, ErrorCodeConfigUnavailable)
		return nil, &GuardError{Code: ErrorCodeConfigUnavailable}
	}
	cfg, ok := s.config.Active()
	if !ok {
		if s.config.EffectiveMode() == ModeBlocking {
			logPromptRequestFailure(req, DecisionUnavailable, ErrorCodeConfigUnavailable)
			return nil, &GuardError{Code: ErrorCodeConfigUnavailable}
		}
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	if req.promptPolicyResolved && req.promptPolicyConfigVersion != cfg.ConfigVersion {
		logPromptRequestFailure(req, DecisionUnavailable, ErrorCodeConfigUnavailable)
		return nil, &GuardError{Code: ErrorCodeConfigUnavailable}
	}
	if cfg.EffectiveMode() != ModeBlocking {
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	applies := cfg.IncludesGroup(req.GroupID)
	blockingExempt := applies && cfg.IsBlockingExempt(req.UserID)
	if req.promptPolicyResolved {
		applies = req.promptPolicyApplies
		blockingExempt = req.promptPolicyExempt
	}
	if !applies {
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	if blockingExempt {
		if err := s.enqueueBlockingExempt(ctx, req, cfg); err != nil {
			var guardErr *GuardError
			if !errors.As(err, &guardErr) {
				guardErr = &GuardError{Code: ErrorCodeUnavailable, Cause: err}
			}
			logPromptRequestFailure(req, DecisionUnavailable, guardErr.Code)
			if guardErr.Code == ErrorCodeUnavailable && ctx.Err() == nil {
				return s.allowPromptUnavailable(req, cfg.ConfigVersion, true, true), nil
			}
			return nil, guardErr
		}
		return &PromptDecision{
			Kind: DecisionAllow, AllowNextStage: true, AsyncAuditHandled: true,
			BlockingExemptAtRequest: true,
		}, nil
	}
	var stateToken, claimToken string
	var deepRequired bool
	var stateErr error
	if !blockingExempt {
		stateToken, deepRequired, claimToken, stateErr = s.acquireRequiredDeepReview(ctx, req)
	}
	if stateErr != nil {
		if errors.Is(stateErr, context.Canceled) || errors.Is(stateErr, context.DeadlineExceeded) {
			s.observeRecoveryRetained(req, DecisionUnavailable, ErrorCodeDeepReviewState)
		} else {
			s.observeRecoveryStateFailure(req, ErrorCodeDeepReviewState)
		}
		logPromptRequestFailure(req, DecisionUnavailable, ErrorCodeDeepReviewState)
		return nil, &GuardError{Code: ErrorCodeDeepReviewState, Cause: stateErr}
	}
	if claimToken != "" {
		defer s.releaseRequiredDeepReviewClaim(req, claimToken)
	}
	var snapshot PromptSnapshot
	var diagnostic promptExtractionDiagnostic
	var err error
	if deepRequired {
		snapshot, diagnostic, err = extractDeepPromptSnapshotWithDiagnostics(req, cfg.DeepReviewModules)
	} else {
		snapshot, diagnostic, err = extractBlockingPromptSnapshotWithDiagnostics(req, cfg.BlockingReviewModules)
	}
	if diagnostic.Failed {
		if s.metrics != nil {
			s.metrics.ObserveExtraction(ExtractionFailed)
		}
		logPromptExtractionFailure(req, diagnostic)
	}
	if diagnostic.Failed {
		if deepRequired {
			s.observeRecoveryRetained(req, DecisionUnavailable, ErrorCodeExtractionFailed)
		}
		return nil, &GuardError{Code: ErrorCodeExtractionFailed, Cause: err}
	}
	if errors.Is(err, ErrNoPromptText) {
		if s.metrics != nil {
			s.metrics.ObserveExtraction(ExtractionEmpty)
		}
		if deepRequired {
			return s.finishRequiredDeepReview(ctx, req, stateToken, claimToken, &PromptDecision{Kind: DecisionBlock, ErrorCode: ErrorCodeDeepReviewRequired, AllowNextStage: false})
		}
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true, DeepReviewed: deepRequired}, nil
	}
	if err != nil {
		if !diagnostic.Failed {
			diagnostic = promptExtractionDiagnostic{Failed: true, ErrorCode: "content_extraction_failed"}
			if s.metrics != nil {
				s.metrics.ObserveExtraction(ExtractionFailed)
			}
			logPromptExtractionFailure(req, diagnostic)
		}
		if deepRequired {
			s.observeRecoveryRetained(req, DecisionUnavailable, ErrorCodeExtractionFailed)
		}
		return nil, &GuardError{Code: ErrorCodeExtractionFailed, Cause: err}
	}
	prepareAllowReceipts(ctx, s.receipts, s.metrics, cfg, &snapshot, req.AllowReceiptKeys, deepRequired)
	if strings.TrimSpace(snapshot.ScanText) == "" {
		if s.metrics != nil {
			s.metrics.ObserveExtraction(ExtractionSucceeded)
		}
		if deepRequired {
			return s.finishRequiredDeepReview(ctx, req, stateToken, claimToken, &PromptDecision{Kind: DecisionBlock, ErrorCode: ErrorCodeDeepReviewRequired, AllowNextStage: false})
		}
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	ciphertext, err := encryptCompletePromptContext(s.config, snapshot.CompleteContext)
	if err != nil {
		if deepRequired {
			s.observeRecoveryRetained(req, DecisionUnavailable, ErrorCodeEncryptionKeyRequired)
		}
		logPromptRequestFailure(req, DecisionUnavailable, ErrorCodeEncryptionKeyRequired)
		return nil, &GuardError{Code: ErrorCodeEncryptionKeyRequired, Cause: err}
	}
	snapshot.FullContextCiphertext = ciphertext
	snapshot.CompleteContext = ""
	if s.metrics != nil {
		s.metrics.ObserveExtraction(ExtractionSucceeded)
	}
	decision, err := s.evaluator.Evaluate(ctx, cfg, snapshot)
	if err == nil && decision != nil && decision.Kind == DecisionAllow {
		decision.AllowReceiptKeys = append([]string(nil), snapshot.AllowReceiptKeys...)
		decision.allowReceipt = &allowReceiptCommit{ConfigVersion: cfg.ConfigVersion, Snapshot: snapshot}
	}
	if err != nil {
		if ctx.Err() != nil {
			return decision, err
		}
		code := guardErrorCode(err)
		if deepRequired {
			s.observeRecoveryRetained(req, DecisionUnavailable, code)
		}
		failureAllowed := code == ErrorCodeUnavailable
		s.recordBlockingFailure(ctx, snapshot, cfg, code, failureAllowed)
		if failureAllowed {
			return s.allowPromptUnavailable(req, cfg.ConfigVersion, false, false), nil
		}
		return decision, err
	}
	if !deepRequired {
		if decision != nil && decision.Kind == DecisionBlock && req.UserID > 0 {
			now := time.Now().UTC()
			if s.clock != nil {
				now = s.clock.Now()
			}
			token := fmt.Sprintf("blocking:%s:%d", req.RequestID, now.UnixNano())
			if stateErr := markDeepReviewRequired(ctx, s.state, s.metrics, req.UserID, token, ModeBlocking, requestLogFields(req)); stateErr != nil {
				logPromptRequestFailure(req, DecisionUnavailable, ErrorCodeDeepReviewState)
				return nil, &GuardError{Code: ErrorCodeDeepReviewState, Cause: stateErr}
			}
		}
		return decision, nil
	}
	return s.finishRequiredDeepReview(ctx, req, stateToken, claimToken, decision)
}

func (s *PromptService) allowPromptUnavailable(req Request, configVersion int64, blockingExempt, asyncHandled bool) *PromptDecision {
	if s != nil && s.metrics != nil {
		s.metrics.IncFailureAllowed()
	}
	LogWarn(EventGuardFailureAllowed, mergeLogFields(requestLogFields(req), map[string]any{
		"config_version": configVersion, "decision": DecisionAllow, "status": "failure_allowed",
		"error_code": ErrorCodeUnavailable, "upstream_dispatched": false, "billing_preconsumed": false,
	}))
	decision := failureAllowedPromptDecision()
	decision.BlockingExemptAtRequest = blockingExempt
	decision.AsyncAuditHandled = asyncHandled
	return decision
}

func (s *PromptService) enqueueBlockingExempt(ctx context.Context, req Request, cfg ActiveConfig) error {
	if s == nil || s.enqueuer == nil {
		return &GuardError{Code: ErrorCodeUnavailable}
	}
	s.lifecycleMu.Lock()
	background := s.background
	s.lifecycleMu.Unlock()
	if background == nil || background.Err() != nil {
		return &GuardError{Code: ErrorCodeUnavailable}
	}
	return s.enqueuer.EnqueueBlockingExempt(ctx, req, cfg)
}

func (s *PromptService) recordBlockingFailure(ctx context.Context, snapshot PromptSnapshot, cfg ActiveConfig, code string, bestEffort bool) {
	if s == nil || s.repo == nil || s.repo.db == nil || ctx.Err() != nil {
		return
	}
	snapshot = failureEventSnapshot(snapshot)
	if !bestEffort {
		s.recordBlockingFailureNow(ctx, snapshot, cfg, code)
		return
	}
	s.lifecycleMu.Lock()
	background := s.background
	s.lifecycleMu.Unlock()
	if background == nil {
		return
	}
	s.enqueueWG.Add(1)
	go func() {
		defer s.enqueueWG.Done()
		recordCtx, cancel := context.WithTimeout(background, 2*time.Second)
		defer cancel()
		s.recordBlockingFailureNow(recordCtx, snapshot, cfg, code)
	}()
}

func (s *PromptService) recordBlockingFailureNow(ctx context.Context, snapshot PromptSnapshot, cfg ActiveConfig, code string) {
	if s == nil || s.repo == nil || s.repo.db == nil || ctx.Err() != nil {
		return
	}
	if _, err := s.repo.RecordBlockingFailure(ctx, snapshot, cfg.ConfigVersion, code); err == nil {
		return
	}
	if s.metrics != nil {
		s.metrics.IncRecordFailed()
	}
	LogWarn(EventFailureRecordFailed, mergeLogFields(snapshotLogFields(snapshot), map[string]any{
		"config_version": cfg.ConfigVersion, "status": "failed", "error_code": "failure_event_record_failed", "error_kind": "audit_dependency",
	}))
}

func (s *PromptService) commitAllowReceipts(ctx context.Context, decision *PromptDecision) {
	if s == nil || decision == nil || decision.Kind != DecisionAllow || decision.allowReceipt == nil {
		return
	}
	commit := decision.allowReceipt
	decision.allowReceipt = nil
	cfg, ok := s.config.Active()
	if !ok || cfg.ConfigVersion != commit.ConfigVersion {
		logAllowReceiptFailure(commit.Snapshot, "store", "allow_receipt_config_changed")
		return
	}
	storeAllowReceipts(ctx, s.receipts, s.metrics, cfg, commit.Snapshot)
}

func (s *PromptService) deepReviewRequired(ctx context.Context, userID int64) (string, bool, error) {
	if userID <= 0 {
		return "", false, nil
	}
	if s == nil || s.state == nil {
		return "", false, errors.New("prompt audit deep review state unavailable")
	}
	return s.state.Required(ctx, userID)
}

func (s *PromptService) pendingRecoveryDecision(ctx context.Context, req Request) (*PromptDecision, error) {
	if s != nil && s.config != nil {
		if cfg, ok := s.config.Active(); ok && (!cfg.IncludesGroup(req.GroupID) || cfg.IsBlockingExempt(req.UserID)) {
			return nil, nil
		}
	}
	_, required, err := s.deepReviewRequired(ctx, req.UserID)
	if err != nil {
		s.observeRecoveryStateFailure(req, ErrorCodeDeepReviewState)
		return nil, &GuardError{Code: ErrorCodeDeepReviewState, Cause: err}
	}
	if !required {
		return nil, nil
	}
	s.observeRecoveryRetained(req, DecisionBlock, ErrorCodeDeepReviewRequired)
	return &PromptDecision{
		Kind: DecisionBlock, ErrorCode: ErrorCodeDeepReviewRequired,
		AllowNextStage: false, DeepReviewed: true,
	}, nil
}

func (s *PromptService) acquireRequiredDeepReview(ctx context.Context, req Request) (string, bool, string, error) {
	if req.UserID <= 0 {
		return "", false, "", nil
	}
	if s == nil || s.state == nil {
		return "", false, "", errors.New("prompt audit deep review state unavailable")
	}
	waiting := false
	started := time.Now().UTC()
	if s.clock != nil {
		started = s.clock.Now()
	}
	claimBytes := make([]byte, 16)
	if _, err := rand.Read(claimBytes); err != nil {
		return "", false, "", errors.New("prompt audit deep review claim unavailable")
	}
	claimToken := "review:" + hex.EncodeToString(claimBytes)
	delay := deepReviewClaimPollMin
	jitter := sha256.Sum256([]byte(req.RequestID))
	for {
		stateToken, status, err := s.state.Claim(ctx, req.UserID, claimToken, deepReviewClaimTTL)
		if err != nil {
			if waiting {
				s.logRecoveryWaitFinished(req, started, "failed")
			}
			return "", false, "", err
		}
		switch status {
		case DeepReviewClaimMissing:
			if waiting {
				s.logRecoveryWaitFinished(req, started, "cleared")
			}
			return "", false, "", nil
		case DeepReviewClaimAcquired:
			if waiting {
				s.logRecoveryWaitFinished(req, started, "acquired")
			}
			return stateToken, true, claimToken, nil
		case DeepReviewClaimBusy:
		default:
			return "", false, "", errors.New("prompt audit deep review claim response invalid")
		}

		if !waiting {
			waiting = true
			LogInfo(EventRecoveryWaitStarted, mergeLogFields(requestLogFields(req), map[string]any{
				"recovery_source": "recovery", "status": "waiting",
			}))
		}
		wait := delay + time.Duration(int64(delay)*int64(jitter[0])/1024)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			s.logRecoveryWaitFinished(req, started, "canceled")
			return "", false, "", ctx.Err()
		case <-timer.C:
		}
		if delay < deepReviewClaimPollMax {
			delay *= 2
			if delay > deepReviewClaimPollMax {
				delay = deepReviewClaimPollMax
			}
		}
	}
}

func (s *PromptService) logRecoveryWaitFinished(req Request, started time.Time, status string) {
	now := time.Now().UTC()
	if s != nil && s.clock != nil {
		now = s.clock.Now()
	}
	latency := now.Sub(started)
	if latency < 0 {
		latency = 0
	}
	LogInfo(EventRecoveryWaitFinished, mergeLogFields(requestLogFields(req), map[string]any{
		"recovery_source": "recovery", "status": status, "latency_ms": latency.Milliseconds(),
	}))
}

func (s *PromptService) releaseRequiredDeepReviewClaim(req Request, claim string) {
	if err := s.releaseRequiredDeepReviewClaimNow(req, claim); err != nil {
		s.observeRecoveryStateFailure(req, ErrorCodeDeepReviewState)
	}
}

func (s *PromptService) releaseRequiredDeepReviewClaimNow(req Request, claim string) error {
	if s == nil || s.state == nil || strings.TrimSpace(claim) == "" {
		return errors.New("prompt audit deep review claim unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), allowReceiptOperationTimeout)
	defer cancel()
	released, err := s.state.ReleaseClaim(ctx, req.UserID, claim)
	if err != nil {
		return err
	}
	if !released {
		return errors.New("prompt audit deep review claim changed")
	}
	return nil
}

func (s *PromptService) finishRequiredDeepReview(ctx context.Context, req Request, stateToken, claimToken string, decision *PromptDecision) (*PromptDecision, error) {
	if decision == nil || s == nil || s.state == nil {
		if s != nil {
			s.observeRecoveryStateFailure(req, ErrorCodeDeepReviewState)
		}
		return nil, &GuardError{Code: ErrorCodeDeepReviewState}
	}
	decision.DeepReviewed = true
	if decision.Kind == DecisionAllow {
		cfg, active := s.config.Active()
		if !active || cfg.EffectiveMode() != ModeBlocking || !cfg.IncludesGroup(req.GroupID) || cfg.IsBlockingExempt(req.UserID) {
			return decision, nil
		}
		cleared, err := s.state.ClearClaimed(ctx, req.UserID, stateToken, claimToken)
		if err != nil || !cleared {
			if err == nil {
				err = errors.New("prompt audit deep review state changed")
			}
			s.observeRecoveryStateFailure(req, ErrorCodeDeepReviewState)
			return nil, &GuardError{Code: ErrorCodeDeepReviewState, Cause: err}
		}
		if s.metrics != nil {
			s.metrics.IncRecoveryCleared()
		}
		LogInfo(EventRecoveryCleared, mergeLogFields(requestLogFields(req), map[string]any{
			"recovery_source": "recovery", "decision": DecisionAllow, "status": "cleared",
		}))
		return decision, nil
	}
	if decision.Kind == DecisionFlag || decision.Kind == DecisionBlock {
		decision.Kind = DecisionBlock
		decision.ErrorCode = ErrorCodeDeepReviewRequired
		decision.AllowNextStage = false
	}
	s.observeRecoveryRetained(req, decision.Kind, decision.ErrorCode)
	return decision, nil
}

func markDeepReviewRequired(ctx context.Context, state DeepReviewStateStore, metrics Metrics, userID int64, token string, mode Mode, fields map[string]any) error {
	source := "blocking"
	if mode == ModeAsyncDeep {
		source = "async_deep"
	}
	if state == nil {
		if metrics != nil {
			metrics.IncRecoveryError()
		}
		LogWarn(EventRecoveryStateFailed, mergeLogFields(fields, map[string]any{
			"recovery_source": source, "status": "failed", "error_code": ErrorCodeDeepReviewState,
		}))
		return errors.New("prompt audit deep review state unavailable")
	}
	if err := state.Require(ctx, userID, token); err != nil {
		if metrics != nil {
			metrics.IncRecoveryError()
		}
		LogWarn(EventRecoveryStateFailed, mergeLogFields(fields, map[string]any{
			"recovery_source": source, "status": "failed", "error_code": ErrorCodeDeepReviewState,
		}))
		return err
	}
	if metrics != nil {
		metrics.IncRecoveryRequired(mode)
	}
	LogInfo(EventRecoveryRequired, mergeLogFields(fields, map[string]any{
		"recovery_source": source, "status": "required",
	}))
	return nil
}

func (s *PromptService) observeRecoveryRetained(req Request, decision DecisionKind, code string) {
	if s.metrics != nil {
		s.metrics.IncRecoveryRetained()
	}
	LogWarn(EventRecoveryRetained, mergeLogFields(requestLogFields(req), map[string]any{
		"recovery_source": "recovery", "decision": decision, "status": "retained", "error_code": code,
	}))
}

func (s *PromptService) observeRecoveryStateFailure(req Request, code string) {
	if s.metrics != nil {
		s.metrics.IncRecoveryError()
	}
	LogWarn(EventRecoveryStateFailed, mergeLogFields(requestLogFields(req), map[string]any{
		"recovery_source": "recovery", "status": "failed", "error_code": code,
	}))
}

func (s *PromptService) GetConfig() (PublicConfig, error) { return s.config.Public() }

func (s *PromptService) GetPassRetention() (PassRetentionConfig, error) {
	store, ok := s.config.(passRetentionConfigStore)
	if !ok {
		return PassRetentionConfig{}, infraerrors.ServiceUnavailable(ErrorCodeConfigUnavailable, "Pass 完整证据留存配置暂不可用")
	}
	return store.PublicPassRetention()
}

func (s *PromptService) SaveConfig(ctx context.Context, req UpdateConfigRequest, actorID int64) (PublicConfig, error) {
	return s.config.Save(ctx, req, actorID)
}

func (s *PromptService) SavePassRetention(ctx context.Context, req UpdatePassRetentionRequest, actorID int64) (PassRetentionConfig, error) {
	store, ok := s.config.(passRetentionConfigStore)
	if !ok {
		return PassRetentionConfig{}, infraerrors.ServiceUnavailable(ErrorCodeConfigUnavailable, "Pass 完整证据留存配置暂不可用")
	}
	return store.SavePassRetention(ctx, req, actorID)
}

func (s *PromptService) Runtime(ctx context.Context) RuntimeSnapshot {
	expected, activeVersion, loadedAt, loadError := s.config.RuntimeState()
	cfg, hasConfig := s.config.Active()
	mode := s.EffectiveMode()
	workerTotal, queueCapacity := 0, 0
	if hasConfig {
		workerTotal, queueCapacity = cfg.WorkerCount, cfg.QueueCapacity
	}
	runtime := RuntimeSnapshot{
		ProcessStatus: "disabled", EffectiveMode: mode, ExpectedConfigVersion: expected,
		ActiveConfigVersion: activeVersion, ConfigLoadedAt: loadedAt, ConfigLoadError: loadError,
		WorkerTotal: workerTotal, QueueCapacity: queueCapacity, DatabaseStatus: "ok", RedisStatus: "ok",
		Endpoints: s.probeSnapshot(), GuardMetrics: s.metrics.Snapshot(),
	}
	if s.repo != nil {
		stats, err := s.repo.QueueStats(ctx)
		if err != nil {
			runtime.DatabaseStatus = "error"
			runtime.LastErrorCode = "database_unavailable"
			now := s.clock.Now()
			runtime.LastErrorAt = &now
			logPromptRuntimeFailure(EventProcessFailed, "queue_stats_failed")
		} else {
			runtime.Queue = stats
		}
	} else {
		runtime.DatabaseStatus = "error"
		now := s.clock.Now()
		applyRuntimeError(&runtime, "database_unavailable", "", &now)
	}
	payloadUnavailable := s.payload == nil
	if !payloadUnavailable {
		payloadUnavailable = s.payload.Ping(ctx) != nil
	}
	if payloadUnavailable {
		runtime.RedisStatus = "error"
		if runtime.LastErrorCode == "" {
			runtime.LastErrorCode = "payload_store_unavailable"
			now := s.clock.Now()
			runtime.LastErrorAt = &now
		}
		logPromptRuntimeFailure(EventProcessFailed, "payload_store_unavailable")
	}
	activeWorkers, processed, failed, heartbeat, lastProcessed, workerCode, workerMessage := s.runner.Snapshot()
	runtime.WorkerActive, runtime.ProcessedTotal, runtime.FailedTotal = activeWorkers, processed, failed
	if s.metrics != nil {
		auditMetrics := s.metrics.AuditSnapshot()
		runtime.EnqueuedTotal, runtime.DroppedTotal = auditMetrics.Enqueued, auditMetrics.Dropped
		runtime.ExtractionAttempted = auditMetrics.ExtractionAttempted
		runtime.ExtractionSucceeded = auditMetrics.ExtractionSucceeded
		runtime.ExtractionEmpty = auditMetrics.ExtractionEmpty
		runtime.ExtractionFailed = auditMetrics.ExtractionFailed
		runtime.AllowReceiptHits = auditMetrics.AllowReceiptHits
		runtime.AllowReceiptMisses = auditMetrics.AllowReceiptMisses
		runtime.AllowReceiptWrites = auditMetrics.AllowReceiptWrites
		runtime.AllowReceiptErrors = auditMetrics.AllowReceiptErrors
		runtime.RecoveryRequiredSync = auditMetrics.RecoveryRequiredSync
		runtime.RecoveryRequiredAsync = auditMetrics.RecoveryRequiredAsync
		runtime.RecoveryCleared = auditMetrics.RecoveryCleared
		runtime.RecoveryRetained = auditMetrics.RecoveryRetained
		runtime.RecoveryErrors = auditMetrics.RecoveryErrors
	}
	runtime.WorkerHeartbeatAt, runtime.LastProcessedAt = heartbeat, lastProcessed
	if workerCode != "" {
		runtime.LastErrorCode, runtime.LastErrorMessage = workerCode, workerMessage
		runtime.LastErrorAt = s.runner.LastErrorAt()
	}
	if mode != ModeOff {
		runtime.ProcessStatus = "running"
		if loadError != "" || runtime.DatabaseStatus != "ok" || runtime.RedisStatus != "ok" || activeVersion != expected {
			runtime.ProcessStatus = "degraded"
		}
		if heartbeat == nil || s.clock.Now().Sub(*heartbeat) > 10*time.Second {
			runtime.ProcessStatus = "degraded"
		}
	}
	return runtime
}

func applyRuntimeError(runtime *RuntimeSnapshot, code, message string, occurredAt *time.Time) {
	if runtime == nil || code == "" {
		return
	}
	if runtime.LastErrorCode != "" {
		if occurredAt == nil || runtime.LastErrorAt != nil && !occurredAt.After(*runtime.LastErrorAt) {
			return
		}
	}
	runtime.LastErrorCode = code
	runtime.LastErrorMessage = message
	runtime.LastErrorAt = occurredAt
}

type ProbeRequest struct {
	Endpoint UpdateEndpoint `json:"endpoint"`
}

func (s *PromptService) Probe(ctx context.Context, request ProbeRequest) ProbeResult {
	started := s.clock.Now()
	endpoint, tokenApplied, err := s.resolveProbeEndpoint(request.Endpoint)
	if err != nil {
		return s.finishProbe(request.Endpoint.ID, started, ProbeResult{Status: "failed", ErrorCode: "endpoint_invalid", Message: "审计节点配置无效"})
	}
	LogInfo(EventProbeStarted, map[string]any{"guard_endpoint_id": endpoint.ID, "status": "started"})
	client, err := NewSecureHTTPClient(endpoint)
	if err != nil {
		return s.finishProbe(endpoint.ID, started, ProbeResult{Status: "failed", ErrorCode: "endpoint_unsafe", Message: "审计节点地址不在允许范围", TokenApplied: tokenApplied})
	}
	modelsURL, _ := ModelsURL(endpoint.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, modelsURL, nil)
	if err != nil {
		return s.finishProbe(endpoint.ID, started, ProbeResult{Status: "failed", ErrorCode: "probe_request_invalid", Message: "无法创建探测请求", TokenApplied: tokenApplied})
	}
	if endpoint.Token != "" {
		req.Header.Set("Authorization", "Bearer "+endpoint.Token)
	}
	resp, err := client.Do(req)
	if err != nil {
		code := "connection_failed"
		var netErr net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
			code = "timeout"
		}
		return s.finishProbe(endpoint.ID, started, ProbeResult{Status: "failed", ErrorCode: code, Message: "无法连接审计节点", Retryable: true, TokenApplied: tokenApplied})
	}
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxGuardResponseBytes+1))
	_ = resp.Body.Close()
	if readErr != nil {
		return s.finishProbe(endpoint.ID, started, ProbeResult{Status: "failed", ErrorCode: "response_read_failed", Message: "审计节点响应读取失败", HTTPStatus: resp.StatusCode, Retryable: true, TokenApplied: tokenApplied})
	}
	if int64(len(responseBody)) > maxGuardResponseBytes {
		return s.finishProbe(endpoint.ID, started, ProbeResult{Status: "failed", ErrorCode: "response_too_large", Message: "审计节点响应无效", HTTPStatus: resp.StatusCode, TokenApplied: tokenApplied})
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && modelsResponseReady(responseBody, endpoint.Model) {
		return s.finishProbe(endpoint.ID, started, ProbeResult{OK: true, Status: "healthy", Message: "审计节点连接正常", HTTPStatus: resp.StatusCode, TokenApplied: tokenApplied})
	}
	if (resp.StatusCode >= 200 && resp.StatusCode < 300) || resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		result, scanErr := s.scanner.Scan(ctx, endpoint, "Hello", AllScannerIDs)
		if scanErr == nil && result != nil {
			return s.finishProbe(endpoint.ID, started, ProbeResult{OK: true, Status: "healthy", Message: "审计节点模型调用正常", HTTPStatus: http.StatusOK, TokenApplied: tokenApplied})
		}
		code, status, retryable := guardErrorCode(scanErr), 0, false
		var guardErr *GuardError
		if errors.As(scanErr, &guardErr) {
			status, retryable = guardErr.HTTPStatus, guardErr.Retryable
		}
		if code == "" {
			code = ErrorCodeInvalidResponse
		}
		return s.finishProbe(endpoint.ID, started, ProbeResult{Status: "failed", ErrorCode: code, Message: "审计节点模型调用失败", HTTPStatus: status, Retryable: retryable, TokenApplied: tokenApplied})
	}
	code, retryable := "probe_http_error", resp.StatusCode == 429 || resp.StatusCode >= 500
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		code = "authentication_failed"
	}
	return s.finishProbe(endpoint.ID, started, ProbeResult{Status: "failed", ErrorCode: code, Message: "审计节点探测失败", HTTPStatus: resp.StatusCode, Retryable: retryable, TokenApplied: tokenApplied})
}

func modelsResponseReady(body []byte, model string) bool {
	var response struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &response) != nil || response.Data == nil {
		return false
	}
	model = strings.TrimSpace(model)
	if model == "" {
		return true
	}
	for _, item := range response.Data {
		if strings.TrimSpace(item.ID) == model {
			return true
		}
	}
	return false
}

func (s *PromptService) resolveProbeEndpoint(input UpdateEndpoint) (ActiveEndpoint, bool, error) {
	baseURL, err := NormalizeBaseURL(input.BaseURL)
	if err != nil {
		return ActiveEndpoint{}, false, err
	}
	token := strings.TrimSpace(input.Token)
	if token == "" {
		if cfg, ok := s.config.Active(); ok {
			for _, endpoint := range cfg.Endpoints {
				if endpoint.ID != strings.TrimSpace(input.ID) {
					continue
				}
				// Reuse a stored credential only when the probe targets the same
				// normalized base URL. Otherwise an admin probe could exfiltrate
				// the Guard token to an attacker-controlled HTTPS host.
				if endpoint.BaseURL == baseURL {
					token = endpoint.Token
				}
				break
			}
		}
	}
	model := strings.TrimSpace(input.Model)
	if model == "" {
		model = DefaultGuardModel
	}
	timeout := input.TimeoutMS
	if timeout == 0 {
		timeout = DefaultTimeoutMS
	}
	limit := input.InputLimit
	if limit == 0 {
		limit = DefaultInputLimit
	}
	storage := storageConfig{Enabled: false, Strategy: "priority", WorkerCount: DefaultWorkerCount, QueueCapacity: DefaultQueueCapacity, AllowReceiptTTLSeconds: DefaultAllowReceiptTTLSeconds, Scanners: append([]string(nil), AllScannerIDs...), AllGroups: true,
		Endpoints: []StorageEndpoint{{ID: strings.TrimSpace(input.ID), Name: strings.TrimSpace(input.Name), Protocol: "openai_compatible", BaseURL: baseURL, Model: model, TimeoutMS: timeout, InputLimit: limit}}}
	if storage.Endpoints[0].ID == "" {
		storage.Endpoints[0].ID = "probe"
	}
	if storage.Endpoints[0].Name == "" {
		storage.Endpoints[0].Name = "Probe"
	}
	if err := validateStorageConfig(storage); err != nil {
		return ActiveEndpoint{}, false, err
	}
	return ActiveEndpoint{ID: storage.Endpoints[0].ID, Name: storage.Endpoints[0].Name, Protocol: "openai_compatible", BaseURL: baseURL, Model: model, Token: token, TimeoutMS: timeout, InputLimit: limit, Enabled: true}, token != "", nil
}

func (s *PromptService) finishProbe(id string, started time.Time, result ProbeResult) ProbeResult {
	result.CheckedAt = s.clock.Now()
	result.LatencyMS = int(result.CheckedAt.Sub(started).Milliseconds())
	if result.OK {
		LogInfo(EventProbeFinished, map[string]any{"guard_endpoint_id": id, "status": result.Status, "latency_ms": result.LatencyMS, "http_status": result.HTTPStatus})
	} else {
		LogWarn(EventProbeFailed, map[string]any{"guard_endpoint_id": id, "status": result.Status, "latency_ms": result.LatencyMS, "http_status": result.HTTPStatus, "error_code": result.ErrorCode, "retryable": result.Retryable})
	}
	s.probeMu.Lock()
	s.probes[id] = result
	s.probeMu.Unlock()
	return result
}

func (s *PromptService) probeSnapshot() map[string]ProbeResult {
	s.probeMu.RLock()
	defer s.probeMu.RUnlock()
	result := make(map[string]ProbeResult, len(s.probes))
	for id, probe := range s.probes {
		result[id] = probe
	}
	return result
}

func (s *PromptService) ListEvents(ctx context.Context, filter EventFilter, page, pageSize int) (*EventPage, error) {
	return s.repo.ListEvents(ctx, filter, page, pageSize)
}
func (s *PromptService) GetEvent(ctx context.Context, id int64) (*Event, error) {
	return s.repo.GetEvent(ctx, id)
}

func (s *PromptService) DownloadEventContext(ctx context.Context, id int64) (*EventContextDownload, error) {
	record, err := s.repo.GetEventContext(ctx, id)
	if err != nil {
		return nil, err
	}
	raw, err := decryptCompletePromptContext(s.config, record.Ciphertext)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != record.SHA256 || !json.Valid(raw) {
		return nil, errors.New("prompt audit event context integrity check failed")
	}
	return &EventContextDownload{JSON: raw, SHA256: record.SHA256}, nil
}

func (s *PromptService) DeleteEvent(ctx context.Context, id int64) (*DeleteResult, error) {
	result, err := s.repo.DeleteEvent(ctx, id)
	if err == nil {
		s.deletePayloads(ctx, result.JobIDs)
	}
	return result, err
}
func (s *PromptService) DeleteEventsByIDs(ctx context.Context, ids []int64) (*DeleteResult, error) {
	result, err := s.repo.DeleteEventsByIDs(ctx, ids)
	if err == nil {
		s.deletePayloads(ctx, result.JobIDs)
	}
	return result, err
}

type deleteClaims struct {
	FilterHash    string    `json:"filter_hash"`
	SnapshotMaxID int64     `json:"snapshot_max_id"`
	AdminID       int64     `json:"admin_id"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func (s *PromptService) PreviewDelete(ctx context.Context, filter EventFilter, adminID int64) (*DeletePreview, error) {
	preview, err := s.repo.PreviewDelete(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	expires := now.Add(5 * time.Minute)
	claimsRaw, _ := json.Marshal(deleteClaims{FilterHash: preview.FilterHash, SnapshotMaxID: preview.SnapshotMaxID, AdminID: adminID, IssuedAt: now, ExpiresAt: expires})
	token, err := s.config.Encrypt(string(claimsRaw))
	if err != nil {
		return nil, err
	}
	preview.ConfirmationToken, preview.ExpiresAt = token, expires
	LogInfo(EventDeletePreviewed, map[string]any{"user_id": adminID, "status": "previewed"})
	return preview, nil
}

type DeleteByFilterRequest struct {
	Filter            EventFilter `json:"filter"`
	SnapshotMaxID     int64       `json:"snapshot_max_id"`
	FilterHash        string      `json:"filter_hash"`
	ConfirmationToken string      `json:"confirmation_token"`
	Confirm           bool        `json:"confirm"`
}

func (s *PromptService) DeleteByFilter(ctx context.Context, request DeleteByFilterRequest, adminID int64) (*DeleteResult, error) {
	if !request.Confirm {
		return nil, errors.New("prompt audit filter delete requires confirm=true")
	}
	plain, err := s.config.Decrypt(strings.TrimSpace(request.ConfirmationToken))
	if err != nil {
		return nil, errors.New("prompt audit confirmation token invalid")
	}
	var claims deleteClaims
	if json.Unmarshal([]byte(plain), &claims) != nil {
		return nil, errors.New("prompt audit confirmation token invalid")
	}
	computed := FilterHash(request.Filter, request.SnapshotMaxID)
	if claims.AdminID != adminID || claims.SnapshotMaxID != request.SnapshotMaxID || claims.FilterHash != request.FilterHash || request.FilterHash != computed || !s.clock.Now().Before(claims.ExpiresAt) {
		return nil, errors.New("prompt audit confirmation token does not match deletion request")
	}
	result, err := s.repo.DeleteEventsByFilter(ctx, request.Filter, request.SnapshotMaxID, 200)
	if err == nil {
		s.deletePayloads(ctx, result.JobIDs)
		LogWarn(EventEventsFilterDeleted, map[string]any{"user_id": adminID, "status": "deleted"})
	}
	return result, err
}

func (s *PromptService) deletePayloads(ctx context.Context, jobIDs []int64) {
	for _, id := range jobIDs {
		_ = s.payload.Delete(ctx, id)
	}
}

func parseTimeQuery(value string) *time.Time {
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return nil
	}
	parsed = parsed.UTC()
	return &parsed
}
