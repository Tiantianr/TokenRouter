package securityaudit

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeAllowReceiptPayload struct {
	mu        sync.Mutex
	values    map[string]bool
	payloads  map[int64]string
	states    map[int64]string
	claims    map[int64]string
	lookupErr error
	storeErr  error
	lastTTL   time.Duration
	writes    int
}

func newFakeAllowReceiptPayload() *fakeAllowReceiptPayload {
	return &fakeAllowReceiptPayload{values: map[string]bool{}, payloads: map[int64]string{}, states: map[int64]string{}, claims: map[int64]string{}}
}

func (s *fakeAllowReceiptPayload) Set(_ context.Context, jobID int64, value string, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.payloads[jobID] = value
	return nil
}
func (s *fakeAllowReceiptPayload) Get(_ context.Context, jobID int64) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.payloads[jobID]
	if !ok {
		return "", errors.New("payload missing")
	}
	return value, nil
}
func (s *fakeAllowReceiptPayload) Delete(_ context.Context, jobID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.payloads, jobID)
	return nil
}
func (s *fakeAllowReceiptPayload) Ping(context.Context) error { return nil }
func (s *fakeAllowReceiptPayload) Required(_ context.Context, userID int64) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token := s.states[userID]
	return token, token != "", nil
}
func (s *fakeAllowReceiptPayload) Require(_ context.Context, userID int64, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[userID] = token
	return nil
}
func (s *fakeAllowReceiptPayload) Claim(_ context.Context, userID int64, token string, _ time.Duration) (string, DeepReviewClaimStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	finding := s.states[userID]
	if finding == "" {
		return "", DeepReviewClaimMissing, nil
	}
	if s.claims[userID] != "" {
		return "", DeepReviewClaimBusy, nil
	}
	s.claims[userID] = token
	return finding, DeepReviewClaimAcquired, nil
}
func (s *fakeAllowReceiptPayload) ReleaseClaim(_ context.Context, userID int64, token string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.claims[userID] != token {
		return false, nil
	}
	delete(s.claims, userID)
	return true, nil
}
func (s *fakeAllowReceiptPayload) ClearClaimed(_ context.Context, userID int64, finding, claim string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states[userID] != finding || s.claims[userID] != claim {
		return false, nil
	}
	delete(s.states, userID)
	return true, nil
}
func (s *fakeAllowReceiptPayload) ReceiptsAllowed(_ context.Context, userID int64, keys []string) ([]bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lookupErr != nil {
		return nil, s.lookupErr
	}
	result := make([]bool, len(keys))
	for index, key := range keys {
		result[index] = s.values[allowReceiptTestKey(userID, key)]
	}
	return result, nil
}
func (s *fakeAllowReceiptPayload) StoreAllowReceipts(_ context.Context, userID int64, keys []string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.storeErr != nil {
		return s.storeErr
	}
	for _, key := range keys {
		s.values[allowReceiptTestKey(userID, key)] = true
	}
	s.lastTTL = ttl
	s.writes += len(keys)
	return nil
}

func allowReceiptTestKey(userID int64, key string) string {
	return strings.Join([]string{strconv.FormatInt(userID, 10), key}, ":")
}

func TestBlockingCurrentUserReusesExactAllowReceipt(t *testing.T) {
	cfg := allowReceiptTestConfig()
	config := &fakeConfigStore{active: true, cfg: cfg}
	cache := newFakeAllowReceiptPayload()
	metrics := NewAtomicMetrics()
	phase := 1
	var scanned []string
	scanner := PromptScannerFunc(func(_ context.Context, _ ActiveEndpoint, chunk string, _ []string) (*NormalizedResult, error) {
		scanned = append(scanned, chunk)
		if phase == 1 && strings.Contains(chunk, "stable system attachment") {
			return allowReceiptResult(ActionWarn), nil
		}
		return allowReceiptResult(ActionAllow), nil
	})
	service := NewPromptService(config, nil, cache, NewOpenAICompatibleScanner(), metrics)
	service.evaluator = NewGuardEvaluator(scanner, nil, metrics)
	req := allowReceiptRequest(7, "first user input", "stable system attachment")

	decision, err := service.Evaluate(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, DecisionFlag, decision.Kind)
	require.Zero(t, cache.writes, "Warn must not create Allow receipts")
	require.Len(t, scanned, 2)

	phase = 2
	scanned = nil
	decision, err = service.Evaluate(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, DecisionAllow, decision.Kind)
	require.Zero(t, cache.writes, "Prompt Guard Allow remains pending until combined Allow")
	service.commitAllowReceipts(context.Background(), decision)
	require.Equal(t, 2, cache.writes)
	require.Equal(t, time.Hour, cache.lastTTL)
	require.Len(t, scanned, 2)

	phase = 3
	scanned = nil
	decision, err = service.Evaluate(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, DecisionAllow, decision.Kind)
	service.commitAllowReceipts(context.Background(), decision)
	require.Equal(t, 2, cache.writes)
	require.Empty(t, scanned)
	repo := &fakeJobRepository{}
	require.NoError(t, NewEnqueuer(config, repo, cache, metrics).EnqueueDeep(context.Background(), req))
	require.Nil(t, repo.createJob)

	audit := metrics.AuditSnapshot()
	require.Equal(t, int64(4), audit.AllowReceiptHits)
	require.Equal(t, int64(4), audit.AllowReceiptMisses)
	require.Equal(t, int64(2), audit.AllowReceiptWrites)
}

func TestBlockingCurrentReceiptReusesTextWhenMediaChanges(t *testing.T) {
	cfg := allowReceiptTestConfig()
	config := &fakeConfigStore{active: true, cfg: cfg}
	receipts := newFakeAllowReceiptPayload()
	scans := 0
	service := NewPromptService(config, nil, receipts, NewOpenAICompatibleScanner(), NewAtomicMetrics())
	seen := ""
	service.evaluator = NewGuardEvaluator(PromptScannerFunc(func(_ context.Context, _ ActiveEndpoint, chunk string, _ []string) (*NormalizedResult, error) {
		scans++
		seen = chunk
		return allowReceiptResult(ActionAllow), nil
	}), nil, NewAtomicMetrics())

	firstMarker := strings.Repeat("a", 40)
	decision, err := service.Evaluate(context.Background(), allowReceiptMediaRequest(firstMarker))
	require.NoError(t, err)
	require.Equal(t, DecisionAllow, decision.Kind)
	require.Equal(t, 1, scans)
	require.Contains(t, seen, "[images:"+firstMarker+"]")
	service.commitAllowReceipts(context.Background(), decision)

	scans = 0
	decision, err = service.Evaluate(context.Background(), allowReceiptMediaRequest(strings.Repeat("b", 40)))
	require.NoError(t, err)
	require.Equal(t, DecisionAllow, decision.Kind)
	require.Zero(t, scans)
}

func TestAllowReceiptKeyNormalizesOnlyOpaqueUserMediaMarkers(t *testing.T) {
	cfg := allowReceiptTestConfig()
	first := "fixed instruction [images:" + strings.Repeat("a", 40) + "]"
	second := "fixed instruction [images:" + strings.Repeat("b", 40) + "]"

	require.Equal(t, buildAllowReceiptKey(cfg, "user", first), buildAllowReceiptKey(cfg, "user", second))
	require.NotEqual(t, buildAllowReceiptKey(cfg, "user", first), buildAllowReceiptKey(cfg, "user", "changed instruction [images:"+strings.Repeat("b", 40)+"]"))
	require.NotEqual(t, buildAllowReceiptKey(cfg, "system", first), buildAllowReceiptKey(cfg, "system", second))
	require.NotEqual(t, buildAllowReceiptKey(cfg, "user", "fixed instruction [images:not-hex]"), buildAllowReceiptKey(cfg, "user", "fixed instruction [images:still-not-hex]"))
}

func TestAllowReceiptsMissOnUserConfigAndContentChanges(t *testing.T) {
	cfg := allowReceiptTestConfig()
	cache := newFakeAllowReceiptPayload()
	metrics := NewAtomicMetrics()
	snapshot, _, err := extractBlockingPromptSnapshotWithDiagnostics(
		allowReceiptRequest(7, "user input", "stable attachment"), cfg.BlockingReviewModules,
	)
	require.NoError(t, err)
	prepareAllowReceipts(context.Background(), cache, metrics, cfg, &snapshot, nil, false)
	storeAllowReceipts(context.Background(), cache, metrics, cfg, snapshot)

	for _, testCase := range []struct {
		name        string
		cfg         ActiveConfig
		req         Request
		wantHits    int
		wantScan    string
		wantOmitted string
	}{
		{name: "other user", cfg: cfg, req: allowReceiptRequest(8, "user input", "stable attachment"), wantScan: "user input"},
		{name: "new config", cfg: func() ActiveConfig { changed := cfg; changed.ConfigVersion++; return changed }(), req: allowReceiptRequest(7, "user input", "stable attachment"), wantScan: "user input"},
		{name: "changed attachment", cfg: cfg, req: allowReceiptRequest(7, "user input", "changed attachment"), wantHits: 1, wantScan: "changed attachment", wantOmitted: "user input"},
		{name: "changed current user", cfg: cfg, req: allowReceiptRequest(7, "changed user input", "stable attachment"), wantHits: 1, wantScan: "changed user input", wantOmitted: "stable attachment"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			candidate, _, extractErr := extractBlockingPromptSnapshotWithDiagnostics(testCase.req, testCase.cfg.BlockingReviewModules)
			require.NoError(t, extractErr)
			prepareAllowReceipts(context.Background(), cache, metrics, testCase.cfg, &candidate, nil, false)
			require.Equal(t, testCase.wantHits, candidate.AllowReceiptHitCount)
			require.Contains(t, candidate.ScanText, testCase.wantScan)
			if testCase.wantOmitted != "" {
				require.NotContains(t, candidate.ScanText, testCase.wantOmitted)
			}
		})
	}
}

func TestAllowReceiptLookupErrorFallsBackToReview(t *testing.T) {
	cfg := allowReceiptTestConfig()
	cache := newFakeAllowReceiptPayload()
	cache.lookupErr = errors.New("redis unavailable")
	metrics := NewAtomicMetrics()
	snapshot, _, err := extractBlockingPromptSnapshotWithDiagnostics(
		allowReceiptRequest(7, "user input", "stable attachment"), cfg.BlockingReviewModules,
	)
	require.NoError(t, err)
	original := snapshot.ScanText

	prepareAllowReceipts(context.Background(), cache, metrics, cfg, &snapshot, nil, false)

	require.Zero(t, snapshot.AllowReceiptHitCount)
	require.Equal(t, original, snapshot.ScanText)
	require.Equal(t, int64(1), metrics.AuditSnapshot().AllowReceiptErrors)
}

func TestAllowReceiptBlockAndStoreFailureNeverCreateExemption(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		action     Action
		storeError error
		wantKind   DecisionKind
	}{
		{name: "Block", action: ActionBlock, wantKind: DecisionBlock},
		{name: "store failure", action: ActionAllow, storeError: errors.New("redis unavailable"), wantKind: DecisionAllow},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := allowReceiptTestConfig()
			config := &fakeConfigStore{active: true, cfg: cfg}
			cache := newFakeAllowReceiptPayload()
			cache.storeErr = testCase.storeError
			metrics := NewAtomicMetrics()
			scans := 0
			service := NewPromptService(config, nil, cache, NewOpenAICompatibleScanner(), metrics)
			service.evaluator = NewGuardEvaluator(PromptScannerFunc(func(_ context.Context, _ ActiveEndpoint, chunk string, _ []string) (*NormalizedResult, error) {
				scans++
				if strings.Contains(chunk, "stable attachment") {
					return allowReceiptResult(testCase.action), nil
				}
				return allowReceiptResult(ActionAllow), nil
			}), nil, metrics)
			req := allowReceiptRequest(7, "user input", "stable attachment")

			decision, err := service.Evaluate(context.Background(), req)
			require.NoError(t, err)
			require.Equal(t, testCase.wantKind, decision.Kind)
			service.commitAllowReceipts(context.Background(), decision)
			require.Zero(t, cache.writes)

			scans = 0
			_, _ = service.Evaluate(context.Background(), req)
			require.Equal(t, 2, scans, "the attachment must be reviewed again")
		})
	}
}

func TestAllowReceiptDependencyAndInvalidFailuresNeverCreateReceipts(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		scanErr error
	}{
		{name: "timeout", scanErr: &GuardError{Code: ErrorCodeUnavailable, Retryable: true, Timeout: true}},
		{name: "invalid response"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := allowReceiptTestConfig()
			receipts := newFakeAllowReceiptPayload()
			metrics := NewAtomicMetrics()
			service := NewPromptService(&fakeConfigStore{active: true, cfg: cfg}, nil, receipts, NewOpenAICompatibleScanner(), metrics)
			service.evaluator = NewGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
				if testCase.scanErr != nil {
					return nil, testCase.scanErr
				}
				return nil, nil
			}), nil, metrics)

			decision, err := service.Evaluate(context.Background(), allowReceiptRequest(7, "user input", "system input"))
			if testCase.scanErr != nil {
				require.NoError(t, err)
				require.True(t, decision.AllowNextStage)
				require.True(t, decision.FailureAllowed)
			} else {
				require.Error(t, err)
				require.Nil(t, decision)
			}
			require.Zero(t, receipts.writes)
			require.Empty(t, receipts.values)
		})
	}
}

func TestAllowReceiptReusesStableSiblingAndReviewsChangedSegment(t *testing.T) {
	cfg := allowReceiptTestConfig()
	cfg.BlockingReviewModules.Assistant = true
	cache := newFakeAllowReceiptPayload()
	metrics := NewAtomicMetrics()
	first, _, err := extractBlockingPromptSnapshotWithDiagnostics(
		allowReceiptAssistantRequest("first assistant"), cfg.BlockingReviewModules,
	)
	require.NoError(t, err)
	prepareAllowReceipts(context.Background(), cache, metrics, cfg, &first, nil, false)
	require.Len(t, first.AllowReceiptKeys, 4)
	storeAllowReceipts(context.Background(), cache, metrics, cfg, first)

	second, _, err := extractBlockingPromptSnapshotWithDiagnostics(
		allowReceiptAssistantRequest("changed assistant"), cfg.BlockingReviewModules,
	)
	require.NoError(t, err)
	prepareAllowReceipts(context.Background(), cache, metrics, cfg, &second, nil, false)

	require.Equal(t, 3, second.AllowReceiptHitCount)
	require.Len(t, second.AllowReceiptKeys, 1)
	require.Contains(t, second.ScanText, "changed assistant")
	require.NotContains(t, second.ScanText, "current user input")
	require.NotContains(t, second.ScanText, "stable system attachment")
	require.NotContains(t, second.ScanText, "stable assistant")
}

func TestAsyncCurrentUserReviewsAgainWhileHistoryUsesReceipts(t *testing.T) {
	cfg := allowReceiptTestConfig()
	cfg.BlockingEnabled = false
	config := &fakeConfigStore{active: true, cfg: cfg}
	cache := newFakeAllowReceiptPayload()
	metrics := NewAtomicMetrics()
	repo := &fakeJobRepository{}
	req := allowReceiptHistoryRequest()
	req.AllowReceiptWrite = true

	require.NoError(t, NewEnqueuer(config, repo, cache, metrics).Enqueue(context.Background(), req))
	firstPayload := decodeTransientPromptPayload(cache.payloads[1])
	require.Contains(t, firstPayload.ScanText, "current async user input")
	require.Contains(t, firstPayload.ScanText, "older async user input")
	require.Contains(t, firstPayload.ScanText, "stable async attachment")
	require.NotEmpty(t, firstPayload.AllowReceiptKeys)
	require.Zero(t, firstPayload.AllowReceiptHitCount)

	repo.createJob.Attempts = 1
	repo.createJob.MaxAttempts = 3
	repo.createJob.ClaimVersion = 1
	runner := NewRunner(config, repo, cache, PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		return allowReceiptResult(ActionAllow), nil
	}), metrics)
	require.NoError(t, runner.processJob(context.Background(), 0, cfg, repo.createJob))
	require.Equal(t, 3, cache.writes)

	secondRepo := &fakeJobRepository{}
	require.NoError(t, NewEnqueuer(config, secondRepo, cache, metrics).Enqueue(context.Background(), req))
	secondPayload := decodeTransientPromptPayload(cache.payloads[1])
	require.Contains(t, secondPayload.ScanText, "current async user input")
	require.NotContains(t, secondPayload.ScanText, "older async user input")
	require.NotContains(t, secondPayload.ScanText, "stable async attachment")
	require.Equal(t, 2, secondPayload.AllowReceiptHitCount)
	require.Len(t, secondPayload.AllowReceiptKeys, 1)
}

func TestBlockingAllowForPreviousOutputIsReusedBySameRequestDeepReview(t *testing.T) {
	cfg := allowReceiptTestConfig()
	cfg.DeepReviewModules.Assistant = true
	config := &fakeConfigStore{active: true, cfg: cfg}
	receipts := newFakeAllowReceiptPayload()
	metrics := NewAtomicMetrics()
	service := NewPromptService(config, nil, receipts, NewOpenAICompatibleScanner(), metrics)
	service.evaluator = NewGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		return allowReceiptResult(ActionAllow), nil
	}), nil, metrics)
	req := Request{
		UserID: 7, Protocol: "openai_responses", Endpoint: "/v1/responses",
		Body: []byte(`{"instructions":"stable system","input":[{"type":"message","role":"assistant","content":"historical assistant"},{"type":"message","role":"user","content":"new user turn"}]}`),
	}

	decision, err := service.Evaluate(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, DecisionAllow, decision.Kind)
	require.Len(t, decision.AllowReceiptKeys, 3)
	service.commitAllowReceipts(context.Background(), decision)

	deepReq := req.Clone()
	deepReq.AllowReceiptKeys = append([]string(nil), decision.AllowReceiptKeys...)
	repo := &fakeJobRepository{}
	require.NoError(t, NewEnqueuer(config, repo, receipts, metrics).EnqueueDeep(context.Background(), deepReq))
	require.Nil(t, repo.createJob)
	require.Empty(t, receipts.payloads)
}

func TestFailureAllowedDeepReviewCannotWriteAllowReceipts(t *testing.T) {
	cfg := allowReceiptTestConfig()
	config := &fakeConfigStore{active: true, cfg: cfg}
	receipts := newFakeAllowReceiptPayload()
	metrics := NewAtomicMetrics()
	repo := &fakeJobRepository{}
	req := allowReceiptRequest(7, "failure-allowed user turn", "stable system")
	req.SuppressReceiptWrite = true

	require.NoError(t, NewEnqueuer(config, repo, receipts, metrics).EnqueueDeep(context.Background(), req))
	payload := decodeTransientPromptPayload(receipts.payloads[repo.createJob.ID])
	require.False(t, payload.AllowReceiptWrite)
	repo.createJob.Attempts = 1
	repo.createJob.MaxAttempts = 3
	repo.createJob.ClaimVersion = 1
	runner := NewRunner(config, repo, receipts, PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		return allowReceiptResult(ActionAllow), nil
	}), metrics)
	require.NoError(t, runner.processJob(context.Background(), 0, cfg, repo.createJob))
	require.Zero(t, receipts.writes)
	require.Zero(t, metrics.AuditSnapshot().AllowReceiptWrites)
}

func TestSameRequestDeepReviewSkipsJobWhenEverySegmentWasAllowed(t *testing.T) {
	cfg := allowReceiptTestConfig()
	config := &fakeConfigStore{active: true, cfg: cfg}
	receipts := newFakeAllowReceiptPayload()
	service := NewPromptService(config, nil, receipts, NewOpenAICompatibleScanner(), NewAtomicMetrics())
	service.evaluator = NewGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		return allowReceiptResult(ActionAllow), nil
	}), nil, NewAtomicMetrics())
	req := allowReceiptRequest(7, "new user turn", "stable system")

	decision, err := service.Evaluate(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, decision.AllowReceiptKeys, 2)
	service.commitAllowReceipts(context.Background(), decision)
	req.AllowReceiptKeys = append([]string(nil), decision.AllowReceiptKeys...)
	repo := &fakeJobRepository{}
	require.NoError(t, NewEnqueuer(config, repo, receipts).EnqueueDeep(context.Background(), req))
	require.Nil(t, repo.createJob)
	require.Empty(t, receipts.payloads)
}

func TestAutomaticContinuationDoesNotRunSynchronousUserGuard(t *testing.T) {
	cfg := allowReceiptTestConfig()
	cfg.BlockingReviewModules = ReviewModules{}
	receipts := newFakeAllowReceiptPayload()
	scans := 0
	seen := ""
	service := NewPromptService(&fakeConfigStore{active: true, cfg: cfg}, nil, receipts, NewOpenAICompatibleScanner(), NewAtomicMetrics())
	service.evaluator = NewGuardEvaluator(PromptScannerFunc(func(_ context.Context, _ ActiveEndpoint, chunk string, _ []string) (*NormalizedResult, error) {
		scans++
		seen += chunk
		return allowReceiptResult(ActionAllow), nil
	}), nil, NewAtomicMetrics())

	initial := Request{
		UserID: 7, Protocol: "openai_responses", Endpoint: "/v1/responses",
		Body: []byte(`{"input":[{"type":"message","role":"user","content":"original user turn"}]}`),
	}
	decision, err := service.Evaluate(context.Background(), initial)
	require.NoError(t, err)
	require.Equal(t, DecisionAllow, decision.Kind)
	service.commitAllowReceipts(context.Background(), decision)
	require.Positive(t, scans)
	scans = 0
	seen = ""

	decision, err = service.Evaluate(context.Background(), allowReceiptToolLoopRequest(true))
	require.NoError(t, err)
	require.Equal(t, DecisionAllow, decision.Kind)
	require.Zero(t, scans)
	require.Empty(t, seen)

	decision, err = service.Evaluate(context.Background(), Request{
		UserID: 7, Protocol: "openai_responses",
		Body: []byte(`{"input":[{"type":"message","role":"user","content":"unreviewed user input"},{"type":"message","role":"assistant","content":"client claimed continuation"}]}`),
	})
	require.NoError(t, err)
	require.Equal(t, DecisionAllow, decision.Kind)
	require.Positive(t, scans)
	require.Contains(t, seen, "unreviewed user input")

	scans, seen = 0, ""
	decision, err = service.Evaluate(context.Background(), Request{
		UserID: 7, Protocol: "openai_responses",
		Body: []byte(`{"input":[{"type":"message","role":"user","content":"unreviewed earlier user"},{"type":"message","role":"user","content":"benign current user"}]}`),
	})
	require.NoError(t, err)
	require.Equal(t, DecisionAllow, decision.Kind)
	require.Contains(t, seen, "unreviewed earlier user")
	require.Contains(t, seen, "benign current user")
}

func TestToolContinuationReviewsOnlyNewCanonicalSegment(t *testing.T) {
	cfg := allowReceiptTestConfig()
	cfg.DeepReviewModules = DefaultDeepReviewModules()
	config := &fakeConfigStore{active: true, cfg: cfg}
	receipts := newFakeAllowReceiptPayload()
	metrics := NewAtomicMetrics()
	firstRepo := &fakeJobRepository{}

	require.NoError(t, NewEnqueuer(config, firstRepo, receipts, metrics).EnqueueDeep(context.Background(), allowReceiptToolLoopRequest(false)))
	firstRepo.createJob.Attempts = 1
	firstRepo.createJob.MaxAttempts = 3
	firstRepo.createJob.ClaimVersion = 1
	runner := NewRunner(config, firstRepo, receipts, PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		return allowReceiptResult(ActionAllow), nil
	}), metrics)
	require.NoError(t, runner.processJob(context.Background(), 0, cfg, firstRepo.createJob))
	require.Equal(t, 5, receipts.writes)

	secondRepo := &fakeJobRepository{}
	require.NoError(t, NewEnqueuer(config, secondRepo, receipts, metrics).EnqueueDeep(context.Background(), allowReceiptToolLoopRequest(true)))
	payload := decodeTransientPromptPayload(receipts.payloads[1])
	require.Equal(t, `{"second":true}`, payload.ScanText)
	require.Equal(t, 5, payload.AllowReceiptHitCount)
	require.Len(t, payload.AllowReceiptKeys, 1)
	require.NotContains(t, receipts.payloads[1], "original user turn")
	require.NotContains(t, receipts.payloads[1], "assistant plan")
	require.NotContains(t, receipts.payloads[1], `{"first":true}`)

	secondRepo.createJob.Attempts = 1
	secondRepo.createJob.MaxAttempts = 3
	secondRepo.createJob.ClaimVersion = 2
	blockedRunner := NewRunner(config, secondRepo, receipts, PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		return allowReceiptResult(ActionBlock), nil
	}), metrics)
	require.NoError(t, blockedRunner.processJob(context.Background(), 0, cfg, secondRepo.createJob))
	require.Equal(t, "async:1:2", receipts.states[7])
}

func TestForcedDeepRecoveryBypassesAllowReceipts(t *testing.T) {
	cfg := allowReceiptTestConfig()
	cfg.DeepReviewModules = ReviewModules{System: true, Assistant: true}
	config := &fakeConfigStore{active: true, cfg: cfg}
	receipts := newFakeAllowReceiptPayload()
	state := &fakePayloadStore{states: map[int64]string{7: "pending-v1"}}
	req := Request{
		RequestID: "recovery", UserID: 7, Protocol: "openai_responses", Endpoint: "/v1/responses",
		Body: []byte(`{"instructions":"recovery system","input":[{"type":"message","role":"user","content":"historical user"},{"type":"message","role":"assistant","content":"historical assistant"},{"type":"message","role":"user","content":"current user"}]}`),
	}
	snapshot, _, err := extractDeepPromptSnapshotWithDiagnostics(req, cfg.DeepReviewModules)
	require.NoError(t, err)
	prepareAllowReceipts(context.Background(), receipts, nil, cfg, &snapshot, nil, false)
	storeAllowReceipts(context.Background(), receipts, nil, cfg, snapshot)

	seen := ""
	service := &PromptService{
		config: config, state: state, receipts: receipts, clock: realClock{},
		evaluator: NewGuardEvaluator(PromptScannerFunc(func(_ context.Context, _ ActiveEndpoint, chunk string, _ []string) (*NormalizedResult, error) {
			seen += chunk
			return allowReceiptResult(ActionAllow), nil
		}), nil, NewAtomicMetrics()),
	}
	decision, err := service.Evaluate(context.Background(), req)
	require.NoError(t, err)
	require.True(t, decision.DeepReviewed)
	require.Equal(t, DecisionAllow, decision.Kind)
	for _, expected := range []string{"current user", "historical user", "historical assistant", "recovery system"} {
		require.Contains(t, seen, expected)
	}
	require.Empty(t, state.states[7])
}

func allowReceiptTestConfig() ActiveConfig {
	return ActiveConfig{
		RiskControlEnabled: true, Enabled: true, BlockingEnabled: true, AllGroups: true,
		BlockingReviewModules: ReviewModules{System: true}, DeepReviewModules: ReviewModules{System: true},
		AllowReceiptTTLSeconds: DefaultAllowReceiptTTLSeconds,
		ConfigVersion:          9, Scanners: []string{"pii"},
		Endpoints: []ActiveEndpoint{{ID: "guard-1", Protocol: "openai_compatible", Model: "guard", TimeoutMS: 3000, InputLimit: 200000, Enabled: true}},
	}
}

func allowReceiptRequest(userID int64, userText, systemText string) Request {
	return Request{
		UserID: userID, Protocol: "openai_responses", Endpoint: "/v1/responses",
		Body: []byte(`{"instructions":"` + systemText + `","input":[{"type":"message","role":"user","content":"` + userText + `"}]}`),
	}
}

func allowReceiptAssistantRequest(assistantText string) Request {
	return Request{
		UserID: 7, Protocol: "openai_responses", Endpoint: "/v1/responses",
		Body: []byte(`{"instructions":"stable system attachment","input":[{"type":"message","role":"assistant","content":"stable assistant"},{"type":"message","role":"assistant","content":"` + assistantText + `"},{"type":"message","role":"user","content":"current user input"}]}`),
	}
}

func allowReceiptHistoryRequest() Request {
	return Request{
		UserID: 7, Protocol: "openai_responses", Endpoint: "/v1/responses",
		Body: []byte(`{"instructions":"stable async attachment","input":[{"type":"message","role":"user","content":"older async user input"},{"type":"message","role":"assistant","content":"assistant separator"},{"type":"message","role":"user","content":"current async user input"}]}`),
	}
}

func allowReceiptMediaRequest(imageID string) Request {
	return Request{
		UserID: 7, Protocol: "grok_media", Endpoint: "/v1/images/generations",
		Body: []byte(`{"prompt":"fixed video-frame instruction [images:` + imageID + `]"}`),
	}
}

func allowReceiptToolLoopRequest(includeSecondOutput bool) Request {
	secondOutput := ""
	if includeSecondOutput {
		secondOutput = `,{"type":"function_call_output","call_id":"call-2","output":{"second":true}}`
	}
	return Request{
		UserID: 7, Protocol: "openai_responses", Endpoint: "/v1/responses",
		Body: []byte(`{"instructions":"stable system","input":[` +
			`{"type":"message","role":"user","content":"original user turn"},` +
			`{"type":"message","role":"assistant","content":"assistant plan"},` +
			`{"type":"function_call","call_id":"call-1","name":"lookup","arguments":{"order":1}},` +
			`{"type":"function_call_output","call_id":"call-1","output":{"first":true}}` + secondOutput + `]}`),
	}
}

func allowReceiptResult(action Action) *NormalizedResult {
	result := &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: action}
	switch action {
	case ActionWarn:
		result.Decision, result.RiskLevel = EventFlag, RiskMedium
	case ActionBlock:
		result.Decision, result.RiskLevel = EventCritical, RiskCritical
	}
	return result
}
