package securityaudit

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type advancingClock struct {
	mu   sync.Mutex
	now  time.Time
	step time.Duration
}

func (c *advancingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(c.step)
	return c.now
}

type fakeConfigStore struct {
	cfg      ActiveConfig
	active   bool
	degraded bool
}

func (s *fakeConfigStore) Start(context.Context) error    { return nil }
func (s *fakeConfigStore) Shutdown(context.Context) error { return nil }
func (s *fakeConfigStore) Active() (ActiveConfig, bool)   { return cloneActiveConfig(s.cfg), s.active }
func (s *fakeConfigStore) ShouldRetainPassEvidence(userID int64) bool {
	return s.active && s.cfg.ShouldRetainPassEvidence(userID)
}
func (s *fakeConfigStore) EffectiveMode() Mode {
	if s.BlockingActivationDegraded() {
		return ModeBlocking
	}
	if !s.active {
		return ModeOff
	}
	return s.cfg.EffectiveMode()
}
func (s *fakeConfigStore) BlockingActivationDegraded() bool { return s.degraded }
func (s *fakeConfigStore) Public() (PublicConfig, error)    { return PublicConfig{}, nil }
func (s *fakeConfigStore) Save(context.Context, UpdateConfigRequest, int64) (PublicConfig, error) {
	return PublicConfig{}, nil
}
func (s *fakeConfigStore) RuntimeState() (int64, int64, *time.Time, string) {
	return s.cfg.ConfigVersion, s.cfg.ConfigVersion, nil, ""
}
func (s *fakeConfigStore) Encrypt(value string) (string, error) { return value, nil }
func (s *fakeConfigStore) Decrypt(value string) (string, error) { return value, nil }

type fakeJobRepository struct {
	mu sync.Mutex

	trace       *[]string
	createJob   *Job
	createErr   error
	publishErr  error
	refreshErr  error
	completeErr error
	retryErr    error
	failErr     error

	createdSnapshot             PromptSnapshot
	markedCode                  string
	completedResult             *NormalizedResult
	completedJob                *Job
	completedRetainPassEvidence bool
	completeCount               int
	eventCount                  int
	retryAt                     time.Time
	retryCode                   string
	retried                     int
	failedCode                  string
	failed                      int
	refreshes                   int

	claimQueue []*Job

	recordBlockingCalls              int
	recordBlockingSnapshot           PromptSnapshot
	recordBlockingResult             *NormalizedResult
	recordBlockingRetainPassEvidence bool
	recordBlockingErr                error
	recordFailureJobs                []int64
	recordFailureCodes               []string
	recordFailureErr                 error
}

func (r *fakeJobRepository) record(value string) {
	if r.trace != nil {
		*r.trace = append(*r.trace, value)
	}
}

func (r *fakeJobRepository) CreateStagingWithCapacity(_ context.Context, snapshot PromptSnapshot, mode Mode, configVersion int64, _, _ int) (*Job, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.record("create_staging")
	r.createdSnapshot = snapshot
	if r.createErr != nil {
		return nil, r.createErr
	}
	if r.createJob == nil {
		r.createJob = &Job{ID: 1, Snapshot: snapshot, ExecutionMode: mode, ConfigVersion: configVersion}
	} else {
		r.createJob.ConfigVersion = configVersion
	}
	return r.createJob, nil
}
func (r *fakeJobRepository) PublishQueued(context.Context, int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.record("publish_queued")
	return r.publishErr
}
func (r *fakeJobRepository) MarkStagingFailed(_ context.Context, _ int64, code, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.record("mark_staging_failed")
	r.markedCode = code
	return nil
}
func (r *fakeJobRepository) ClaimNextJob(context.Context, time.Time) (*Job, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.claimQueue) == 0 {
		return nil, false, nil
	}
	job := r.claimQueue[0]
	r.claimQueue = r.claimQueue[1:]
	return job, true, nil
}
func (r *fakeJobRepository) RefreshLease(context.Context, int64, int64, time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refreshes++
	return r.refreshErr
}
func (r *fakeJobRepository) Complete(_ context.Context, job *Job, result *NormalizedResult, retainPassEvidence bool) (*Event, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.record("complete")
	r.completeCount++
	r.completedJob = job
	r.completedResult, r.completedRetainPassEvidence = result, retainPassEvidence
	if r.completeErr != nil {
		return nil, r.completeErr
	}
	r.eventCount++
	return &Event{ID: 99, Decision: result.Decision}, nil
}
func (r *fakeJobRepository) Retry(_ context.Context, _, _ int64, next time.Time, code, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.retried++
	r.retryAt, r.retryCode = next, code
	return r.retryErr
}
func (r *fakeJobRepository) Fail(_ context.Context, _, _ int64, code, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failed++
	r.failedCode = code
	return r.failErr
}
func (r *fakeJobRepository) ReclaimStale(context.Context, time.Time, time.Time, int) (int64, error) {
	return 0, nil
}
func (r *fakeJobRepository) QueueStats(context.Context) (QueueStats, error) { return QueueStats{}, nil }
func (r *fakeJobRepository) RecordBlocking(_ context.Context, snapshot PromptSnapshot, _ int64, result *NormalizedResult, retainPassEvidence bool) (*Event, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recordBlockingCalls++
	r.recordBlockingSnapshot, r.recordBlockingResult, r.recordBlockingRetainPassEvidence = snapshot, result, retainPassEvidence
	return nil, r.recordBlockingErr
}
func (r *fakeJobRepository) RecordFailureEvent(_ context.Context, job *Job, code string) (*Event, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if job != nil {
		r.recordFailureJobs = append(r.recordFailureJobs, job.ID)
	}
	r.recordFailureCodes = append(r.recordFailureCodes, code)
	if r.recordFailureErr != nil {
		return nil, r.recordFailureErr
	}
	return &Event{ID: int64(len(r.recordFailureCodes)), Decision: EventFailed, ErrorCode: code, ErrorMessage: stableErrorMessage(code)}, nil
}

type fakePayloadStore struct {
	mu sync.Mutex

	trace     *[]string
	values    map[int64]string
	setErr    error
	getErr    error
	deleteErr error
	pingErr   error
	setTTL    time.Duration
	deleted   []int64
	states    map[int64]string
	claims    map[int64]string
	stateErr  error
}

func (s *fakePayloadStore) Set(_ context.Context, jobID int64, value string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.trace != nil {
		*s.trace = append(*s.trace, "payload_set")
	}
	if s.setErr != nil {
		return s.setErr
	}
	if s.values == nil {
		s.values = map[int64]string{}
	}
	s.values[jobID], s.setTTL = value, ttl
	return nil
}
func (s *fakePayloadStore) Get(_ context.Context, jobID int64) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getErr != nil {
		return "", s.getErr
	}
	value, ok := s.values[jobID]
	if !ok {
		return "", errors.New("missing")
	}
	return value, nil
}
func (s *fakePayloadStore) Delete(_ context.Context, jobID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.trace != nil {
		*s.trace = append(*s.trace, "payload_delete")
	}
	s.deleted = append(s.deleted, jobID)
	delete(s.values, jobID)
	return s.deleteErr
}
func (s *fakePayloadStore) Ping(context.Context) error { return s.pingErr }
func (s *fakePayloadStore) Required(_ context.Context, userID int64) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stateErr != nil {
		return "", false, s.stateErr
	}
	token := s.states[userID]
	return token, token != "", nil
}
func (s *fakePayloadStore) Require(_ context.Context, userID int64, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.trace != nil {
		*s.trace = append(*s.trace, "state_require")
	}
	if s.stateErr != nil {
		return s.stateErr
	}
	if s.states == nil {
		s.states = map[int64]string{}
	}
	s.states[userID] = token
	return nil
}
func (s *fakePayloadStore) Claim(_ context.Context, userID int64, token string, _ time.Duration) (string, DeepReviewClaimStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stateErr != nil {
		return "", DeepReviewClaimMissing, s.stateErr
	}
	finding := s.states[userID]
	if finding == "" {
		return "", DeepReviewClaimMissing, nil
	}
	if s.claims == nil {
		s.claims = map[int64]string{}
	}
	if s.claims[userID] != "" {
		return "", DeepReviewClaimBusy, nil
	}
	s.claims[userID] = token
	return finding, DeepReviewClaimAcquired, nil
}
func (s *fakePayloadStore) ReleaseClaim(_ context.Context, userID int64, token string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stateErr != nil {
		return false, s.stateErr
	}
	if s.claims[userID] != token {
		return false, nil
	}
	delete(s.claims, userID)
	return true, nil
}
func (s *fakePayloadStore) ClearClaimed(_ context.Context, userID int64, finding, claim string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stateErr != nil {
		return false, s.stateErr
	}
	if s.states[userID] != finding || s.claims[userID] != claim {
		return false, nil
	}
	delete(s.states, userID)
	return true, nil
}

func asyncConfig() ActiveConfig {
	return ActiveConfig{
		RiskControlEnabled: true, Enabled: true, BlockingEnabled: false, Strategy: "priority",
		WorkerCount: 1, QueueCapacity: 8, Scanners: []string{"pii"}, AllGroups: true, ConfigVersion: 7,
		Endpoints: []ActiveEndpoint{{ID: "guard", Enabled: true, TimeoutMS: 1000, InputLimit: 3}},
	}
}

func asyncRequest() Request {
	return Request{RequestID: "request-async", Protocol: "openai_chat_completions", Body: []byte(`{"messages":[{"role":"user","content":"payload canary text"}]}`)}
}

func TestEnqueuerStagingPayloadPublishProtocolAndFailureCleanup(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		trace := []string{}
		repo := &fakeJobRepository{trace: &trace, createJob: &Job{ID: 41}}
		payload := &fakePayloadStore{trace: &trace, values: map[int64]string{}}
		enqueuer := NewEnqueuer(&fakeConfigStore{cfg: asyncConfig(), active: true}, repo, payload)
		require.NoError(t, enqueuer.Enqueue(context.Background(), asyncRequest()))
		require.Equal(t, []string{"create_staging", "payload_set", "publish_queued"}, trace)
		require.Empty(t, repo.createdSnapshot.ScanText)
		require.Equal(t, "payload canary text", decodeTransientPromptPayload(payload.values[41]).ScanText)
		require.Equal(t, DefaultPayloadTTL, payload.setTTL)
	})

	t.Run("queue admission failures never touch payload", func(t *testing.T) {
		for _, createErr := range []error{ErrQueueFull, ErrQueueAdmissionBusy, errors.New("database down")} {
			trace := []string{}
			repo := &fakeJobRepository{trace: &trace, createErr: createErr}
			payload := &fakePayloadStore{trace: &trace, values: map[int64]string{}}
			err := NewEnqueuer(&fakeConfigStore{cfg: asyncConfig(), active: true}, repo, payload).Enqueue(context.Background(), asyncRequest())
			require.ErrorIs(t, err, createErr)
			require.Equal(t, []string{"create_staging"}, trace)
		}
	})

	t.Run("payload failure marks staging failed", func(t *testing.T) {
		trace := []string{}
		repo := &fakeJobRepository{trace: &trace, createJob: &Job{ID: 42}}
		payload := &fakePayloadStore{trace: &trace, values: map[int64]string{}, setErr: errors.New("redis down")}
		err := NewEnqueuer(&fakeConfigStore{cfg: asyncConfig(), active: true}, repo, payload).Enqueue(context.Background(), asyncRequest())
		require.Error(t, err)
		require.Equal(t, []string{"create_staging", "payload_set", "mark_staging_failed"}, trace)
		require.Equal(t, "payload_store_failed", repo.markedCode)
	})

	t.Run("publish failure removes payload and marks staging failed", func(t *testing.T) {
		trace := []string{}
		repo := &fakeJobRepository{trace: &trace, createJob: &Job{ID: 43}, publishErr: errors.New("publish down")}
		payload := &fakePayloadStore{trace: &trace, values: map[int64]string{}}
		err := NewEnqueuer(&fakeConfigStore{cfg: asyncConfig(), active: true}, repo, payload).Enqueue(context.Background(), asyncRequest())
		require.Error(t, err)
		require.Equal(t, []string{"create_staging", "payload_set", "publish_queued", "payload_delete", "mark_staging_failed"}, trace)
		require.Equal(t, "queue_publish_failed", repo.markedCode)
		require.NotContains(t, payload.values, int64(43))
	})
}

func TestEnqueuerCreatesDistinctAsyncDeepJobWithConfiguredModules(t *testing.T) {
	cfg := asyncConfig()
	cfg.BlockingEnabled = true
	cfg.DeepReviewModules = ReviewModules{System: true}
	repo := &fakeJobRepository{}
	payload := &fakePayloadStore{values: map[int64]string{}}
	enqueuer := NewEnqueuer(&fakeConfigStore{cfg: cfg, active: true}, repo, payload)
	req := Request{Protocol: "openai_chat_completions", Body: []byte(`{"messages":[{"role":"system","content":"deep system"},{"role":"user","content":"deep user"}]}`)}

	require.NoError(t, enqueuer.EnqueueDeep(context.Background(), req))
	require.Equal(t, ModeAsyncDeep, repo.createJob.ExecutionMode)
	transient := decodeTransientPromptPayload(payload.values[repo.createJob.ID])
	require.Contains(t, transient.ScanText, "deep user")
	require.Contains(t, transient.ScanText, "deep system")
}

func TestEnqueuerSkipsOffOutOfScopeAndNoText(t *testing.T) {
	tests := []struct {
		name string
		cfg  ActiveConfig
		req  Request
	}{
		{name: "off", cfg: ActiveConfig{}, req: asyncRequest()},
		{name: "out of scope", cfg: func() ActiveConfig {
			cfg := asyncConfig()
			cfg.AllGroups = false
			cfg.GroupIDs = []int64{9}
			return cfg
		}(), req: asyncRequest()},
		{name: "no user text", cfg: asyncConfig(), req: Request{Protocol: "openai_chat_completions", Body: []byte(`{"messages":[{"role":"user","content":"  "}]}`)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeJobRepository{}
			err := NewEnqueuer(&fakeConfigStore{cfg: tt.cfg, active: true}, repo, &fakePayloadStore{}).Enqueue(context.Background(), tt.req)
			require.NoError(t, err)
			require.Zero(t, repo.createdSnapshot.MessageCount)
		})
	}
}

func TestWorkerDropsJobWhoseGroupLeftScopeWithoutGuardOrEvent(t *testing.T) {
	groupID := int64(7)
	cfg := asyncConfig()
	cfg.ConfigVersion++
	cfg.AllGroups = false
	cfg.GroupIDs = []int64{9}
	repo := &fakeJobRepository{}
	payload := &fakePayloadStore{values: map[int64]string{51: "must not scan"}}
	scans := 0
	runner := NewRunner(&fakeConfigStore{active: true, cfg: cfg}, repo, payload, PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		scans++
		return nil, errors.New("unexpected scan")
	}), NewAtomicMetrics())
	job := workerJob(1, 3)
	job.Snapshot.GroupID = &groupID

	require.NoError(t, runner.processJob(context.Background(), 0, cfg, job))
	require.Zero(t, scans)
	require.Equal(t, 1, repo.failed)
	require.Equal(t, "group_out_of_scope", repo.failedCode)
	require.Empty(t, repo.recordFailureCodes)
	require.NotContains(t, payload.values, job.ID)
}

func TestEnqueuerRecordsAcceptedDroppedAndSkippedMetrics(t *testing.T) {
	t.Run("accepted increments enqueued", func(t *testing.T) {
		metrics := NewAtomicMetrics()
		repo := &fakeJobRepository{createJob: &Job{ID: 44}}
		payload := &fakePayloadStore{values: map[int64]string{}}

		require.NoError(t, NewEnqueuer(
			&fakeConfigStore{cfg: asyncConfig(), active: true},
			repo,
			payload,
			metrics,
		).Enqueue(context.Background(), asyncRequest()))

		require.Equal(t, AuditMetricsSnapshot{Enqueued: 1, ExtractionAttempted: 1, ExtractionSucceeded: 1}, metrics.AuditSnapshot())
	})

	t.Run("queue full increments dropped", func(t *testing.T) {
		metrics := NewAtomicMetrics()
		repo := &fakeJobRepository{createErr: ErrQueueFull}

		err := NewEnqueuer(
			&fakeConfigStore{cfg: asyncConfig(), active: true},
			repo,
			&fakePayloadStore{},
			metrics,
		).Enqueue(context.Background(), asyncRequest())

		require.ErrorIs(t, err, ErrQueueFull)
		require.Equal(t, AuditMetricsSnapshot{Dropped: 1, ExtractionAttempted: 1, ExtractionSucceeded: 1}, metrics.AuditSnapshot())
	})

	t.Run("skipped request does not increment dropped", func(t *testing.T) {
		metrics := NewAtomicMetrics()

		require.NoError(t, NewEnqueuer(
			&fakeConfigStore{cfg: ActiveConfig{}, active: true},
			&fakeJobRepository{},
			&fakePayloadStore{},
			metrics,
		).Enqueue(context.Background(), asyncRequest()))

		require.Equal(t, AuditMetricsSnapshot{}, metrics.AuditSnapshot())
	})

	t.Run("empty content extraction failure is skipped and not dropped", func(t *testing.T) {
		metrics := NewAtomicMetrics()
		repo := &fakeJobRepository{}
		require.NoError(t, NewEnqueuer(
			&fakeConfigStore{cfg: asyncConfig(), active: true},
			repo,
			&fakePayloadStore{},
			metrics,
		).Enqueue(context.Background(), Request{
			Protocol: "openai_responses",
			Body:     []byte(`{"input":[{"type":"future_content","payload":"missing adapter"}]}`),
		}))

		require.Zero(t, repo.createdSnapshot.MessageCount)
		require.Equal(t, AuditMetricsSnapshot{ExtractionAttempted: 1, ExtractionFailed: 1}, metrics.AuditSnapshot())
	})

	t.Run("partial content extraction failure still enqueues extracted sibling", func(t *testing.T) {
		metrics := NewAtomicMetrics()
		repo := &fakeJobRepository{createJob: &Job{ID: 45}}
		payload := &fakePayloadStore{values: map[int64]string{}}
		require.NoError(t, NewEnqueuer(
			&fakeConfigStore{cfg: asyncConfig(), active: true}, repo, payload, metrics,
		).Enqueue(context.Background(), Request{
			Protocol: "openai_responses",
			Body:     []byte(`{"input":[{"type":"message","role":"user","content":"audit this sibling"},{"type":"future_content","payload":"missing adapter"}]}`),
		}))

		require.Contains(t, payload.values[45], "audit this sibling")
		require.Equal(t, AuditMetricsSnapshot{Enqueued: 1, ExtractionAttempted: 1, ExtractionFailed: 1}, metrics.AuditSnapshot())
	})
}

func workerJob(attempts, maxAttempts int) *Job {
	return &Job{ID: 51, ClaimVersion: 3, Attempts: attempts, MaxAttempts: maxAttempts, ConfigVersion: 7,
		Snapshot: PromptSnapshot{RequestID: "worker-request", PromptLength: 6, RedactedPreview: "red***"}}
}

func TestWorkerCompletesPassWithoutEventRefreshesEveryChunkAndDeletesPayload(t *testing.T) {
	repo := &fakeJobRepository{}
	payload := &fakePayloadStore{values: map[int64]string{51: "abcdef"}}
	scannerCalls := 0
	scanner := PromptScannerFunc(func(_ context.Context, endpoint ActiveEndpoint, chunk string, _ []string) (*NormalizedResult, error) {
		scannerCalls++
		return &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, Safety: "Safe", Categories: []string{}, MatchedScanners: []string{}, ScannerScores: map[string]float64{}, ScannerEvidence: map[string]string{}, GuardEndpointID: endpoint.ID}, nil
	})
	metrics := NewAtomicMetrics()
	runner := NewRunner(&fakeConfigStore{cfg: asyncConfig(), active: true}, repo, payload, scanner, metrics)
	runner.clock = fixedClock{now: time.Unix(100, 0).UTC()}
	require.NoError(t, runner.processJob(context.Background(), 0, asyncConfig(), workerJob(1, 3)))
	require.Equal(t, 2, scannerCalls)
	require.Equal(t, 2, repo.refreshes)
	require.NotNil(t, repo.completedResult)
	require.Equal(t, EventPass, repo.completedResult.Decision)
	require.False(t, repo.completedRetainPassEvidence)
	require.Equal(t, []int64{51}, payload.deleted)
	require.Equal(t, int64(1), metrics.Snapshot().Total)
	require.Equal(t, int64(1), metrics.Snapshot().Allowed)
}

func TestWorkerRejectsStaleConfigWithoutScanningOrWritingReceipts(t *testing.T) {
	cfg := asyncConfig()
	repo := &fakeJobRepository{}
	payload := newFakeAllowReceiptPayload()
	payload.payloads[51] = "stale input"
	scans := 0
	runner := NewRunner(&fakeConfigStore{cfg: cfg, active: true}, repo, payload, PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		scans++
		return allowReceiptResult(ActionAllow), nil
	}), NewAtomicMetrics())
	job := workerJob(1, 3)
	job.ConfigVersion = cfg.ConfigVersion - 1
	job.Snapshot.AllowReceiptKeys = []string{strings.Repeat("a", 64)}

	err := runner.processJob(context.Background(), 0, cfg, job)
	require.Error(t, err)
	require.Zero(t, scans)
	require.Zero(t, payload.writes)
	require.Equal(t, "config_version_changed", repo.failedCode)
	require.NotContains(t, payload.payloads, int64(51))
}

func TestWorkerMarksReconstructedContentIncompleteAfterNULRemoval(t *testing.T) {
	repo := &fakeJobRepository{}
	payload := &fakePayloadStore{values: map[int64]string{51: "abc\x00def"}}
	runner := NewRunner(&fakeConfigStore{cfg: asyncConfig(), active: true}, repo, payload, PromptScannerFunc(func(_ context.Context, _ ActiveEndpoint, _ string, _ []string) (*NormalizedResult, error) {
		return integrationResult(EventPass), nil
	}), NewAtomicMetrics())
	job := workerJob(1, 3)
	job.Snapshot.PromptLength = 7
	require.NoError(t, runner.processJob(context.Background(), 0, asyncConfig(), job))
	require.NotNil(t, repo.completedJob)
	require.Equal(t, "abcdef", repo.completedJob.Snapshot.FullPrompt)
	require.True(t, repo.completedJob.Snapshot.FullPromptTruncated)
}

func TestWorkerRetryBackoffTerminalFailureAndFailover(t *testing.T) {
	now := time.Unix(200, 0).UTC()
	for _, tt := range []struct {
		name        string
		attempts    int
		maxAttempts int
		err         *GuardError
		wantRetry   bool
		wantBackoff time.Duration
	}{
		{name: "first retry", attempts: 1, maxAttempts: 3, err: &GuardError{Code: ErrorCodeUnavailable, Retryable: true}, wantRetry: true, wantBackoff: 5 * time.Second},
		{name: "second retry", attempts: 2, maxAttempts: 3, err: &GuardError{Code: ErrorCodeUnavailable, Retryable: true}, wantRetry: true, wantBackoff: 30 * time.Second},
		{name: "third retry", attempts: 3, maxAttempts: 4, err: &GuardError{Code: ErrorCodeUnavailable, Retryable: true}, wantRetry: true, wantBackoff: 2 * time.Minute},
		{name: "max attempts", attempts: 3, maxAttempts: 3, err: &GuardError{Code: ErrorCodeUnavailable, Retryable: true}},
		{name: "invalid terminal", attempts: 1, maxAttempts: 3, err: &GuardError{Code: ErrorCodeInvalidResponse, Retryable: false}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeJobRepository{}
			payload := &fakePayloadStore{values: map[int64]string{51: "abc"}}
			metrics := NewAtomicMetrics()
			runner := NewRunner(&fakeConfigStore{cfg: asyncConfig(), active: true}, repo, payload, PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
				return nil, tt.err
			}), metrics)
			runner.clock = fixedClock{now: now}
			err := runner.processJob(context.Background(), 0, asyncConfig(), workerJob(tt.attempts, tt.maxAttempts))
			require.Error(t, err)
			if tt.wantRetry {
				require.Equal(t, 1, repo.retried)
				require.Equal(t, now.Add(tt.wantBackoff), repo.retryAt)
				require.Empty(t, payload.deleted)
				require.Empty(t, repo.recordFailureCodes)
			} else {
				require.Equal(t, 1, repo.failed)
				require.Equal(t, tt.err.Code, repo.failedCode)
				require.Equal(t, []int64{51}, payload.deleted)
				require.Equal(t, []int64{51}, repo.recordFailureJobs)
				require.Equal(t, []string{tt.err.Code}, repo.recordFailureCodes)
			}
			snapshot := metrics.Snapshot()
			require.Equal(t, int64(1), snapshot.Total)
			if tt.err.Code == ErrorCodeInvalidResponse {
				require.Equal(t, int64(1), snapshot.Invalid)
			} else {
				require.Equal(t, int64(1), snapshot.Unavailable)
			}
		})
	}

	repo := &fakeJobRepository{}
	payload := &fakePayloadStore{values: map[int64]string{51: "abc"}}
	metrics := NewAtomicMetrics()
	scanner := PromptScannerFunc(func(_ context.Context, endpoint ActiveEndpoint, _ string, _ []string) (*NormalizedResult, error) {
		if endpoint.ID == "first" {
			return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true}
		}
		return integrationResult(EventPass), nil
	})
	cfg := asyncConfig()
	cfg.Endpoints = []ActiveEndpoint{{ID: "first", Enabled: true, InputLimit: 10}, {ID: "second", Enabled: true, InputLimit: 10}}
	runner := NewRunner(&fakeConfigStore{cfg: cfg, active: true}, repo, payload, scanner, metrics)
	require.NoError(t, runner.processJob(context.Background(), 0, cfg, workerJob(1, 3)))
	require.Equal(t, int64(1), metrics.Snapshot().Failovers)
}

func TestWorkerCancellationDoesNotPersistFailureEvent(t *testing.T) {
	repo := &fakeJobRepository{}
	runner := NewRunner(&fakeConfigStore{cfg: asyncConfig(), active: true}, repo,
		&fakePayloadStore{values: map[int64]string{51: "abc"}},
		PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
			return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true}
		}), NewAtomicMetrics())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := runner.finishFailure(ctx, workerJob(1, 3), &GuardError{
		Code: ErrorCodeUnavailable, Retryable: true, Cause: context.Canceled,
	})
	require.Error(t, err)
	require.Empty(t, repo.recordFailureCodes)
}

func TestWorkerPersistenceFailuresUpdateRuntimeErrorTimestamp(t *testing.T) {
	tests := []struct {
		name     string
		repo     *fakeJobRepository
		scan     PromptScannerFunc
		job      *Job
		wantCode string
	}{
		{
			name: "complete", repo: &fakeJobRepository{completeErr: errors.New("complete failed")},
			scan: func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
				return integrationResult(EventPass), nil
			},
			job: workerJob(1, 3), wantCode: "job_complete_failed",
		},
		{
			name: "retry", repo: &fakeJobRepository{retryErr: errors.New("retry failed")},
			scan: func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
				return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true}
			},
			job: workerJob(1, 3), wantCode: "job_retry_failed",
		},
		{
			name: "fail", repo: &fakeJobRepository{failErr: errors.New("fail failed")},
			scan: func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
				return nil, &GuardError{Code: ErrorCodeInvalidResponse}
			},
			job: workerJob(1, 3), wantCode: "job_fail_failed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := NewRunner(&fakeConfigStore{cfg: asyncConfig(), active: true}, test.repo,
				&fakePayloadStore{values: map[int64]string{51: "abc"}}, test.scan, NewAtomicMetrics())
			runner.clock = fixedClock{now: time.Unix(456, 0).UTC()}
			require.Error(t, runner.processJob(context.Background(), 0, asyncConfig(), test.job))
			_, _, _, _, _, code, _ := runner.Snapshot()
			require.Equal(t, test.wantCode, code)
			require.Equal(t, time.Unix(456, 0).UTC(), *runner.LastErrorAt())
		})
	}
}

func TestWorkerPanicLeaseLossAndLifecycleAreContained(t *testing.T) {
	t.Run("panic", func(t *testing.T) {
		repo := &fakeJobRepository{}
		payload := &fakePayloadStore{values: map[int64]string{51: "abc"}}
		runner := NewRunner(&fakeConfigStore{cfg: asyncConfig(), active: true}, repo, payload, PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
			panic("scanner panic canary")
		}), NewAtomicMetrics())
		errorAt := time.Unix(123, 0).UTC()
		runner.clock = fixedClock{now: errorAt}
		require.NotPanics(t, func() { runner.processSafely(context.Background(), 0, asyncConfig(), workerJob(1, 3)) })
		_, _, failed, _, _, code, message := runner.Snapshot()
		require.Equal(t, int64(1), failed)
		require.Equal(t, "worker_panic", code)
		require.NotContains(t, message, "canary")
		require.Equal(t, errorAt, *runner.LastErrorAt())
		require.Equal(t, 1, repo.failed)
		require.Equal(t, []string{"worker_panic"}, repo.recordFailureCodes)
	})

	t.Run("lease loss", func(t *testing.T) {
		repo := &fakeJobRepository{refreshErr: ErrLeaseLost}
		payload := &fakePayloadStore{values: map[int64]string{51: "abc"}}
		calls := 0
		runner := NewRunner(&fakeConfigStore{cfg: asyncConfig(), active: true}, repo, payload, PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
			calls++
			return integrationResult(EventPass), nil
		}), NewAtomicMetrics())
		require.ErrorIs(t, runner.processJob(context.Background(), 0, asyncConfig(), workerJob(1, 3)), ErrLeaseLost)
		require.Zero(t, calls)
		require.Zero(t, repo.retried)
		require.Zero(t, repo.failed)
		_, _, _, _, _, code, _ := runner.Snapshot()
		require.Equal(t, "lease_refresh_failed", code)
		require.NotNil(t, runner.LastErrorAt())
	})

	t.Run("start and shutdown", func(t *testing.T) {
		cfg := asyncConfig()
		cfg.Enabled = false
		configStore := &fakeConfigStore{cfg: cfg, active: true}
		repo := &fakeJobRepository{}
		payload := &fakePayloadStore{pingErr: errors.New("redis unavailable")}
		runner := NewRunner(configStore, repo, payload, PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
			return integrationResult(EventPass), nil
		}), NewAtomicMetrics())
		require.NoError(t, runner.Start(context.Background()))
		require.NoError(t, runner.Start(context.Background()))
		_, _, _, _, _, code, _ := runner.Snapshot()
		require.Equal(t, "payload_store_unavailable", code)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, runner.Shutdown(ctx))
		require.NoError(t, runner.Shutdown(ctx))
	})

	t.Run("shutdown timeout is bounded", func(t *testing.T) {
		runner := &Runner{}
		release := make(chan struct{})
		runner.wg.Add(1)
		go func() {
			defer runner.wg.Done()
			<-release
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		require.ErrorIs(t, runner.Shutdown(ctx), context.DeadlineExceeded)
		close(release)
		ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
		defer cancel2()
		require.NoError(t, runner.Shutdown(ctx2))
	})
}

func TestWorkerSuccessAdvancesProcessedTimeWithoutOverwritingPriorError(t *testing.T) {
	repo := &fakeJobRepository{}
	payload := &fakePayloadStore{values: map[int64]string{51: "abc"}}
	scanCalls := 0
	runner := NewRunner(&fakeConfigStore{cfg: asyncConfig(), active: true}, repo, payload, PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		scanCalls++
		if scanCalls == 1 {
			return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true}
		}
		return integrationResult(EventPass), nil
	}), NewAtomicMetrics())

	errorAt := time.Unix(123, 0).UTC()
	runner.clock = fixedClock{now: errorAt}
	runner.processSafely(context.Background(), 0, asyncConfig(), workerJob(1, 3))
	_, processed, failed, _, lastProcessed, code, _ := runner.Snapshot()
	require.Zero(t, processed)
	require.Equal(t, int64(1), failed)
	require.Nil(t, lastProcessed)
	require.Equal(t, ErrorCodeUnavailable, code)
	require.Equal(t, errorAt, *runner.LastErrorAt())

	successAt := time.Unix(456, 0).UTC()
	runner.clock = fixedClock{now: successAt}
	runner.processSafely(context.Background(), 0, asyncConfig(), workerJob(2, 3))
	_, processed, failed, _, lastProcessed, code, _ = runner.Snapshot()
	require.Equal(t, int64(1), processed)
	require.Equal(t, int64(1), failed)
	require.Equal(t, successAt, *lastProcessed)
	require.Equal(t, ErrorCodeUnavailable, code)
	require.Equal(t, errorAt, *runner.LastErrorAt())
}

func TestPromptAuditSyntheticAsyncBaseline(t *testing.T) {
	const totalRequests = 100
	cfg := asyncConfig()
	cfg.Endpoints[0].InputLimit = 256
	repo := &fakeJobRepository{}
	payload := &fakePayloadStore{values: make(map[int64]string, totalRequests)}
	metrics := NewAtomicMetrics()
	knownBenignFindings := 0
	knownMaliciousBlocked := 0
	scanner := PromptScannerFunc(func(_ context.Context, endpoint ActiveEndpoint, chunk string, _ []string) (*NormalizedResult, error) {
		switch {
		case strings.HasPrefix(chunk, "benign"):
			return &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, Safety: "Safe", GuardEndpointID: endpoint.ID}, nil
		case strings.HasPrefix(chunk, "flag"):
			return &NormalizedResult{Decision: EventFlag, RiskLevel: RiskMedium, Action: ActionWarn, Safety: "Controversial", Categories: []string{"politically_sensitive_topics"}, GuardEndpointID: endpoint.ID}, nil
		case strings.HasPrefix(chunk, "block"):
			knownMaliciousBlocked++
			return &NormalizedResult{Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock, Safety: "Unsafe", Categories: []string{"jailbreak"}, GuardEndpointID: endpoint.ID}, nil
		case strings.HasPrefix(chunk, "invalid"):
			return nil, &GuardError{Code: ErrorCodeInvalidResponse}
		default:
			return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true, Timeout: true}
		}
	})
	runner := NewRunner(&fakeConfigStore{cfg: cfg, active: true}, repo, payload, scanner, metrics)
	runner.clock = &advancingClock{now: time.Unix(1_000, 0).UTC(), step: time.Millisecond}

	for index := 1; index <= totalRequests; index++ {
		text := fmt.Sprintf("benign-%03d", index)
		switch {
		case index > 90 && index <= 95:
			text = fmt.Sprintf("flag-%03d", index)
		case index > 95 && index <= 98:
			text = fmt.Sprintf("block-%03d", index)
		case index == 99:
			text = "invalid-099"
		case index == 100:
			text = "timeout-100"
		}
		jobID := int64(index)
		payload.values[jobID] = text
		job := &Job{ID: jobID, ClaimVersion: 1, Attempts: 1, MaxAttempts: 1, ConfigVersion: cfg.ConfigVersion,
			Snapshot: PromptSnapshot{RequestID: fmt.Sprintf("baseline-%03d", index), PromptLength: len([]rune(text)), RedactedPreview: "synthetic"}}
		err := runner.processJob(context.Background(), 0, cfg, job)
		if index <= 98 {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}

	snapshot := metrics.Snapshot()
	require.Equal(t, int64(totalRequests), snapshot.Total)
	require.Equal(t, int64(90), snapshot.Allowed)
	require.Equal(t, int64(5), snapshot.Flagged)
	require.Equal(t, int64(3), snapshot.Blocked)
	require.Equal(t, int64(1), snapshot.Invalid)
	require.Equal(t, int64(1), snapshot.Unavailable)
	require.Equal(t, int64(1), snapshot.Timeouts)
	require.Zero(t, knownBenignFindings)
	require.Equal(t, 3, knownMaliciousBlocked)
	require.Equal(t, 98, repo.completeCount)
	require.Equal(t, 98, repo.eventCount, "every completed review creates a lightweight event")
	require.Positive(t, snapshot.LatencyP50MS)
	require.LessOrEqual(t, snapshot.LatencyP50MS, snapshot.LatencyP95MS)
	require.LessOrEqual(t, snapshot.LatencyP95MS, snapshot.LatencyP99MS)
	t.Logf("synthetic async baseline: p50=%dms p95=%dms p99=%dms failure_rate=2%% false_positive_rate=0%% event_growth=98/100", snapshot.LatencyP50MS, snapshot.LatencyP95MS, snapshot.LatencyP99MS)
}

func TestRunnerUsesUserPassRetentionAtCompletion(t *testing.T) {
	cfg := asyncConfig()
	cfg.PassRetentionUserIDs = []int64{42}
	resultScanner := PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		return &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, ScannerScores: map[string]float64{}, ScannerEvidence: map[string]string{}}, nil
	})

	for _, testCase := range []struct {
		userID         int64
		retainEvidence bool
	}{
		{userID: 42, retainEvidence: true},
		{userID: 43, retainEvidence: false},
	} {
		repo := &fakeJobRepository{}
		payload := &fakePayloadStore{values: map[int64]string{1: "normal input"}}
		runner := NewRunner(&fakeConfigStore{active: true, cfg: cfg}, repo, payload, resultScanner, NewAtomicMetrics())
		job := &Job{ID: 1, ClaimVersion: 1, Attempts: 1, MaxAttempts: 1, ConfigVersion: cfg.ConfigVersion,
			Snapshot: PromptSnapshot{UserID: testCase.userID, PromptLength: 12}}
		require.NoError(t, runner.processJob(context.Background(), 0, cfg, job))
		require.Equal(t, testCase.retainEvidence, repo.completedRetainPassEvidence)
		require.Equal(t, 1, repo.eventCount)
	}
}

func TestRunnerReadsLatestPassRetentionAfterScanning(t *testing.T) {
	cfg := asyncConfig()
	cfg.PassRetentionUserIDs = []int64{42}
	configStore := &fakeConfigStore{active: true, cfg: cfg}
	repo := &fakeJobRepository{}
	payload := &fakePayloadStore{values: map[int64]string{1: "normal input"}}
	runner := NewRunner(configStore, repo, payload, PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		configStore.cfg.PassRetentionUserIDs = nil
		return &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, ScannerScores: map[string]float64{}, ScannerEvidence: map[string]string{}}, nil
	}), NewAtomicMetrics())
	job := &Job{ID: 1, ClaimVersion: 1, Attempts: 1, MaxAttempts: 1, ConfigVersion: cfg.ConfigVersion,
		Snapshot: PromptSnapshot{UserID: 42, PromptLength: 12}}

	require.NoError(t, runner.processJob(context.Background(), 0, cfg, job))
	require.False(t, repo.completedRetainPassEvidence)
	require.Equal(t, 1, repo.eventCount)
}

func TestAsyncDeepBlockMarksUserBeforeCompletingJob(t *testing.T) {
	trace := []string{}
	payload := &fakePayloadStore{trace: &trace, values: map[int64]string{51: "deep blocked input"}, states: map[int64]string{}}
	repo := &fakeJobRepository{trace: &trace}
	metrics := NewAtomicMetrics()
	runner := NewRunner(&fakeConfigStore{active: true, cfg: asyncConfig()}, repo, payload, PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		return &NormalizedResult{Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock, ScannerScores: map[string]float64{}, ScannerEvidence: map[string]string{}}, nil
	}), metrics)
	job := &Job{
		ID: 51, Snapshot: PromptSnapshot{UserID: 42, PromptLength: 18}, ExecutionMode: ModeAsyncDeep,
		Status: "processing", Attempts: 1, MaxAttempts: 3, ClaimVersion: 7, ConfigVersion: asyncConfig().ConfigVersion,
	}

	require.NoError(t, runner.processJob(context.Background(), 0, asyncConfig(), job))
	require.Equal(t, "async:51:7", payload.states[42])
	require.Equal(t, 1, repo.completeCount)
	require.Equal(t, []string{"state_require", "complete", "payload_delete"}, trace)
	require.Equal(t, int64(1), metrics.AuditSnapshot().RecoveryRequiredAsync)
}

func TestAsyncDeepBlockWithRequestTimeExemptionStillCompletesCriticalEventWithoutRecovery(t *testing.T) {
	trace := []string{}
	payload := &fakePayloadStore{trace: &trace, values: map[int64]string{51: "deep blocked input"}, states: map[int64]string{42: "existing"}}
	repo := &fakeJobRepository{trace: &trace}
	cfg := asyncConfig()
	runner := NewRunner(&fakeConfigStore{active: true, cfg: cfg}, repo, payload, PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		return &NormalizedResult{Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock, ScannerScores: map[string]float64{}, ScannerEvidence: map[string]string{}}, nil
	}), NewAtomicMetrics())
	job := &Job{
		ID: 51, Snapshot: PromptSnapshot{UserID: 42, PromptLength: 18, BlockingExemptAtRequest: true}, ExecutionMode: ModeAsyncDeep,
		Status: "processing", Attempts: 1, MaxAttempts: 3, ClaimVersion: 7, ConfigVersion: cfg.ConfigVersion,
	}

	require.NoError(t, runner.processJob(context.Background(), 0, cfg, job))
	require.Equal(t, "existing", payload.states[42])
	require.Equal(t, 1, repo.completeCount)
	require.Equal(t, []string{"complete", "payload_delete"}, trace)
}

func TestAsyncDeepBlockFailsJobWhenRecoveryStateCannotBeWritten(t *testing.T) {
	payload := &fakePayloadStore{
		values: map[int64]string{52: "deep blocked input"}, states: map[int64]string{},
		stateErr: errors.New("redis unavailable"),
	}
	repo := &fakeJobRepository{}
	metrics := NewAtomicMetrics()
	runner := NewRunner(&fakeConfigStore{active: true, cfg: asyncConfig()}, repo, payload, PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		return &NormalizedResult{Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock, ScannerScores: map[string]float64{}, ScannerEvidence: map[string]string{}}, nil
	}), metrics)
	job := &Job{
		ID: 52, Snapshot: PromptSnapshot{UserID: 42, PromptLength: 18}, ExecutionMode: ModeAsyncDeep,
		Status: "processing", Attempts: 1, MaxAttempts: 3, ClaimVersion: 7, ConfigVersion: asyncConfig().ConfigVersion,
	}

	require.Error(t, runner.processJob(context.Background(), 0, asyncConfig(), job))
	require.Zero(t, repo.completeCount)
	require.Equal(t, int64(1), metrics.AuditSnapshot().RecoveryErrors)
}

func TestRequestCloneOwnsMutableInputs(t *testing.T) {
	groupID := int64(7)
	req := Request{Body: []byte("original"), GroupID: &groupID, AllowReceiptKeys: []string{"receipt"}}
	clone := req.Clone()
	clone.Body[0] = 'X'
	*clone.GroupID = 8
	clone.AllowReceiptKeys[0] = "changed"
	require.Equal(t, []byte("original"), req.Body)
	require.Equal(t, int64(7), *req.GroupID)
	require.Equal(t, []string{"receipt"}, req.AllowReceiptKeys)
	require.False(t, reflect.ValueOf(req.Body).Pointer() == reflect.ValueOf(clone.Body).Pointer())
}
