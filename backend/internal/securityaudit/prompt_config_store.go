package securityaudit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TokenFlux/TokenRouter/internal/config"
	infraerrors "github.com/TokenFlux/TokenRouter/internal/pkg/errors"
	"github.com/TokenFlux/TokenRouter/internal/service"
	"github.com/redis/go-redis/v9"
)

type activeConfigSnapshot struct {
	storage   storageConfig
	retention passRetentionStorage
	active    ActiveConfig
	loadedAt  time.Time
}

type ConfigManager struct {
	db        *sql.DB
	settings  service.SettingRepository
	redis     *redis.Client
	encryptor SecretEncryptor
	clock     Clock
	// encryptionKeyConfigured mirrors cfg.Totp.EncryptionKeyConfigured. With an
	// auto-generated (per-boot) key, newly saved endpoint tokens would become
	// undecryptable after the next restart, so Save rejects them (issue #4887).
	encryptionKeyConfigured bool

	snapshot   atomic.Pointer[activeConfigSnapshot]
	snapshotMu sync.Mutex
	expected   atomic.Int64
	// expectedBlocking records the last storage intent that could be decoded,
	// independently of whether endpoint credentials or the full config could be
	// activated. A config version alone cannot distinguish async from blocking.
	expectedBlocking atomic.Bool
	// configUntrusted is set when a load/reload fails before a trustworthy
	// snapshot is installed. Combined with expectedBlocking, EffectiveMode
	// fails closed so a persisted blocking policy cannot be silently skipped
	// after startup or invalidation errors. Without blocking intent, untrusted
	// alone must not force ModeBlocking—Prompt Audit is default-off and must
	// not take the gateway down for every API request (see issue #4560).
	configUntrusted atomic.Bool

	stateMu            sync.RWMutex
	lastLoadError      string
	lastErrorAt        *time.Time
	retentionLoadError string

	lifecycleMu sync.Mutex
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

func NewConfigManager(db *sql.DB, settings service.SettingRepository, redisClient *redis.Client, encryptor service.SecretEncryptor, cfg *config.Config) *ConfigManager {
	return &ConfigManager{
		db: db, settings: settings, redis: redisClient, encryptor: encryptor, clock: realClock{},
		encryptionKeyConfigured: cfg != nil && cfg.Totp.EncryptionKeyConfigured,
	}
}

func (m *ConfigManager) Start(ctx context.Context) error {
	if m == nil {
		return errors.New("prompt audit config manager unavailable")
	}
	m.lifecycleMu.Lock()
	if m.cancel != nil {
		m.lifecycleMu.Unlock()
		return nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.lifecycleMu.Unlock()
	loadErr := m.Reload(runCtx)
	if loadErr != nil {
		m.markConfigUntrusted()
	}
	m.wg.Add(1)
	go m.refreshLoop(runCtx)
	if m.redis != nil {
		m.wg.Add(1)
		go m.subscribeLoop(runCtx)
	}
	return loadErr
}

func (m *ConfigManager) Shutdown(_ context.Context) error {
	if m == nil {
		return nil
	}
	m.lifecycleMu.Lock()
	cancel := m.cancel
	m.cancel = nil
	m.lifecycleMu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.wg.Wait()
	return nil
}

func (m *ConfigManager) Reload(ctx context.Context) error {
	if m == nil || m.settings == nil {
		m.markUntrustedIfNoActiveSnapshot()
		return errors.New("prompt audit setting repository unavailable")
	}
	values, err := m.settings.GetMultiple(ctx, []string{SettingKeyPromptAuditConfig, SettingKeyPromptAuditPassRetention, SettingKeyRiskControl})
	if err != nil {
		m.recordLoadError(err)
		m.disablePassRetention("pass_retention_config_unavailable")
		m.markUntrustedIfNoActiveSnapshot()
		return err
	}
	m.observeExpectedState(values[SettingKeyPromptAuditConfig], values[SettingKeyRiskControl] == "true")
	storage, err := ParseStorageConfig(values[SettingKeyPromptAuditConfig])
	if err != nil {
		m.recordLoadError(err)
		m.disablePassRetention("pass_retention_config_unavailable")
		m.markUntrustedIfNoActiveSnapshot()
		return err
	}
	m.expected.Store(storage.ConfigVersion)
	m.expectedBlocking.Store(values[SettingKeyRiskControl] == "true" && storage.Enabled && storage.BlockingEnabled)
	active, err := ActiveFromStorage(storage, values[SettingKeyRiskControl] == "true", m.encryptor)
	if err != nil {
		m.recordLoadError(err)
		m.disablePassRetention("pass_retention_config_unavailable")
		// expectedBlocking may already require fail-closed via BlockingActivationDegraded.
		m.markUntrustedIfNoActiveSnapshot()
		return err
	}
	retention, retentionErr := parsePassRetentionStorage(values[SettingKeyPromptAuditPassRetention])
	if retentionErr != nil {
		retention = defaultPassRetentionStorage()
		m.recordRetentionLoadError()
	} else {
		m.clearRetentionLoadError()
	}
	active.PassRetentionUserIDs = append([]int64(nil), retention.UserIDs...)
	now := m.clock.Now()
	m.snapshotMu.Lock()
	previous := m.snapshot.Load()
	if retentionErr == nil && previous != nil && previous.retention.Revision > retention.Revision {
		retention = clonePassRetentionStorage(previous.retention)
		active.PassRetentionUserIDs = append([]int64(nil), retention.UserIDs...)
	}
	m.snapshot.Store(&activeConfigSnapshot{storage: cloneStorageConfig(storage), retention: clonePassRetentionStorage(retention), active: cloneActiveConfig(active), loadedAt: now})
	m.snapshotMu.Unlock()
	m.configUntrusted.Store(false)
	recovered := m.clearLoadError()
	m.logInvalidTokenEndpoints(previous, active)
	// refreshLoop calls Reload every 5s, so logging every successful load turns
	// config_loaded into a heartbeat that buries real config changes.
	if recovered || shouldLogConfigLoaded(previous, storage, retention, active) {
		LogInfo(EventConfigLoaded, map[string]any{
			"config_version": storage.ConfigVersion, "status": "loaded",
		})
	}
	return nil
}

// shouldLogConfigLoaded reports whether a successful reload carries news: the
// first snapshot, a new config version (every admin save bumps it under the
// advisory lock in UpdateConfig) or a flip of the global risk control gate,
// which lives in its own setting and so leaves the version untouched.
func shouldLogConfigLoaded(previous *activeConfigSnapshot, storage storageConfig, retention passRetentionStorage, active ActiveConfig) bool {
	return previous == nil ||
		previous.storage.ConfigVersion != storage.ConfigVersion ||
		previous.retention.Revision != retention.Revision ||
		previous.active.RiskControlEnabled != active.RiskControlEnabled
}

// logInvalidTokenEndpoints warns once per change (not on every 5s refresh)
// when stored endpoint tokens cannot be decrypted with the current key.
func (m *ConfigManager) logInvalidTokenEndpoints(previous *activeConfigSnapshot, active ActiveConfig) {
	invalid := active.InvalidTokenEndpointIDs()
	if len(invalid) == 0 {
		return
	}
	if previous != nil {
		prior := previous.active.InvalidTokenEndpointIDs()
		if len(prior) == len(invalid) {
			same := true
			for i := range invalid {
				if prior[i] != invalid[i] {
					same = false
					break
				}
			}
			if same && previous.active.ConfigVersion == active.ConfigVersion {
				return
			}
		}
	}
	LogWarn(EventConfigTokenInvalid, map[string]any{
		"config_version": active.ConfigVersion, "status": "degraded",
		"error_code": "endpoint_token_undecryptable", "guard_endpoint_id": strings.Join(invalid, ","),
	})
}

func (m *ConfigManager) Active() (ActiveConfig, bool) {
	if m == nil {
		return ActiveConfig{}, false
	}
	snapshot := m.snapshot.Load()
	if snapshot == nil {
		return ActiveConfig{}, false
	}
	return cloneActiveConfig(snapshot.active), true
}

func (m *ConfigManager) ShouldRetainPassEvidence(userID int64) bool {
	active, ok := m.Active()
	return ok && active.ShouldRetainPassEvidence(userID)
}

func (m *ConfigManager) BlockingActivationDegraded() bool {
	if m == nil {
		return false
	}
	// Fail closed only when storage intent requires blocking. Untrusted config
	// without blocking intent must remain ModeOff so administrators can still
	// operate the gateway and turn Prompt Audit off after a failed reload.
	if !m.expectedBlocking.Load() {
		return false
	}
	if m.configUntrusted.Load() {
		return true
	}
	active, ok := m.Active()
	if !ok {
		return true
	}
	// A still-active weaker snapshot after a failed blocking activation must not
	// keep serving allow decisions under the old off/async mode.
	return active.EffectiveMode() != ModeBlocking
}

func (m *ConfigManager) EffectiveMode() Mode {
	if m != nil && m.BlockingActivationDegraded() {
		return ModeBlocking
	}
	active, ok := m.Active()
	if !ok {
		return ModeOff
	}
	return active.EffectiveMode()
}

func (m *ConfigManager) markConfigUntrusted() {
	if m == nil {
		return
	}
	m.configUntrusted.Store(true)
}

func (m *ConfigManager) markUntrustedIfNoActiveSnapshot() {
	if m == nil {
		return
	}
	if _, ok := m.Active(); !ok {
		m.markConfigUntrusted()
	}
}

func (m *ConfigManager) Public() (PublicConfig, error) {
	if m == nil {
		return PublicConfig{}, infraerrors.ServiceUnavailable(ErrorCodeConfigUnavailable, "提示词审计配置暂不可用")
	}
	snapshot := m.snapshot.Load()
	if snapshot == nil {
		return PublicConfig{}, infraerrors.ServiceUnavailable(ErrorCodeConfigUnavailable, "提示词审计配置暂不可用")
	}
	return PublicFromStorage(cloneStorageConfig(snapshot.storage), snapshot.active.RiskControlEnabled, snapshot.active.InvalidTokenEndpointIDs()), nil
}

func (m *ConfigManager) PublicPassRetention() (PassRetentionConfig, error) {
	if m == nil {
		return PassRetentionConfig{}, infraerrors.ServiceUnavailable(ErrorCodeConfigUnavailable, "Pass 完整证据留存配置暂不可用")
	}
	snapshot := m.snapshot.Load()
	if snapshot == nil {
		return PassRetentionConfig{}, infraerrors.ServiceUnavailable(ErrorCodeConfigUnavailable, "Pass 完整证据留存配置暂不可用")
	}
	return publicPassRetention(clonePassRetentionStorage(snapshot.retention), m.currentRetentionLoadError()), nil
}

func (m *ConfigManager) Save(ctx context.Context, req UpdateConfigRequest, actorID int64) (PublicConfig, error) {
	if m == nil || m.db == nil || m.encryptor == nil {
		return PublicConfig{}, errors.New("prompt audit config persistence unavailable")
	}
	if req.ExpectedConfigVersion < 1 {
		return PublicConfig{}, infraerrors.BadRequest("prompt_audit_expected_config_version_required", "必须提供有效的配置版本")
	}
	tx, err := m.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return PublicConfig{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, promptAuditConfigLockKey); err != nil {
		return PublicConfig{}, err
	}
	current := DefaultStorageConfig()
	var raw string
	err = tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=$1 FOR UPDATE`, SettingKeyPromptAuditConfig).Scan(&raw)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return PublicConfig{}, err
	}
	if err == nil {
		current, err = ParseStorageConfig(raw)
		if err != nil {
			return PublicConfig{}, err
		}
	}
	if current.ConfigVersion != req.ExpectedConfigVersion {
		return PublicConfig{}, infraerrors.Conflict(ErrorCodeConfigConflict, "提示词审计配置已被其他管理员更新")
	}
	next, err := m.buildNextStorage(current, req, actorID)
	if err != nil {
		return PublicConfig{}, err
	}
	next.ConfigVersion = current.ConfigVersion + 1
	next.UpdatedAt = m.clock.Now()
	next.UpdatedBy = actorID
	next.ChangeSummary = changeSummary(next)
	rawNext, err := json.Marshal(next)
	if err != nil {
		return PublicConfig{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO settings (key,value,updated_at) VALUES ($1,$2,NOW())
		ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=EXCLUDED.updated_at`,
		SettingKeyPromptAuditConfig, string(rawNext)); err != nil {
		return PublicConfig{}, err
	}
	if err := tx.Commit(); err != nil {
		return PublicConfig{}, err
	}
	// Install the snapshot with the current global gate, not merely the value
	// cached when this process last reloaded Prompt Audit configuration.
	riskControlEnabled := m.currentRiskControlEnabled()
	if values, getErr := m.settings.GetMultiple(ctx, []string{SettingKeyRiskControl}); getErr == nil {
		riskControlEnabled = values[SettingKeyRiskControl] == "true"
	}
	active, err := ActiveFromStorage(next, riskControlEnabled, m.encryptor)
	if err != nil {
		return PublicConfig{}, err
	}
	m.expected.Store(next.ConfigVersion)
	m.expectedBlocking.Store(active.RiskControlEnabled && next.Enabled && next.BlockingEnabled)
	m.snapshotMu.Lock()
	previous := m.snapshot.Load()
	retention := defaultPassRetentionStorage()
	if previous != nil {
		retention = clonePassRetentionStorage(previous.retention)
	}
	active.PassRetentionUserIDs = append([]int64(nil), retention.UserIDs...)
	m.snapshot.Store(&activeConfigSnapshot{storage: cloneStorageConfig(next), retention: retention, active: cloneActiveConfig(active), loadedAt: m.clock.Now()})
	m.snapshotMu.Unlock()
	// A successful admin save installs a trustworthy snapshot; clear any prior
	// fail-closed degradation so disabling audit actually takes effect.
	m.configUntrusted.Store(false)
	m.clearLoadError()
	m.logInvalidTokenEndpoints(previous, active)
	LogInfo(EventConfigUpdated, map[string]any{
		"config_version": next.ConfigVersion, "status": "updated",
	})
	if m.redis != nil {
		if err := m.redis.Publish(ctx, ConfigInvalidationChannel, strconv.FormatInt(next.ConfigVersion, 10)).Err(); err != nil {
			LogWarn(EventConfigReloadDegraded, map[string]any{
				"config_version": next.ConfigVersion, "status": "degraded", "error_code": "config_invalidation_publish_failed",
			})
		}
	}
	return PublicFromStorage(next, active.RiskControlEnabled, active.InvalidTokenEndpointIDs()), nil
}

func (m *ConfigManager) SavePassRetention(ctx context.Context, req UpdatePassRetentionRequest, actorID int64) (PassRetentionConfig, error) {
	if m == nil || m.db == nil {
		return PassRetentionConfig{}, errors.New("prompt audit Pass retention persistence unavailable")
	}
	userIDs, err := validatePassRetentionUpdate(req)
	if err != nil {
		return PassRetentionConfig{}, err
	}
	tx, err := m.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return PassRetentionConfig{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, promptAuditPassRetentionLockKey); err != nil {
		return PassRetentionConfig{}, err
	}
	current := defaultPassRetentionStorage()
	var raw string
	err = tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=$1 FOR UPDATE`, SettingKeyPromptAuditPassRetention).Scan(&raw)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return PassRetentionConfig{}, err
	}
	if err == nil {
		parsed, parseErr := parsePassRetentionStorage(raw)
		if parseErr == nil {
			current = parsed
		}
	}
	if current.Revision != req.ExpectedRevision {
		return PassRetentionConfig{}, infraerrors.Conflict("prompt_audit_pass_retention_conflict", "Pass 完整证据留存配置已被其他管理员更新")
	}
	next := passRetentionStorage{
		Revision: current.Revision + 1, UserIDs: userIDs,
		UpdatedAt: m.clock.Now(), UpdatedBy: actorID,
	}
	rawNext, err := json.Marshal(next)
	if err != nil {
		return PassRetentionConfig{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO settings (key,value,updated_at) VALUES ($1,$2,NOW())
		ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=EXCLUDED.updated_at`,
		SettingKeyPromptAuditPassRetention, string(rawNext)); err != nil {
		return PassRetentionConfig{}, err
	}
	if err := tx.Commit(); err != nil {
		return PassRetentionConfig{}, err
	}
	m.installPassRetention(next)
	m.clearRetentionLoadError()
	LogInfo(EventConfigUpdated, map[string]any{
		"retention_revision": next.Revision, "selected_user_count": len(next.UserIDs), "status": "updated",
	})
	if m.redis != nil {
		if err := m.redis.Publish(ctx, PassRetentionInvalidationChannel, strconv.FormatInt(next.Revision, 10)).Err(); err != nil {
			LogWarn(EventConfigReloadDegraded, map[string]any{
				"retention_revision": next.Revision, "status": "degraded", "error_code": "pass_retention_invalidation_publish_failed",
			})
		}
	}
	return publicPassRetention(next, ""), nil
}

func (m *ConfigManager) buildNextStorage(current storageConfig, req UpdateConfigRequest, actorID int64) (storageConfig, error) {
	if err := validateUpdateConfigRequest(req); err != nil {
		return storageConfig{}, err
	}
	currentByID := make(map[string]StorageEndpoint, len(current.Endpoints))
	for _, endpoint := range current.Endpoints {
		currentByID[endpoint.ID] = endpoint
	}
	next := storageConfig{
		Enabled: req.Enabled, BlockingEnabled: req.BlockingEnabled,
		BlockingLatestTurnOnly: req.BlockingLatestTurnOnly,
		BlockingReviewModules:  current.BlockingReviewModules, DeepReviewModules: current.DeepReviewModules,
		AllowReceiptTTLSeconds: current.AllowReceiptTTLSeconds,
		Strategy:               strings.TrimSpace(req.Strategy), WorkerCount: req.WorkerCount,
		QueueCapacity: req.QueueCapacity, Scanners: append([]string(nil), req.Scanners...),
		AllGroups: req.AllGroups, GroupIDs: append([]int64(nil), req.GroupIDs...),
		BlockingExemptUserIDs: append([]int64(nil), current.BlockingExemptUserIDs...),
		ConfigVersion:         current.ConfigVersion, UpdatedBy: actorID,
		Endpoints: make([]StorageEndpoint, 0, len(req.Endpoints)),
	}
	if req.BlockingReviewModules != nil {
		next.BlockingReviewModules = *req.BlockingReviewModules
	}
	if req.DeepReviewModules != nil {
		next.DeepReviewModules = *req.DeepReviewModules
	}
	if req.AllowReceiptTTLSeconds != nil {
		next.AllowReceiptTTLSeconds = *req.AllowReceiptTTLSeconds
	}
	if req.BlockingExemptUserIDs != nil {
		next.BlockingExemptUserIDs = append([]int64(nil), (*req.BlockingExemptUserIDs)...)
	}
	for _, endpoint := range req.Endpoints {
		baseURL, err := NormalizeBaseURL(endpoint.BaseURL)
		if err != nil {
			return storageConfig{}, err
		}
		stored := StorageEndpoint{
			ID: strings.TrimSpace(endpoint.ID), Name: strings.TrimSpace(endpoint.Name),
			Protocol: strings.TrimSpace(endpoint.Protocol), BaseURL: baseURL, Model: strings.TrimSpace(endpoint.Model),
			TimeoutMS: endpoint.TimeoutMS, InputLimit: endpoint.InputLimit, Enabled: endpoint.Enabled,
		}
		old, hadOld := currentByID[stored.ID]
		switch {
		case endpoint.ClearToken:
			stored.TokenCiphertext = ""
		case strings.TrimSpace(endpoint.Token) != "":
			if !m.encryptionKeyConfigured {
				return storageConfig{}, infraerrors.BadRequest(ErrorCodeEncryptionKeyRequired,
					"未配置固定加密密钥，审计节点 Token 将在服务重启后失效。请先设置 TOTP_ENCRYPTION_KEY 环境变量（64 位十六进制）并重启服务")
			}
			ciphertext, err := m.encryptor.Encrypt(strings.TrimSpace(endpoint.Token))
			if err != nil {
				return storageConfig{}, fmt.Errorf("encrypt prompt audit endpoint token: %w", err)
			}
			stored.TokenCiphertext = ciphertext
		case hadOld:
			stored.TokenCiphertext = old.TokenCiphertext
		}
		next.Endpoints = append(next.Endpoints, stored)
	}
	normalizeStorageConfig(&next)
	if err := validateStorageConfig(next); err != nil {
		return storageConfig{}, err
	}
	return next, nil
}

func (m *ConfigManager) RuntimeState() (expected int64, active int64, loadedAt *time.Time, loadError string) {
	if m == nil {
		return 1, 0, nil, "config_manager_unavailable"
	}
	expected = m.expected.Load()
	if expected < 1 {
		expected = 1
	}
	if snapshot := m.snapshot.Load(); snapshot != nil {
		active = snapshot.active.ConfigVersion
		value := snapshot.loadedAt
		loadedAt = &value
	}
	m.stateMu.RLock()
	loadError = m.lastLoadError
	m.stateMu.RUnlock()
	return
}

func (m *ConfigManager) Encrypt(value string) (string, error) { return m.encryptor.Encrypt(value) }
func (m *ConfigManager) Decrypt(value string) (string, error) { return m.encryptor.Decrypt(value) }

func (m *ConfigManager) currentRiskControlEnabled() bool {
	if snapshot := m.snapshot.Load(); snapshot != nil {
		return snapshot.active.RiskControlEnabled
	}
	return false
}

func (m *ConfigManager) observeExpectedState(raw string, riskControlEnabled bool) {
	if m == nil {
		return
	}
	if strings.TrimSpace(raw) == "" {
		m.expected.Store(1)
		m.expectedBlocking.Store(false)
		return
	}
	var intent struct {
		Enabled         bool  `json:"enabled"`
		BlockingEnabled bool  `json:"blocking_enabled"`
		ConfigVersion   int64 `json:"config_version"`
	}
	if err := json.Unmarshal([]byte(raw), &intent); err != nil {
		return
	}
	if intent.ConfigVersion < 1 {
		intent.ConfigVersion = 1
	}
	m.expected.Store(intent.ConfigVersion)
	m.expectedBlocking.Store(riskControlEnabled && intent.Enabled && intent.BlockingEnabled)
}

func (m *ConfigManager) refreshLoop(ctx context.Context) {
	defer m.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.Reload(ctx); err != nil {
				LogWarn(EventConfigReloadDegraded, map[string]any{"status": "degraded", "error_code": "config_ttl_reload_failed"})
			}
		}
	}
}

func (m *ConfigManager) subscribeLoop(ctx context.Context) {
	defer m.wg.Done()
	pubsub := m.redis.Subscribe(ctx, ConfigInvalidationChannel, PassRetentionInvalidationChannel)
	defer func() { _ = pubsub.Close() }()
	channel := pubsub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case message, ok := <-channel:
			if !ok {
				return
			}
			version, err := strconv.ParseInt(strings.TrimSpace(message.Payload), 10, 64)
			if err != nil || version < 1 {
				continue
			}
			if message.Channel == ConfigInvalidationChannel {
				m.expected.Store(version)
			}
			if err := m.Reload(ctx); err != nil {
				// A newer published version failed to activate. Until reload
				// succeeds, do not keep serving a potentially stale weaker mode.
				if message.Channel == ConfigInvalidationChannel {
					if active, ok := m.Active(); !ok || active.ConfigVersion < version {
						m.markConfigUntrusted()
					}
				}
				LogWarn(EventConfigReloadDegraded, map[string]any{
					"config_version": version, "status": "degraded", "error_code": "config_invalidation_reload_failed",
				})
			}
		}
	}
}

func (m *ConfigManager) recordLoadError(_ error) {
	if m == nil {
		return
	}
	now := m.clock.Now()
	m.stateMu.Lock()
	m.lastLoadError = stableErrorMessage("config_load_failed")
	m.lastErrorAt = &now
	m.stateMu.Unlock()
}

// clearLoadError drops the recorded load failure and reports whether one was
// pending, so callers can tell a recovery apart from an unchanged reload.
func (m *ConfigManager) clearLoadError() bool {
	m.stateMu.Lock()
	recovered := m.lastLoadError != ""
	m.lastLoadError = ""
	m.lastErrorAt = nil
	m.stateMu.Unlock()
	return recovered
}

func (m *ConfigManager) recordRetentionLoadError() {
	m.stateMu.Lock()
	m.retentionLoadError = "pass_retention_config_invalid"
	m.stateMu.Unlock()
}

func (m *ConfigManager) disablePassRetention(code string) {
	m.stateMu.Lock()
	m.retentionLoadError = code
	m.stateMu.Unlock()
	m.snapshotMu.Lock()
	if previous := m.snapshot.Load(); previous != nil {
		active := cloneActiveConfig(previous.active)
		active.PassRetentionUserIDs = nil
		m.snapshot.Store(&activeConfigSnapshot{
			storage: cloneStorageConfig(previous.storage), retention: defaultPassRetentionStorage(),
			active: active, loadedAt: previous.loadedAt,
		})
	}
	m.snapshotMu.Unlock()
}

func (m *ConfigManager) installPassRetention(next passRetentionStorage) {
	m.snapshotMu.Lock()
	defer m.snapshotMu.Unlock()
	previous := m.snapshot.Load()
	if previous == nil || next.Revision <= previous.retention.Revision {
		return
	}
	active := cloneActiveConfig(previous.active)
	active.PassRetentionUserIDs = append([]int64(nil), next.UserIDs...)
	m.snapshot.Store(&activeConfigSnapshot{
		storage: cloneStorageConfig(previous.storage), retention: clonePassRetentionStorage(next),
		active: active, loadedAt: previous.loadedAt,
	})
}

func (m *ConfigManager) clearRetentionLoadError() {
	m.stateMu.Lock()
	m.retentionLoadError = ""
	m.stateMu.Unlock()
}

func (m *ConfigManager) currentRetentionLoadError() string {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	return m.retentionLoadError
}

func cloneStorageConfig(cfg storageConfig) storageConfig {
	cfg.Scanners = append([]string(nil), cfg.Scanners...)
	cfg.GroupIDs = append([]int64(nil), cfg.GroupIDs...)
	cfg.BlockingExemptUserIDs = append([]int64(nil), cfg.BlockingExemptUserIDs...)
	cfg.Endpoints = append([]StorageEndpoint(nil), cfg.Endpoints...)
	return cfg
}

func cloneActiveConfig(cfg ActiveConfig) ActiveConfig {
	cfg.Scanners = append([]string(nil), cfg.Scanners...)
	cfg.GroupIDs = append([]int64(nil), cfg.GroupIDs...)
	cfg.BlockingExemptUserIDs = append([]int64(nil), cfg.BlockingExemptUserIDs...)
	cfg.PassRetentionUserIDs = append([]int64(nil), cfg.PassRetentionUserIDs...)
	cfg.Endpoints = append([]ActiveEndpoint(nil), cfg.Endpoints...)
	return cfg
}

func clonePassRetentionStorage(stored passRetentionStorage) passRetentionStorage {
	stored.UserIDs = append([]int64{}, stored.UserIDs...)
	return stored
}
