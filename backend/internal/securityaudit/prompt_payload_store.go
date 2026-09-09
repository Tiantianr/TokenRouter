package securityaudit

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const deepReviewClaimTTL = 30 * time.Minute

type DeepReviewClaimStatus uint8

const (
	DeepReviewClaimMissing DeepReviewClaimStatus = iota
	DeepReviewClaimAcquired
	DeepReviewClaimBusy
)

type PayloadStore interface {
	Set(ctx context.Context, jobID int64, scanText string, ttl time.Duration) error
	Get(ctx context.Context, jobID int64) (string, error)
	Delete(ctx context.Context, jobID int64) error
	Ping(ctx context.Context) error
}

type DeepReviewStateStore interface {
	Required(ctx context.Context, userID int64) (token string, required bool, err error)
	Require(ctx context.Context, userID int64, token string) error
	Claim(ctx context.Context, userID int64, token string, ttl time.Duration) (finding string, status DeepReviewClaimStatus, err error)
	ReleaseClaim(ctx context.Context, userID int64, token string) (bool, error)
	ClearClaimed(ctx context.Context, userID int64, finding, claim string) (bool, error)
}

type AllowReceiptStore interface {
	ReceiptsAllowed(ctx context.Context, userID int64, keys []string) ([]bool, error)
	StoreAllowReceipts(ctx context.Context, userID int64, keys []string, ttl time.Duration) error
}

type RedisPayloadStore struct {
	client *redis.Client
}

func NewRedisPayloadStore(client *redis.Client) *RedisPayloadStore {
	return &RedisPayloadStore{client: client}
}

func (s *RedisPayloadStore) Set(ctx context.Context, jobID int64, scanText string, ttl time.Duration) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("prompt audit payload store unavailable")
	}
	if jobID <= 0 || scanText == "" {
		return fmt.Errorf("prompt audit payload input invalid")
	}
	if ttl <= 0 || ttl > DefaultPayloadTTL {
		ttl = DefaultPayloadTTL
	}
	return s.client.Set(ctx, payloadKey(jobID), scanText, ttl).Err()
}

func (s *RedisPayloadStore) Get(ctx context.Context, jobID int64) (string, error) {
	if s == nil || s.client == nil {
		return "", fmt.Errorf("prompt audit payload store unavailable")
	}
	return s.client.Get(ctx, payloadKey(jobID)).Result()
}

func (s *RedisPayloadStore) Delete(ctx context.Context, jobID int64) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("prompt audit payload store unavailable")
	}
	return s.client.Del(ctx, payloadKey(jobID)).Err()
}

func (s *RedisPayloadStore) Ping(ctx context.Context) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("prompt audit payload store unavailable")
	}
	return s.client.Ping(ctx).Err()
}

func (s *RedisPayloadStore) Required(ctx context.Context, userID int64) (string, bool, error) {
	if s == nil || s.client == nil {
		return "", false, fmt.Errorf("prompt audit deep review state unavailable")
	}
	if userID <= 0 {
		return "", false, nil
	}
	token, err := s.client.Get(ctx, deepReviewStateKey(userID)).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return token, strings.TrimSpace(token) != "", nil
}

func (s *RedisPayloadStore) Require(ctx context.Context, userID int64, token string) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("prompt audit deep review state unavailable")
	}
	if userID <= 0 || strings.TrimSpace(token) == "" {
		return fmt.Errorf("prompt audit deep review state input invalid")
	}
	return s.client.Set(ctx, deepReviewStateKey(userID), token, 0).Err()
}

func (s *RedisPayloadStore) Claim(ctx context.Context, userID int64, token string, ttl time.Duration) (string, DeepReviewClaimStatus, error) {
	if s == nil || s.client == nil {
		return "", DeepReviewClaimMissing, fmt.Errorf("prompt audit deep review state unavailable")
	}
	if userID <= 0 || strings.TrimSpace(token) == "" || ttl <= 0 {
		return "", DeepReviewClaimMissing, fmt.Errorf("prompt audit deep review state input invalid")
	}
	ttlMS := ttl.Milliseconds()
	if ttlMS < 1 {
		ttlMS = 1
	}
	result, err := s.client.Eval(ctx, `
		local finding = redis.call('GET', KEYS[1])
		if not finding or finding == '' then
			return {0, ''}
		end
		if redis.call('SET', KEYS[2], ARGV[1], 'NX', 'PX', ARGV[2]) then
			return {1, finding}
		end
		return {2, ''}`, []string{deepReviewStateKey(userID), deepReviewClaimKey(userID)}, token, ttlMS).Slice()
	if err != nil {
		return "", DeepReviewClaimMissing, err
	}
	if len(result) != 2 {
		return "", DeepReviewClaimMissing, fmt.Errorf("prompt audit deep review claim response invalid")
	}
	code, ok := result[0].(int64)
	if !ok {
		return "", DeepReviewClaimMissing, fmt.Errorf("prompt audit deep review claim response invalid")
	}
	switch DeepReviewClaimStatus(code) {
	case DeepReviewClaimMissing:
		return "", DeepReviewClaimMissing, nil
	case DeepReviewClaimAcquired:
		finding, ok := result[1].(string)
		if !ok || strings.TrimSpace(finding) == "" {
			return "", DeepReviewClaimMissing, fmt.Errorf("prompt audit deep review claim response invalid")
		}
		return finding, DeepReviewClaimAcquired, nil
	case DeepReviewClaimBusy:
		return "", DeepReviewClaimBusy, nil
	default:
		return "", DeepReviewClaimMissing, fmt.Errorf("prompt audit deep review claim response invalid")
	}
}

func (s *RedisPayloadStore) ReleaseClaim(ctx context.Context, userID int64, token string) (bool, error) {
	if s == nil || s.client == nil {
		return false, fmt.Errorf("prompt audit deep review state unavailable")
	}
	if userID <= 0 || strings.TrimSpace(token) == "" {
		return false, fmt.Errorf("prompt audit deep review state input invalid")
	}
	result, err := s.client.Eval(ctx, `
		if redis.call('GET', KEYS[1]) == ARGV[1] then
			return redis.call('DEL', KEYS[1])
		end
		return 0`, []string{deepReviewClaimKey(userID)}, token).Int64()
	return result == 1, err
}

func (s *RedisPayloadStore) ClearClaimed(ctx context.Context, userID int64, finding, claim string) (bool, error) {
	if s == nil || s.client == nil {
		return false, fmt.Errorf("prompt audit deep review state unavailable")
	}
	if userID <= 0 || strings.TrimSpace(finding) == "" || strings.TrimSpace(claim) == "" {
		return false, fmt.Errorf("prompt audit deep review state input invalid")
	}
	result, err := s.client.Eval(ctx, `
		if redis.call('GET', KEYS[1]) == ARGV[1] and redis.call('GET', KEYS[2]) == ARGV[2] then
			return redis.call('DEL', KEYS[1])
		end
		return 0`, []string{deepReviewStateKey(userID), deepReviewClaimKey(userID)}, finding, claim).Int64()
	return result == 1, err
}

func (s *RedisPayloadStore) ReceiptsAllowed(ctx context.Context, userID int64, keys []string) ([]bool, error) {
	if s == nil || s.client == nil {
		return nil, fmt.Errorf("prompt audit allow receipt store unavailable")
	}
	redisKeys, ok := allowReceiptRedisKeys(userID, keys)
	if !ok {
		return nil, fmt.Errorf("prompt audit allow receipt input invalid")
	}
	values, err := s.client.MGet(ctx, redisKeys...).Result()
	if err != nil {
		return nil, err
	}
	allowed := make([]bool, len(values))
	for index, value := range values {
		allowed[index] = value != nil
	}
	return allowed, nil
}

func (s *RedisPayloadStore) StoreAllowReceipts(ctx context.Context, userID int64, keys []string, ttl time.Duration) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("prompt audit allow receipt store unavailable")
	}
	redisKeys, ok := allowReceiptRedisKeys(userID, keys)
	if !ok || ttl <= 0 {
		return fmt.Errorf("prompt audit allow receipt input invalid")
	}
	pipe := s.client.Pipeline()
	for _, key := range redisKeys {
		pipe.Set(ctx, key, "1", ttl)
	}
	_, err := pipe.Exec(ctx)
	return err
}

func payloadKey(jobID int64) string {
	return PayloadKeyPrefix + strconv.FormatInt(jobID, 10)
}

func deepReviewStateKey(userID int64) string {
	return DeepReviewStateKeyPrefix + strconv.FormatInt(userID, 10)
}

func deepReviewClaimKey(userID int64) string {
	return DeepReviewClaimKeyPrefix + strconv.FormatInt(userID, 10)
}

func allowReceiptRedisKey(userID int64, key string) string {
	return AllowReceiptKeyPrefix + strconv.FormatInt(userID, 10) + ":" + key
}

func allowReceiptRedisKeys(userID int64, keys []string) ([]string, bool) {
	if userID <= 0 || len(keys) == 0 {
		return nil, false
	}
	result := make([]string, len(keys))
	for index, key := range keys {
		if !validAllowReceiptKey(key) {
			return nil, false
		}
		result[index] = allowReceiptRedisKey(userID, key)
	}
	return result, true
}

func validAllowReceiptKey(key string) bool {
	if len(key) != 64 {
		return false
	}
	for _, char := range key {
		if char < '0' || char > '9' {
			if char < 'a' || char > 'f' {
				return false
			}
		}
	}
	return true
}
