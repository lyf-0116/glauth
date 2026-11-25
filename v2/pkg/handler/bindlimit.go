package handler

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/glauth/glauth/v2/pkg/config"
)

// BindLimitPolicy configures the two independent bind-failure dimensions.
type BindLimitPolicy struct {
	Enabled       bool
	Threshold     int
	FailureWindow time.Duration
	BlockDuration time.Duration
	Retention     time.Duration
	PruneInterval time.Duration
}

// BindFailureStore is the synchronization boundary for bind counters.
//
// A process-local implementation is suitable for one replica. A database or
// cache implementation can be shared by all GLAuth replicas; its
// RecordBindFailure implementation must make the read/modify/write sequence
// atomic for a key.
type BindFailureStore interface {
	BindAllowed(ctx context.Context, key string, at time.Time) (bool, time.Time, error)
	RecordBindFailure(ctx context.Context, key string, at time.Time, policy BindLimitPolicy) (time.Time, error)
	ResetBindFailures(ctx context.Context, keys ...string) error
	PruneBindFailures(ctx context.Context, at time.Time, retention time.Duration) error
}

// MemoryBindFailureStore is the default, concurrency-safe store. Two helper
// instances configured with the same value share failure state in-process.
type MemoryBindFailureStore struct {
	mu      sync.Mutex
	records map[string]*memoryBindFailure
}

type memoryBindFailure struct {
	count        int
	windowStart  time.Time
	blockedUntil time.Time
	lastSeen     time.Time
}

// NewMemoryBindFailureStore creates an empty in-memory failure store.
func NewMemoryBindFailureStore() *MemoryBindFailureStore {
	return &MemoryBindFailureStore{records: make(map[string]*memoryBindFailure)}
}

// BindAllowed reports whether a key is outside its block window.
func (s *MemoryBindFailureStore) BindAllowed(_ context.Context, key string, at time.Time) (bool, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.records[key]
	if !ok {
		return true, time.Time{}, nil
	}

	record.lastSeen = at
	if record.blockedUntil.After(at) {
		return false, record.blockedUntil, nil
	}
	if !record.blockedUntil.IsZero() {
		record.count = 0
		record.windowStart = time.Time{}
		record.blockedUntil = time.Time{}
	}
	return true, time.Time{}, nil
}

// RecordBindFailure adds one failure and blocks the key when threshold is reached.
func (s *MemoryBindFailureStore) RecordBindFailure(_ context.Context, key string, at time.Time, policy BindLimitPolicy) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.records[key]
	if !ok {
		record = &memoryBindFailure{}
		s.records[key] = record
	}
	record.lastSeen = at

	if record.blockedUntil.After(at) {
		return record.blockedUntil, nil
	}
	if !record.blockedUntil.IsZero() {
		record.count = 0
		record.windowStart = time.Time{}
		record.blockedUntil = time.Time{}
	}

	if record.windowStart.IsZero() || at.Sub(record.windowStart) >= policy.FailureWindow {
		record.windowStart = at
		record.count = 1
	} else {
		record.count++
	}

	if policy.Threshold > 0 && record.count >= policy.Threshold {
		record.blockedUntil = at.Add(policy.BlockDuration)
		record.count = 0
		record.windowStart = time.Time{}
		return record.blockedUntil, nil
	}
	return time.Time{}, nil
}

// ResetBindFailures removes all state for the given keys.
func (s *MemoryBindFailureStore) ResetBindFailures(_ context.Context, keys ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, key := range keys {
		delete(s.records, key)
	}
	return nil
}

// PruneBindFailures removes keys that have not been seen within retention.
func (s *MemoryBindFailureStore) PruneBindFailures(_ context.Context, at time.Time, retention time.Duration) error {
	if retention <= 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for key, record := range s.records {
		if at.Sub(record.lastSeen) > retention {
			delete(s.records, key)
		}
	}
	return nil
}

type bindGuard struct {
	store BindFailureStore
	now   func() time.Time

	pruneMu   sync.Mutex
	nextPrune time.Time
}

func newBindGuard(store BindFailureStore) *bindGuard {
	if store == nil {
		store = NewMemoryBindFailureStore()
	}
	return &bindGuard{store: store, now: time.Now}
}

func (g *bindGuard) at() time.Time {
	if g == nil || g.now == nil {
		return time.Now()
	}
	return g.now()
}

func (g *bindGuard) allowed(ctx context.Context, key string) bool {
	if g == nil || key == "" {
		return true
	}
	allowed, _, err := g.store.BindAllowed(ctx, key, g.at())
	if err != nil {
		log.Ctx(ctx).Warn().Err(err).Str("key", key).Msg("bind failure store check failed; rejecting bind")
		return false
	}
	return allowed
}

func (g *bindGuard) failure(ctx context.Context, policy BindLimitPolicy, keys ...string) {
	if g == nil || !policy.Enabled {
		return
	}
	now := g.at()
	for _, key := range keys {
		if key == "" {
			continue
		}
		if _, err := g.store.RecordBindFailure(ctx, key, now, policy); err != nil {
			log.Ctx(ctx).Warn().Err(err).Str("key", key).Msg("could not record bind failure")
		}
	}
	g.pruneMaybe(ctx, policy, now)
}

func (g *bindGuard) reset(ctx context.Context, keys ...string) {
	if g == nil {
		return
	}
	valid := keys[:0]
	for _, key := range keys {
		if key != "" {
			valid = append(valid, key)
		}
	}
	if len(valid) > 0 {
		_ = g.store.ResetBindFailures(ctx, valid...)
	}
}

func (g *bindGuard) pruneMaybe(ctx context.Context, policy BindLimitPolicy, now time.Time) {
	if g == nil || policy.Retention <= 0 || policy.PruneInterval <= 0 {
		return
	}

	g.pruneMu.Lock()
	if g.nextPrune.After(now) {
		g.pruneMu.Unlock()
		return
	}
	g.nextPrune = now.Add(policy.PruneInterval)
	g.pruneMu.Unlock()

	if err := g.store.PruneBindFailures(ctx, now, policy.Retention); err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("could not prune bind failure records")
	}
}

// bindLimitPolicyFromConfig maps the historical integer-seconds settings to
// durations. A caller that supplies an actual duration (for example in tests)
// is respected; raw TOML integers decode as nanosecond values such as 10 and
// have historically meant 10 seconds.
func bindLimitPolicyFromConfig(cfg *config.Config) BindLimitPolicy {
	if cfg == nil {
		return BindLimitPolicy{}
	}
	behaviors := cfg.Behaviors
	policy := BindLimitPolicy{
		Enabled:       behaviors.LimitFailedBinds,
		Threshold:     behaviors.NumberOfFailedBinds,
		FailureWindow: bindConfigSeconds(behaviors.PeriodOfFailedBinds),
		BlockDuration: bindConfigSeconds(behaviors.BlockFailedBindsFor),
		Retention:     bindConfigSeconds(behaviors.PruneSourcesOlderThan),
		PruneInterval: bindConfigSeconds(behaviors.PruneSourceTableEvery),
	}
	if policy.Enabled {
		if policy.Threshold <= 0 {
			policy.Threshold = 3
		}
		if policy.FailureWindow <= 0 {
			policy.FailureWindow = 10 * time.Second
		}
		if policy.BlockDuration <= 0 {
			policy.BlockDuration = 60 * time.Second
		}
		if policy.Retention <= 0 {
			policy.Retention = 600 * time.Second
		}
		if policy.PruneInterval <= 0 {
			policy.PruneInterval = 600 * time.Second
		}
	}
	return policy
}

func bindConfigSeconds(value time.Duration) time.Duration {
	if value <= 0 {
		return 0
	}
	// Raw TOML integers and existing unit tests using untyped integer constants
	// arrive as a handful of nanoseconds. Real duration values are much larger.
	if value < time.Microsecond {
		return time.Duration(int64(value)) * time.Second
	}
	return value
}

func sourceBindKey(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return ""
	}
	return "source:" + source
}

func principalBindKey(principal string) string {
	principal = strings.ToLower(strings.TrimSpace(principal))
	if principal == "" {
		return ""
	}
	return "principal:" + principal
}

func attemptedBindPrincipal(bindDN string, backend config.Backend) string {
	bindDN = strings.ToLower(strings.TrimSpace(bindDN))
	if bindDN == "" {
		return ""
	}
	candidates := bindDNCandidates(&backend, bindDN)
	if len(candidates) > 0 {
		return candidates[0].name
	}
	return bindDN
}
