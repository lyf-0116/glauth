package handler

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

// SQLBindFailureStore stores bind counters in a shared database table.
//
// MySQL, PostgreSQL and SQLite dialects are supported. The driver itself is
// intentionally not imported: GLAuth loads SQL drivers through its database
// plugins or a custom server build.
type SQLBindFailureStore struct {
	db      *sql.DB
	table   string
	dialect string
}

// NewSQLBindFailureStore creates a shared store using an existing database pool.
func NewSQLBindFailureStore(db *sql.DB, dialect string) *SQLBindFailureStore {
	return &SQLBindFailureStore{db: db, table: "glauth_bind_failures", dialect: dialect}
}

func (s *SQLBindFailureStore) placeholder(index int) string {
	if s.dialect == "postgres" {
		return fmt.Sprintf("$%d", index)
	}
	return "?"
}

func (s *SQLBindFailureStore) forUpdate() string {
	if s.dialect == "sqlite3" || s.dialect == "sqlite" {
		return ""
	}
	return " FOR UPDATE"
}

func (s *SQLBindFailureStore) insertIgnore() string {
	if s.dialect == "mysql" {
		return "INSERT IGNORE INTO"
	}
	return "INSERT INTO"
}

// EnsureSchema creates the counter table if necessary.
func (s *SQLBindFailureStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
	key_hash CHAR(64) NOT NULL PRIMARY KEY,
	key_value TEXT NOT NULL,
	failure_count INTEGER NOT NULL,
	window_start_nanos BIGINT NOT NULL,
	blocked_until_nanos BIGINT NOT NULL,
	last_seen_nanos BIGINT NOT NULL
)`, s.table))
	return err
}

// BindAllowed refreshes last_seen for an existing row and reports block state.
func (s *SQLBindFailureStore) BindAllowed(ctx context.Context, key string, at time.Time) (bool, time.Time, error) {
	hash := hashBindFailureKey(key)

	var blockedUntilNanos int64
	err := s.db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT blocked_until_nanos FROM %s WHERE key_hash = %s`, s.table, s.placeholder(1)),
		hash,
	).Scan(&blockedUntilNanos)
	if err == sql.ErrNoRows {
		return true, time.Time{}, nil
	}
	if err != nil {
		return true, time.Time{}, err
	}

	_, err = s.db.ExecContext(ctx,
		fmt.Sprintf(`UPDATE %s SET last_seen_nanos = %s WHERE key_hash = %s`, s.table, s.placeholder(1), s.placeholder(2)),
		at.UnixNano(), hash,
	)
	if err != nil {
		return true, time.Time{}, err
	}

	if blockedUntilNanos > at.UnixNano() {
		return false, time.Unix(0, blockedUntilNanos), nil
	}
	if blockedUntilNanos != 0 {
		_, err = s.db.ExecContext(ctx, fmt.Sprintf(`
UPDATE %s
   SET failure_count = 0, window_start_nanos = 0, blocked_until_nanos = 0
 WHERE key_hash = %s`, s.table, s.placeholder(1)), hash)
		if err != nil {
			return true, time.Time{}, err
		}
	}
	return true, time.Time{}, nil
}

// RecordBindFailure atomically updates one counter row.
func (s *SQLBindFailureStore) RecordBindFailure(ctx context.Context, key string, at time.Time, policy BindLimitPolicy) (time.Time, error) {
	hash := hashBindFailureKey(key)
	nowNanos := at.UnixNano()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = tx.Rollback() }()

	insertStatement := `
` + s.insertIgnore() + ` %s (key_hash, key_value, failure_count, window_start_nanos, blocked_until_nanos, last_seen_nanos)
VALUES (%s, %s, 0, 0, 0, %s)`
	if s.dialect != "mysql" {
		insertStatement += ` ON CONFLICT (key_hash) DO NOTHING`
	}
	_, err = tx.ExecContext(ctx, fmt.Sprintf(insertStatement,
		s.table, s.placeholder(1), s.placeholder(2), s.placeholder(3)),
		hash, key, nowNanos)
	if err != nil {
		return time.Time{}, err
	}

	var count, windowStartNanos, blockedUntilNanos int64
	err = tx.QueryRowContext(ctx, fmt.Sprintf(`
SELECT failure_count, window_start_nanos, blocked_until_nanos
  FROM %s
 WHERE key_hash = %s%s`, s.table, s.placeholder(1), s.forUpdate()), hash).
		Scan(&count, &windowStartNanos, &blockedUntilNanos)
	if err != nil {
		return time.Time{}, err
	}

	blockedUntil := time.Unix(0, blockedUntilNanos)
	if blockedUntil.After(at) {
		if err := tx.Commit(); err != nil {
			return time.Time{}, err
		}
		return blockedUntil, nil
	}
	if blockedUntilNanos != 0 {
		count = 0
		windowStartNanos = 0
		blockedUntilNanos = 0
	}

	windowStart := time.Unix(0, windowStartNanos)
	if windowStartNanos == 0 || at.Sub(windowStart) >= policy.FailureWindow {
		count = 1
		windowStartNanos = nowNanos
	} else {
		count++
	}

	var newBlockedUntil time.Time
	if policy.Threshold > 0 && int(count) >= policy.Threshold {
		newBlockedUntil = at.Add(policy.BlockDuration)
		blockedUntilNanos = newBlockedUntil.UnixNano()
		count = 0
		windowStartNanos = 0
	} else {
		blockedUntilNanos = 0
	}

	// The statement has five positional parameters. PostgreSQL needs numbered
	// placeholders; ? works for MySQL and SQLite.
	update := fmt.Sprintf(`
UPDATE %s
   SET failure_count = %s,
       window_start_nanos = %s,
       blocked_until_nanos = %s,
       last_seen_nanos = %s
 WHERE key_hash = %s`,
		s.table,
		s.placeholder(1), s.placeholder(2), s.placeholder(3),
		s.placeholder(4), s.placeholder(5))
	_, err = tx.ExecContext(ctx, update,
		count, windowStartNanos, blockedUntilNanos, nowNanos, hash)
	if err != nil {
		return time.Time{}, err
	}
	if err := tx.Commit(); err != nil {
		return time.Time{}, err
	}
	return newBlockedUntil, nil
}

// ResetBindFailures deletes counter rows.
func (s *SQLBindFailureStore) ResetBindFailures(ctx context.Context, keys ...string) error {
	for _, key := range keys {
		if key == "" {
			continue
		}
		if _, err := s.db.ExecContext(ctx,
			fmt.Sprintf(`DELETE FROM %s WHERE key_hash = %s`, s.table, s.placeholder(1)),
			hashBindFailureKey(key),
		); err != nil {
			return err
		}
	}
	return nil
}

// PruneBindFailures removes rows whose keys have not been seen recently.
func (s *SQLBindFailureStore) PruneBindFailures(ctx context.Context, at time.Time, retention time.Duration) error {
	if retention <= 0 {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		fmt.Sprintf(`DELETE FROM %s WHERE last_seen_nanos < %s`, s.table, s.placeholder(1)),
		at.Add(-retention).UnixNano(),
	)
	return err
}

func hashBindFailureKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

var _ BindFailureStore = (*SQLBindFailureStore)(nil)
