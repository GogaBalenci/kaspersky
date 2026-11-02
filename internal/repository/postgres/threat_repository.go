// Package postgres implements repositories backed by PostgreSQL and pgx.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/balenci/kaspersky/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const threatColumns = `md5, name, type, severity, description, tags, first_seen_at, last_seen_at, created_at, updated_at`

const createThreatQuery = `
INSERT INTO threats (md5, name, type, severity, description, tags, first_seen_at, last_seen_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING ` + threatColumns

const getThreatByMD5Query = `
SELECT ` + threatColumns + `
FROM threats
WHERE md5 = $1`

const updateThreatQuery = `
UPDATE threats
SET name = $2,
    type = $3,
    severity = $4,
    description = $5,
    tags = $6,
    first_seen_at = $7,
    last_seen_at = $8
WHERE md5 = $1
RETURNING ` + threatColumns

// DBTX is intentionally small so the repository can be unit-tested without a running PostgreSQL instance.
type DBTX interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type ThreatRepository struct {
	db DBTX
}

func NewThreatRepository(db DBTX) *ThreatRepository {
	return &ThreatRepository{db: db}
}

func (r *ThreatRepository) Create(ctx context.Context, threat domain.Threat) (domain.Threat, error) {
	row := r.db.QueryRow(ctx, createThreatQuery,
		threat.MD5, threat.Name, threat.Type, threat.Severity, threat.Description,
		threat.Tags, threat.FirstSeenAt, threat.LastSeenAt,
	)
	return scanThreat(row)
}

func (r *ThreatRepository) GetByMD5(ctx context.Context, md5 string) (domain.Threat, error) {
	return scanThreat(r.db.QueryRow(ctx, getThreatByMD5Query, md5))
}

func (r *ThreatRepository) Update(ctx context.Context, threat domain.Threat) (domain.Threat, error) {
	row := r.db.QueryRow(ctx, updateThreatQuery,
		threat.MD5, threat.Name, threat.Type, threat.Severity, threat.Description,
		threat.Tags, threat.FirstSeenAt, threat.LastSeenAt,
	)
	return scanThreat(row)
}

func scanThreat(row pgx.Row) (domain.Threat, error) {
	var threat domain.Threat
	err := row.Scan(
		&threat.MD5,
		&threat.Name,
		&threat.Type,
		&threat.Severity,
		&threat.Description,
		&threat.Tags,
		&threat.FirstSeenAt,
		&threat.LastSeenAt,
		&threat.CreatedAt,
		&threat.UpdatedAt,
	)
	if err == nil {
		return threat, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Threat{}, domain.ErrThreatNotFound
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return domain.Threat{}, domain.ErrThreatExists
		case "23514", "22001", "22021": // check_violation, string_data_right_truncation, character_not_in_repertoire
			return domain.Threat{}, fmt.Errorf("%w: %s", domain.ErrInvalidThreat, pgErr.ConstraintName)
		}
	}
	return domain.Threat{}, fmt.Errorf("scan threat: %w", err)
}
