// Package database creates and verifies PostgreSQL connection pools.
package database

import (
	"context"
	"fmt"

	"github.com/balenci/kaspersky/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

func NewPostgresPool(ctx context.Context, databaseURL string, settings config.DatabaseConfig) (*pgxpool.Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}

	poolConfig.MaxConns = settings.MaxConns
	poolConfig.MinConns = settings.MinConns
	poolConfig.MaxConnLifetime = settings.MaxConnLifetime
	poolConfig.MaxConnIdleTime = settings.MaxConnIdleTime
	poolConfig.HealthCheckPeriod = settings.HealthCheckPeriod

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("create PostgreSQL pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping PostgreSQL: %w", err)
	}

	return pool, nil
}
