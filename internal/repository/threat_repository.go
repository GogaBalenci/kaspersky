// Package repository declares storage contracts used by services.
package repository

import (
	"context"

	"github.com/balenci/kaspersky/internal/domain"
)

type ThreatRepository interface {
	Create(ctx context.Context, threat domain.Threat) (domain.Threat, error)
	GetByMD5(ctx context.Context, md5 string) (domain.Threat, error)
	Update(ctx context.Context, threat domain.Threat) (domain.Threat, error)
}
