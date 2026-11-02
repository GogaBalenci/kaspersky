// Package domain defines the core business entities without infrastructure dependencies.
package domain

import "time"

type ThreatType string

// DefaultThreatType and DefaultSeverity are applied when a client omits the
// optional classification fields, keeping the original md5+name contract valid.
const (
	DefaultThreatType = ThreatTypeOther
	DefaultSeverity   = SeverityMedium
)

const (
	ThreatTypeTrojan     ThreatType = "trojan"
	ThreatTypeRansomware ThreatType = "ransomware"
	ThreatTypeWorm       ThreatType = "worm"
	ThreatTypeAdware     ThreatType = "adware"
	ThreatTypeSpyware    ThreatType = "spyware"
	ThreatTypeOther      ThreatType = "other"
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Threat is the persistent, enriched information about a file threat.
// Timestamps created by the database are always populated on returned entities.
type Threat struct {
	MD5         string
	Name        string
	Type        ThreatType
	Severity    Severity
	Description *string
	Tags        []string
	FirstSeenAt *time.Time
	LastSeenAt  *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
