// Package service contains threat use cases and input validation.
package service

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/balenci/kaspersky/internal/domain"
	"github.com/balenci/kaspersky/internal/repository"
)

var md5Pattern = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

// minSeenAt and maxSeenAtSkew bound observation timestamps. Values outside this
// window are not meaningful for a threat sighting and, at the extremes, cannot be
// serialized back to RFC 3339 JSON once PostgreSQL returns them in a local zone.
var (
	minSeenAt     = time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)
	maxSeenAtSkew = 24 * time.Hour
	now           = time.Now
)

// ValidationError describes client input that violates the service contract.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

type CreateThreatInput struct {
	MD5         string
	Name        string
	Type        domain.ThreatType
	Severity    domain.Severity
	Description *string
	Tags        []string
	FirstSeenAt *time.Time
	LastSeenAt  *time.Time
}

type UpdateThreatInput struct {
	Name        string
	Type        domain.ThreatType
	Severity    domain.Severity
	Description *string
	Tags        []string
	FirstSeenAt *time.Time
	LastSeenAt  *time.Time
}

type ThreatService struct {
	repository repository.ThreatRepository
}

func NewThreatService(repository repository.ThreatRepository) *ThreatService {
	return &ThreatService{repository: repository}
}

func (s *ThreatService) Create(ctx context.Context, input CreateThreatInput) (domain.Threat, error) {
	threat, err := threatFromCreate(input)
	if err != nil {
		return domain.Threat{}, err
	}
	return s.repository.Create(ctx, threat)
}

func (s *ThreatService) GetByMD5(ctx context.Context, md5 string) (domain.Threat, error) {
	normalizedMD5, err := normalizeMD5(md5)
	if err != nil {
		return domain.Threat{}, err
	}
	return s.repository.GetByMD5(ctx, normalizedMD5)
}

func (s *ThreatService) Update(ctx context.Context, md5 string, input UpdateThreatInput) (domain.Threat, error) {
	normalizedMD5, err := normalizeMD5(md5)
	if err != nil {
		return domain.Threat{}, err
	}
	threat, err := threatFromUpdate(normalizedMD5, input)
	if err != nil {
		return domain.Threat{}, err
	}
	return s.repository.Update(ctx, threat)
}

func threatFromCreate(input CreateThreatInput) (domain.Threat, error) {
	md5, err := normalizeMD5(input.MD5)
	if err != nil {
		return domain.Threat{}, err
	}
	return validatedThreat(md5, input.Name, input.Type, input.Severity, input.Description, input.Tags, input.FirstSeenAt, input.LastSeenAt)
}

func threatFromUpdate(md5 string, input UpdateThreatInput) (domain.Threat, error) {
	return validatedThreat(md5, input.Name, input.Type, input.Severity, input.Description, input.Tags, input.FirstSeenAt, input.LastSeenAt)
}

func validatedThreat(md5, name string, threatType domain.ThreatType, severity domain.Severity, description *string, tags []string, firstSeenAt, lastSeenAt *time.Time) (domain.Threat, error) {
	name = strings.TrimSpace(name)
	if count := utf8.RuneCountInString(name); count == 0 || count > 255 {
		return domain.Threat{}, invalid("name", "must contain from 1 to 255 characters")
	}
	if containsControl(name) {
		return domain.Threat{}, invalid("name", "must not contain control characters")
	}
	if !validThreatType(threatType) {
		return domain.Threat{}, invalid("type", "must be one of trojan, ransomware, worm, adware, spyware, other")
	}
	if !validSeverity(severity) {
		return domain.Threat{}, invalid("severity", "must be one of low, medium, high, critical")
	}
	if description != nil && strings.TrimSpace(*description) == "" {
		// An empty description carries no information; store it as absent.
		description = nil
	}
	if description != nil && utf8.RuneCountInString(*description) > 4000 {
		return domain.Threat{}, invalid("description", "must not exceed 4000 characters")
	}
	if description != nil && containsNUL(*description) {
		return domain.Threat{}, invalid("description", "must not contain NUL characters")
	}
	normalizedTags, err := normalizeTags(tags)
	if err != nil {
		return domain.Threat{}, err
	}
	if err := validateSeenAt("first_seen_at", firstSeenAt); err != nil {
		return domain.Threat{}, err
	}
	if err := validateSeenAt("last_seen_at", lastSeenAt); err != nil {
		return domain.Threat{}, err
	}
	if firstSeenAt != nil && lastSeenAt != nil && firstSeenAt.After(*lastSeenAt) {
		return domain.Threat{}, invalid("first_seen_at", "must not be after last_seen_at")
	}

	return domain.Threat{
		MD5: md5, Name: name, Type: threatType, Severity: severity, Description: description,
		Tags: normalizedTags, FirstSeenAt: firstSeenAt, LastSeenAt: lastSeenAt,
	}, nil
}

func normalizeMD5(value string) (string, error) {
	if !md5Pattern.MatchString(value) {
		return "", invalid("md5", "must contain exactly 32 hexadecimal characters")
	}
	return strings.ToLower(value), nil
}

func normalizeTags(tags []string) ([]string, error) {
	if len(tags) > 20 {
		return nil, invalid("tags", "must not contain more than 20 values")
	}
	normalized := make([]string, 0, len(tags))
	seen := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if count := utf8.RuneCountInString(tag); count == 0 || count > 64 {
			return nil, invalid("tags", "each tag must contain from 1 to 64 characters")
		}
		if containsControl(tag) {
			return nil, invalid("tags", "must not contain control characters")
		}
		if _, exists := seen[tag]; exists {
			return nil, invalid("tags", "must not contain duplicate values")
		}
		seen[tag] = struct{}{}
		normalized = append(normalized, tag)
	}
	return normalized, nil
}

// containsNUL reports whether value has a NUL character, which PostgreSQL text
// columns reject; catching it here keeps such input a 400 instead of a 500.
func containsNUL(value string) bool {
	return strings.ContainsRune(value, 0)
}

// containsControl reports whether a single-line value (name, tag) contains control
// characters such as NUL, newlines or escape sequences.
func containsControl(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}

func validateSeenAt(field string, value *time.Time) error {
	if value == nil {
		return nil
	}
	if value.Before(minSeenAt) || value.After(now().Add(maxSeenAtSkew)) {
		return invalid(field, "must be between 1970-01-01T00:00:00Z and the current time plus 24 hours")
	}
	return nil
}

func validThreatType(value domain.ThreatType) bool {
	switch value {
	case domain.ThreatTypeTrojan, domain.ThreatTypeRansomware, domain.ThreatTypeWorm, domain.ThreatTypeAdware, domain.ThreatTypeSpyware, domain.ThreatTypeOther:
		return true
	default:
		return false
	}
}

func validSeverity(value domain.Severity) bool {
	switch value {
	case domain.SeverityLow, domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical:
		return true
	default:
		return false
	}
}

func invalid(field, message string) error {
	return &ValidationError{Field: field, Message: message}
}
