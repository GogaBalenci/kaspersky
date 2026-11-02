package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/balenci/kaspersky/internal/domain"
)

type fakeThreatRepository struct {
	created domain.Threat
}

func (r *fakeThreatRepository) Create(_ context.Context, threat domain.Threat) (domain.Threat, error) {
	r.created = threat
	return threat, nil
}

func (r *fakeThreatRepository) GetByMD5(_ context.Context, md5 string) (domain.Threat, error) {
	return domain.Threat{MD5: md5}, nil
}

func (r *fakeThreatRepository) Update(_ context.Context, threat domain.Threat) (domain.Threat, error) {
	return threat, nil
}

func TestCreateNormalizesMD5BeforePersistence(t *testing.T) {
	repository := &fakeThreatRepository{}
	service := NewThreatService(repository)

	_, err := service.Create(context.Background(), CreateThreatInput{
		MD5:      "D41D8CD98F00B204E9800998ECF8427E",
		Name:     "Trojan.Win32.Generic",
		Type:     domain.ThreatTypeTrojan,
		Severity: domain.SeverityHigh,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if repository.created.MD5 != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Fatalf("persisted MD5 = %q", repository.created.MD5)
	}
}

func TestGetByMD5RejectsInvalidHash(t *testing.T) {
	service := NewThreatService(&fakeThreatRepository{})
	_, err := service.GetByMD5(context.Background(), "not-an-md5")
	if err == nil {
		t.Fatal("GetByMD5() error = nil, want validation error")
	}
}

func TestCreateRejectsInvalidFieldValues(t *testing.T) {
	service := NewThreatService(&fakeThreatRepository{})
	tests := []struct {
		name  string
		input CreateThreatInput
	}{
		{
			name:  "invalid severity",
			input: CreateThreatInput{MD5: "d41d8cd98f00b204e9800998ecf8427e", Name: "Example", Type: domain.ThreatTypeTrojan, Severity: "dangerous"},
		},
		{
			name:  "duplicate tags",
			input: CreateThreatInput{MD5: "d41d8cd98f00b204e9800998ecf8427e", Name: "Example", Type: domain.ThreatTypeTrojan, Severity: domain.SeverityHigh, Tags: []string{"windows", "windows"}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := service.Create(context.Background(), test.input)
			if err == nil {
				t.Fatal("Create() error = nil, want validation error")
			}
			if _, ok := err.(*ValidationError); !ok {
				t.Fatalf("Create() error = %T, want *ValidationError", err)
			}
		})
	}
}

func TestValidationRejectsValuesPostgreSQLCannotStoreOrReturn(t *testing.T) {
	fixedNow := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	previousNow := now
	now = func() time.Time { return fixedNow }
	t.Cleanup(func() { now = previousNow })

	nul := "x\x00y"
	beforeEpoch := time.Date(1969, 12, 31, 23, 59, 59, 0, time.UTC)
	farFuture := time.Date(9999, 12, 31, 23, 59, 59, 0, time.FixedZone("", -23*3600))
	tomorrowPlus := fixedNow.Add(25 * time.Hour)
	base := func() CreateThreatInput {
		return CreateThreatInput{MD5: "d41d8cd98f00b204e9800998ecf8427e", Name: "Example", Type: domain.ThreatTypeTrojan, Severity: domain.SeverityHigh}
	}
	tests := map[string]func(*CreateThreatInput){
		"NUL in name":                 func(in *CreateThreatInput) { in.Name = nul },
		"NUL in description":          func(in *CreateThreatInput) { in.Description = &nul },
		"NUL in tag":                  func(in *CreateThreatInput) { in.Tags = []string{nul} },
		"first_seen_at before epoch":  func(in *CreateThreatInput) { in.FirstSeenAt = &beforeEpoch },
		"first_seen_at in year 10000": func(in *CreateThreatInput) { in.FirstSeenAt = &farFuture },
		"last_seen_at too far ahead":  func(in *CreateThreatInput) { in.LastSeenAt = &tomorrowPlus },
		"empty explicit type":         func(in *CreateThreatInput) { in.Type = "" },
		"empty explicit severity":     func(in *CreateThreatInput) { in.Severity = "" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := base()
			mutate(&input)
			_, err := NewThreatService(&fakeThreatRepository{}).Create(context.Background(), input)
			var validationError *ValidationError
			if !errors.As(err, &validationError) {
				t.Fatalf("Create() error = %v, want *ValidationError", err)
			}
		})
	}

	t.Run("seen timestamps inside the window are accepted", func(t *testing.T) {
		input := base()
		first := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
		last := fixedNow.Add(time.Hour)
		input.FirstSeenAt, input.LastSeenAt = &first, &last
		if _, err := NewThreatService(&fakeThreatRepository{}).Create(context.Background(), input); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	})
}

func TestValidationRejectsControlCharactersAndDropsBlankDescription(t *testing.T) {
	repository := &fakeThreatRepository{}
	threats := NewThreatService(repository)
	base := CreateThreatInput{MD5: "d41d8cd98f00b204e9800998ecf8427e", Name: "Example", Type: domain.ThreatTypeTrojan, Severity: domain.SeverityHigh}

	for name, mutate := range map[string]func(*CreateThreatInput){
		"newline in name": func(in *CreateThreatInput) { in.Name = "Trojan\nFake" },
		"escape in tag":   func(in *CreateThreatInput) { in.Tags = []string{"a\x1b[31m"} },
	} {
		t.Run(name, func(t *testing.T) {
			input := base
			mutate(&input)
			var validationError *ValidationError
			if _, err := threats.Create(context.Background(), input); !errors.As(err, &validationError) {
				t.Fatalf("Create() error = %v, want *ValidationError", err)
			}
		})
	}

	t.Run("multi-line description is allowed, blank becomes absent", func(t *testing.T) {
		input := base
		multiLine := "line one\nline two"
		input.Description = &multiLine
		if _, err := threats.Create(context.Background(), input); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		blank := "   "
		input.Description = &blank
		if _, err := threats.Create(context.Background(), input); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		if repository.created.Description != nil {
			t.Fatalf("description = %q, want nil", *repository.created.Description)
		}
	})
}
