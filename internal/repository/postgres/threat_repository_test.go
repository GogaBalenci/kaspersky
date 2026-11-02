package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/balenci/kaspersky/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type fakeDB struct {
	query string
	args  []any
	row   pgx.Row
}

func (db *fakeDB) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	db.query = query
	db.args = args
	return db.row
}

type fakeRow struct {
	values []any
	err    error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, value := range r.values {
		reflect.ValueOf(dest[i]).Elem().Set(reflect.ValueOf(value))
	}
	return nil
}

func TestThreatRepositoryCreate(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	description := "Steals credentials"
	input := domain.Threat{
		MD5:         "d41d8cd98f00b204e9800998ecf8427e",
		Name:        "Trojan.Win32.Generic",
		Type:        domain.ThreatTypeTrojan,
		Severity:    domain.SeverityHigh,
		Description: &description,
		Tags:        []string{"stealer", "windows"},
	}
	db := &fakeDB{row: fakeRow{values: []any{
		input.MD5, input.Name, input.Type, input.Severity, input.Description,
		input.Tags, (*time.Time)(nil), (*time.Time)(nil), now, now,
	}}}

	got, err := NewThreatRepository(db).Create(context.Background(), input)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if db.query != createThreatQuery {
		t.Fatal("Create() used an unexpected SQL query")
	}
	if !reflect.DeepEqual(got, domain.Threat{
		MD5: input.MD5, Name: input.Name, Type: input.Type, Severity: input.Severity,
		Description: input.Description, Tags: input.Tags, CreatedAt: now, UpdatedAt: now,
	}) {
		t.Fatalf("Create() threat = %#v", got)
	}
}

func TestThreatRepositoryGetByMD5NotFound(t *testing.T) {
	db := &fakeDB{row: fakeRow{err: pgx.ErrNoRows}}
	_, err := NewThreatRepository(db).GetByMD5(context.Background(), "d41d8cd98f00b204e9800998ecf8427e")
	if !errors.Is(err, domain.ErrThreatNotFound) {
		t.Fatalf("GetByMD5() error = %v, want ErrThreatNotFound", err)
	}
}

func TestThreatRepositoryUpdate(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	input := domain.Threat{MD5: "d41d8cd98f00b204e9800998ecf8427e", Name: "Renamed", Type: domain.ThreatTypeWorm, Severity: domain.SeverityLow, Tags: []string{}}
	db := &fakeDB{row: fakeRow{values: []any{
		input.MD5, input.Name, input.Type, input.Severity, (*string)(nil),
		input.Tags, (*time.Time)(nil), (*time.Time)(nil), now, now,
	}}}

	got, err := NewThreatRepository(db).Update(context.Background(), input)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if db.query != updateThreatQuery || db.args[0] != input.MD5 {
		t.Fatalf("Update() query/args = %q %v", db.query, db.args)
	}
	if got.Name != "Renamed" || got.UpdatedAt != now {
		t.Fatalf("Update() threat = %#v", got)
	}
}

func TestThreatRepositoryMapsPostgreSQLErrors(t *testing.T) {
	tests := map[string]struct {
		err  error
		want error
	}{
		"unique violation": {&pgconn.PgError{Code: "23505"}, domain.ErrThreatExists},
		"check violation":  {&pgconn.PgError{Code: "23514", ConstraintName: "threats_name_not_blank"}, domain.ErrInvalidThreat},
		"not found":        {pgx.ErrNoRows, domain.ErrThreatNotFound},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := NewThreatRepository(&fakeDB{row: fakeRow{err: test.err}}).Update(context.Background(), domain.Threat{})
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}
