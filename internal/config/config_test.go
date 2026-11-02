package config

import (
	"strings"
	"testing"
	"time"
)

func setRequired(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgres://example")
	t.Setenv("API_KEY", "test-key")
}

func TestLoadRejectsMissingAPIKey(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://example")
	t.Setenv("API_KEY", "")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want missing API_KEY error")
	}
}

func TestLoadRejectsZeroMaxConnections(t *testing.T) {
	setRequired(t)
	t.Setenv("DB_MAX_CONNS", "0")
	t.Setenv("DB_MIN_CONNS", "0")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "DB_MAX_CONNS must be greater than zero") {
		t.Fatalf("Load() error = %v, want DB_MAX_CONNS validation error", err)
	}
}

func TestLoadRejectsInvalidSecuritySettings(t *testing.T) {
	tests := map[string]map[string]string{
		"certificate without key":         {"TLS_CERT_FILE": "cert.pem"},
		"key without certificate":         {"TLS_KEY_FILE": "key.pem"},
		"non-boolean read auth":           {"REQUIRE_API_KEY_FOR_READS": "maybe"},
		"timeout not below write timeout": {"REQUEST_TIMEOUT": "15s"},
	}
	for name, env := range tests {
		t.Run(name, func(t *testing.T) {
			setRequired(t)
			for key, value := range env {
				t.Setenv(key, value)
			}
			if _, err := Load(); err == nil {
				t.Fatal("Load() error = nil, want validation error")
			}
		})
	}
}

func TestLoadDefaults(t *testing.T) {
	setRequired(t)
	got, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.RequestTimeout != 5*time.Second || got.RequireAPIKeyForReads || got.TLSCertFile != "" || got.HTTPAddress != ":8080" {
		t.Fatalf("unexpected defaults: %#v", got)
	}
}
