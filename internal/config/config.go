// Package config loads process configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddress string
	DatabaseURL string
	APIKey      string
	// RequireAPIKeyForReads also protects GET /info/{md5} with X-API-Key.
	RequireAPIKeyForReads bool
	// RequestTimeout bounds handler work, including database queries.
	RequestTimeout time.Duration
	// TLSCertFile and TLSKeyFile enable HTTPS when both are set.
	TLSCertFile string
	TLSKeyFile  string
	RateLimit   RateLimitConfig
	Database    DatabaseConfig
}

type RateLimitConfig struct {
	RequestsPerMinute int
	Burst             int
}

type DatabaseConfig struct {
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
}

// Load reads configuration from environment. DATABASE_URL is deliberately
// required because falling back to a hidden database target is unsafe.
func Load() (Config, error) {
	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if databaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}
	apiKey := strings.TrimSpace(os.Getenv("API_KEY"))
	if apiKey == "" {
		return Config{}, fmt.Errorf("API_KEY is required")
	}

	maxConns, err := int32FromEnv("DB_MAX_CONNS", 10)
	if err != nil {
		return Config{}, err
	}
	minConns, err := int32FromEnv("DB_MIN_CONNS", 1)
	if err != nil {
		return Config{}, err
	}
	if maxConns == 0 {
		return Config{}, fmt.Errorf("DB_MAX_CONNS must be greater than zero")
	}
	if minConns > maxConns {
		return Config{}, fmt.Errorf("DB_MIN_CONNS cannot exceed DB_MAX_CONNS")
	}

	maxConnLifetime, err := durationFromEnv("DB_MAX_CONN_LIFETIME", time.Hour)
	if err != nil {
		return Config{}, err
	}
	maxConnIdleTime, err := durationFromEnv("DB_MAX_CONN_IDLE_TIME", 30*time.Minute)
	if err != nil {
		return Config{}, err
	}
	healthCheckPeriod, err := durationFromEnv("DB_HEALTH_CHECK_PERIOD", time.Minute)
	if err != nil {
		return Config{}, err
	}
	rateLimit, err := positiveIntFromEnv("RATE_LIMIT_PER_MINUTE", 60)
	if err != nil {
		return Config{}, err
	}
	rateLimitBurst, err := positiveIntFromEnv("RATE_LIMIT_BURST", 10)
	if err != nil {
		return Config{}, err
	}

	requestTimeout, err := durationFromEnv("REQUEST_TIMEOUT", 5*time.Second)
	if err != nil {
		return Config{}, err
	}
	if requestTimeout >= MaxRequestTimeout {
		return Config{}, fmt.Errorf("REQUEST_TIMEOUT must be less than %s (the HTTP write timeout)", MaxRequestTimeout)
	}
	requireReadAuth, err := boolFromEnv("REQUIRE_API_KEY_FOR_READS", false)
	if err != nil {
		return Config{}, err
	}
	tlsCertFile := strings.TrimSpace(os.Getenv("TLS_CERT_FILE"))
	tlsKeyFile := strings.TrimSpace(os.Getenv("TLS_KEY_FILE"))
	if (tlsCertFile == "") != (tlsKeyFile == "") {
		return Config{}, fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE must be set together")
	}

	httpAddress := strings.TrimSpace(os.Getenv("HTTP_ADDRESS"))
	if httpAddress == "" {
		httpAddress = ":8080"
	}

	return Config{
		HTTPAddress: httpAddress,
		DatabaseURL: databaseURL,
		APIKey:      apiKey,

		RequireAPIKeyForReads: requireReadAuth,
		RequestTimeout:        requestTimeout,
		TLSCertFile:           tlsCertFile,
		TLSKeyFile:            tlsKeyFile,
		RateLimit: RateLimitConfig{
			RequestsPerMinute: rateLimit,
			Burst:             rateLimitBurst,
		},
		Database: DatabaseConfig{
			MaxConns:          maxConns,
			MinConns:          minConns,
			MaxConnLifetime:   maxConnLifetime,
			MaxConnIdleTime:   maxConnIdleTime,
			HealthCheckPeriod: healthCheckPeriod,
		},
	}, nil
}

// MaxRequestTimeout is the HTTP server write timeout; handler work must finish before it.
const MaxRequestTimeout = 15 * time.Second

func boolFromEnv(name string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", name)
	}
	return parsed, nil
}

func positiveIntFromEnv(name string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}

func int32FromEnv(name string, fallback int32) (int32, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("%s must be a non-negative 32-bit integer", name)
	}
	return int32(parsed), nil
}

func durationFromEnv(name string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive Go duration", name)
	}
	return parsed, nil
}
