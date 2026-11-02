package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/balenci/kaspersky/internal/config"
	"github.com/balenci/kaspersky/internal/platform/database"
	"github.com/balenci/kaspersky/internal/repository/postgres"
	"github.com/balenci/kaspersky/internal/service"
	httptransport "github.com/balenci/kaspersky/internal/transport/http"
	"github.com/balenci/kaspersky/migrations"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const integrationAPIKey = "integration-test-api-key"

func TestThreatAPIIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// INTEGRATION_DATABASE_URL points the test at an existing, disposable PostgreSQL
	// database (for environments without Docker); otherwise Testcontainers is used.
	databaseURL := os.Getenv("INTEGRATION_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = startPostgresContainer(ctx, t)
	}
	pool, err := database.NewPostgresPool(ctx, databaseURL, config.DatabaseConfig{MaxConns: 4, MinConns: 1, MaxConnLifetime: time.Hour, MaxConnIdleTime: time.Minute, HealthCheckPeriod: time.Minute})
	if err != nil {
		t.Fatalf("create PostgreSQL pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	repository := postgres.NewThreatRepository(pool)
	handler := httptransport.NewHandlerWithOptions(service.NewThreatService(repository), httptransport.HandlerOptions{APIKey: integrationAPIKey, HealthChecker: pool})
	server := httptest.NewServer(httptransport.NewRouter(handler, httptransport.RouterOptions{RequestsPerMinute: 10000, RateLimitBurst: 10000}))
	t.Cleanup(server.Close)

	client := server.Client()
	md5 := "d41d8cd98f00b204e9800998ecf8427e"
	t.Run("create get update and duplicate", func(t *testing.T) {
		create := request(t, client, http.MethodPost, server.URL+"/info", integrationAPIKey, map[string]any{
			"md5": md5, "name": "Trojan.Win32.Generic", "type": "trojan", "severity": "high", "tags": []string{"windows"},
		})
		if create.StatusCode != http.StatusCreated {
			t.Fatalf("create status = %d, body = %s", create.StatusCode, responseBody(t, create))
		}
		create.Body.Close()

		get := request(t, client, http.MethodGet, server.URL+"/info/D41D8CD98F00B204E9800998ECF8427E", "", nil)
		if get.StatusCode != http.StatusOK {
			t.Fatalf("get status = %d, body = %s", get.StatusCode, responseBody(t, get))
		}
		var fetched struct {
			MD5  string `json:"md5"`
			Name string `json:"name"`
		}
		decodeResponse(t, get, &fetched)
		if fetched.MD5 != md5 || fetched.Name != "Trojan.Win32.Generic" {
			t.Fatalf("unexpected fetched threat: %#v", fetched)
		}

		update := request(t, client, http.MethodPut, server.URL+"/info/"+md5, integrationAPIKey, map[string]any{
			"name": "Ransom.Win32.Example", "type": "ransomware", "severity": "critical", "tags": []string{"windows", "encryptor"},
		})
		if update.StatusCode != http.StatusOK {
			t.Fatalf("update status = %d, body = %s", update.StatusCode, responseBody(t, update))
		}
		var updated struct {
			Name     string `json:"name"`
			Severity string `json:"severity"`
		}
		decodeResponse(t, update, &updated)
		if updated.Name != "Ransom.Win32.Example" || updated.Severity != "critical" {
			t.Fatalf("unexpected updated threat: %#v", updated)
		}

		duplicate := request(t, client, http.MethodPost, server.URL+"/info", integrationAPIKey, map[string]any{
			"md5": md5, "name": "Duplicate", "type": "trojan", "severity": "high",
		})
		assertStatus(t, duplicate, http.StatusConflict)
	})

	t.Run("validation and authorization errors", func(t *testing.T) {
		assertStatus(t, request(t, client, http.MethodGet, server.URL+"/info/not-an-md5", "", nil), http.StatusBadRequest)
		assertStatus(t, request(t, client, http.MethodGet, server.URL+"/info/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", nil), http.StatusNotFound)
		assertStatus(t, request(t, client, http.MethodPost, server.URL+"/info", "", map[string]any{
			"md5": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "name": "Unauthorized", "type": "trojan", "severity": "high",
		}), http.StatusUnauthorized)
		assertStatus(t, request(t, client, http.MethodPost, server.URL+"/info", integrationAPIKey, map[string]any{
			"md5": "cccccccccccccccccccccccccccccccc", "name": "Invalid", "type": "trojan", "severity": "unknown",
		}), http.StatusBadRequest)

		badJSON, err := http.NewRequest(http.MethodPost, server.URL+"/info", bytes.NewBufferString(`{"md5":`))
		if err != nil {
			t.Fatalf("new malformed request: %v", err)
		}
		badJSON.Header.Set("Content-Type", "application/json")
		badJSON.Header.Set("X-API-Key", integrationAPIKey)
		response, err := client.Do(badJSON)
		if err != nil {
			t.Fatalf("send malformed request: %v", err)
		}
		assertStatus(t, response, http.StatusBadRequest)
	})

	t.Run("original contract accepts md5 and name only", func(t *testing.T) {
		const originalMD5 = "0123456789abcdef0123456789abcdef"
		create := request(t, client, http.MethodPost, server.URL+"/info", integrationAPIKey, map[string]any{
			"md5": originalMD5, "name": "Trojan.Win32.Generic",
		})
		if create.StatusCode != http.StatusCreated {
			t.Fatalf("create status = %d, body = %s", create.StatusCode, responseBody(t, create))
		}
		var created struct {
			Type     string `json:"type"`
			Severity string `json:"severity"`
		}
		decodeResponse(t, create, &created)
		if created.Type != "other" || created.Severity != "medium" {
			t.Fatalf("defaults = %#v, want other/medium", created)
		}

		update := request(t, client, http.MethodPut, server.URL+"/info/"+originalMD5, integrationAPIKey, map[string]any{"name": "Renamed"})
		if update.StatusCode != http.StatusOK {
			t.Fatalf("update status = %d, body = %s", update.StatusCode, responseBody(t, update))
		}
		update.Body.Close()
	})

	t.Run("input rejected by PostgreSQL is a client error", func(t *testing.T) {
		for name, body := range map[string]map[string]any{
			"NUL in name":        {"md5": "11111111111111111111111111111111", "name": "a\x00b", "type": "trojan", "severity": "high"},
			"NUL in description": {"md5": "11111111111111111111111111111111", "name": "a", "description": "x\x00", "type": "trojan", "severity": "high"},
			"NUL in tag":         {"md5": "11111111111111111111111111111111", "name": "a", "tags": []string{"x\x00"}, "type": "trojan", "severity": "high"},
		} {
			t.Run(name, func(t *testing.T) {
				assertStatus(t, request(t, client, http.MethodPost, server.URL+"/info", integrationAPIKey, body), http.StatusBadRequest)
			})
		}
	})

	t.Run("unserializable seen timestamp is rejected and not persisted", func(t *testing.T) {
		const farMD5 = "22222222222222222222222222222222"
		assertStatus(t, request(t, client, http.MethodPost, server.URL+"/info", integrationAPIKey, map[string]any{
			"md5": farMD5, "name": "a", "first_seen_at": "9999-12-31T23:59:59-23:00", "type": "trojan", "severity": "high",
		}), http.StatusBadRequest)
		assertStatus(t, request(t, client, http.MethodGet, server.URL+"/info/"+farMD5, "", nil), http.StatusNotFound)
	})

	t.Run("errors outside handlers are JSON and timestamps are UTC", func(t *testing.T) {
		notFound := request(t, client, http.MethodGet, server.URL+"/no-such-endpoint", "", nil)
		if ct := notFound.Header.Get("Content-Type"); notFound.StatusCode != http.StatusNotFound || !strings.HasPrefix(ct, "application/json") {
			t.Fatalf("unknown endpoint: status = %d, Content-Type = %q", notFound.StatusCode, ct)
		}
		notFound.Body.Close()

		get := request(t, client, http.MethodGet, server.URL+"/info/"+md5, "", nil)
		var fetched struct {
			CreatedAt string `json:"created_at"`
		}
		decodeResponse(t, get, &fetched)
		if !strings.HasSuffix(fetched.CreatedAt, "Z") {
			t.Fatalf("created_at = %q, want UTC", fetched.CreatedAt)
		}
	})
}

func startPostgresContainer(ctx context.Context, t *testing.T) string {
	t.Helper()
	testcontainers.SkipIfProviderIsNotHealthy(t)
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "postgres:16-alpine",
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_DB":       "threats",
				"POSTGRES_USER":     "threats",
				"POSTGRES_PASSWORD": "threats",
			},
			WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(time.Minute),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start PostgreSQL container: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("get container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatalf("get PostgreSQL port: %v", err)
	}
	return fmt.Sprintf("postgres://threats:threats@%s:%s/threats?sslmode=disable", host, port.Port())
}

func request(t *testing.T, client *http.Client, method, url, apiKey string, body any) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	return response
}

func assertStatus(t *testing.T, response *http.Response, want int) {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode != want {
		t.Fatalf("status = %d, want %d, body = %s", response.StatusCode, want, responseBody(t, response))
	}
}

func decodeResponse(t *testing.T, response *http.Response, destination any) {
	t.Helper()
	defer response.Body.Close()
	if err := json.NewDecoder(response.Body).Decode(destination); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func responseBody(t *testing.T, response *http.Response) string {
	t.Helper()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return string(data)
}
