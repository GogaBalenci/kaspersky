package httptransport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/balenci/kaspersky/internal/domain"
	"github.com/balenci/kaspersky/internal/service"
)

type fakeThreatService struct {
	create func(context.Context, service.CreateThreatInput) (domain.Threat, error)
	get    func(context.Context, string) (domain.Threat, error)
	update func(context.Context, string, service.UpdateThreatInput) (domain.Threat, error)
}

func (s fakeThreatService) Create(ctx context.Context, input service.CreateThreatInput) (domain.Threat, error) {
	return s.create(ctx, input)
}

func (s fakeThreatService) GetByMD5(ctx context.Context, md5 string) (domain.Threat, error) {
	return s.get(ctx, md5)
}

func (s fakeThreatService) Update(ctx context.Context, md5 string, input service.UpdateThreatInput) (domain.Threat, error) {
	return s.update(ctx, md5, input)
}

func TestCreateThreatRejectsUnknownJSONField(t *testing.T) {
	server := newTestServer(t, fakeThreatService{})
	request := httptest.NewRequest(http.MethodPost, "/info", strings.NewReader(`{"md5":"d41d8cd98f00b204e9800998ecf8427e","name":"Example","type":"trojan","severity":"high","unexpected":true}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	server.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	assertErrorResponse(t, response, "invalid request")
}

func TestCreateThreatReturnsCreatedResponse(t *testing.T) {
	var gotInput service.CreateThreatInput
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	server := newTestServer(t, fakeThreatService{
		create: func(_ context.Context, input service.CreateThreatInput) (domain.Threat, error) {
			gotInput = input
			return domain.Threat{MD5: strings.ToLower(input.MD5), Name: input.Name, Type: input.Type, Severity: input.Severity, Tags: input.Tags, CreatedAt: now, UpdatedAt: now}, nil
		},
	})
	request := httptest.NewRequest(http.MethodPost, "/info", strings.NewReader(`{"md5":"D41D8CD98F00B204E9800998ECF8427E","name":"Example","type":"trojan","severity":"high"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	server.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusCreated)
	}
	if gotInput.MD5 != "D41D8CD98F00B204E9800998ECF8427E" {
		t.Fatalf("input md5 = %q", gotInput.MD5)
	}
	var body struct {
		MD5 string `json:"md5"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.MD5 != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Fatalf("response md5 = %q", body.MD5)
	}
}

func TestGetThreatMapsDomainErrors(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		status  int
		message string
	}{
		{name: "not found", err: domain.ErrThreatNotFound, status: http.StatusNotFound, message: "threat not found"},
		{name: "internal", err: errors.New("database unavailable"), status: http.StatusInternalServerError, message: "internal server error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newTestServer(t, fakeThreatService{get: func(context.Context, string) (domain.Threat, error) {
				return domain.Threat{}, test.err
			}})
			response := httptest.NewRecorder()
			server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/info/d41d8cd98f00b204e9800998ecf8427e", nil))
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
			assertErrorResponse(t, response, test.message)
		})
	}
}

func TestCreateThreatMapsDuplicateToConflict(t *testing.T) {
	server := newTestServer(t, fakeThreatService{create: func(context.Context, service.CreateThreatInput) (domain.Threat, error) {
		return domain.Threat{}, domain.ErrThreatExists
	}})
	request := httptest.NewRequest(http.MethodPost, "/info", strings.NewReader(`{"md5":"d41d8cd98f00b204e9800998ecf8427e","name":"Example","type":"trojan","severity":"high"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	server.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusConflict)
	}
	assertErrorResponse(t, response, "threat already exists")
}

func TestUpdateThreatReturnsUpdatedResponse(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	server := newTestServer(t, fakeThreatService{update: func(_ context.Context, md5 string, input service.UpdateThreatInput) (domain.Threat, error) {
		return domain.Threat{MD5: md5, Name: input.Name, Type: input.Type, Severity: input.Severity, Tags: input.Tags, CreatedAt: now, UpdatedAt: now}, nil
	}})
	request := httptest.NewRequest(http.MethodPut, "/info/d41d8cd98f00b204e9800998ecf8427e", strings.NewReader(`{"name":"Updated","type":"ransomware","severity":"critical"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Name != "Updated" {
		t.Fatalf("name = %q, want Updated", body.Name)
	}
}

func TestCreateThreatRejectsMalformedJSON(t *testing.T) {
	server := newTestServer(t, fakeThreatService{})
	request := httptest.NewRequest(http.MethodPost, "/info", strings.NewReader(`{"md5":`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	server.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	assertErrorResponse(t, response, "invalid request")
}

func TestCreateThreatRejectsLargeBody(t *testing.T) {
	server := NewRouter(NewHandlerWithMaxBodyBytes(fakeThreatService{}, 20))
	request := httptest.NewRequest(http.MethodPost, "/info", strings.NewReader(`{"md5":"d41d8cd98f00b204e9800998ecf8427e"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	server.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	assertErrorResponse(t, response, "invalid request")
}

func TestCreateThreatRequiresAPIKeyWhenConfigured(t *testing.T) {
	server := NewRouter(NewHandlerWithOptions(fakeThreatService{}, HandlerOptions{APIKey: "test-secret"}))
	request := httptest.NewRequest(http.MethodPost, "/info", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	server.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	assertErrorResponse(t, response, "unauthorized")
}

func TestHealthCheck(t *testing.T) {
	t.Run("database available", func(t *testing.T) {
		server := NewRouter(NewHandlerWithOptions(fakeThreatService{}, HandlerOptions{HealthChecker: fakeHealthChecker{}}))
		response := httptest.NewRecorder()
		server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
		}
	})
	t.Run("database unavailable", func(t *testing.T) {
		server := NewRouter(NewHandlerWithOptions(fakeThreatService{}, HandlerOptions{HealthChecker: fakeHealthChecker{err: errors.New("down")}}))
		response := httptest.NewRecorder()
		server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
		}
		assertErrorResponse(t, response, "service unavailable")
	})
}

func TestRateLimitAndRequestID(t *testing.T) {
	server := NewRouter(NewHandler(fakeThreatService{}), RouterOptions{RequestsPerMinute: 1, RateLimitBurst: 1})
	first := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	first.RemoteAddr = "192.0.2.1:1234"
	firstResponse := httptest.NewRecorder()
	server.ServeHTTP(firstResponse, first)
	if firstResponse.Header().Get(requestIDHeader) == "" {
		t.Fatal("response does not contain a request ID")
	}

	second := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	second.RemoteAddr = "192.0.2.1:1234"
	secondResponse := httptest.NewRecorder()
	server.ServeHTTP(secondResponse, second)
	if secondResponse.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", secondResponse.Code, http.StatusTooManyRequests)
	}
}

type fakeHealthChecker struct{ err error }

func (checker fakeHealthChecker) Ping(context.Context) error { return checker.err }

func newTestServer(t *testing.T, service fakeThreatService) http.Handler {
	t.Helper()
	return NewRouter(NewHandler(service))
}

func assertErrorResponse(t *testing.T, response *httptest.ResponseRecorder, message string) {
	t.Helper()
	var body struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if body.Message != message {
		t.Fatalf("message = %q, want %q", body.Message, message)
	}
}

func TestOptionalClassificationFieldsUseDefaultsOnlyWhenAbsent(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	var created service.CreateThreatInput
	var updated service.UpdateThreatInput
	server := newTestServer(t, fakeThreatService{
		create: func(_ context.Context, input service.CreateThreatInput) (domain.Threat, error) {
			created = input
			return domain.Threat{MD5: input.MD5, Name: input.Name, Type: input.Type, Severity: input.Severity, CreatedAt: now, UpdatedAt: now}, nil
		},
		update: func(_ context.Context, md5 string, input service.UpdateThreatInput) (domain.Threat, error) {
			updated = input
			return domain.Threat{MD5: md5, Name: input.Name, Type: input.Type, Severity: input.Severity, CreatedAt: now, UpdatedAt: now}, nil
		},
	})

	send := func(method, target, body string) int {
		request := httptest.NewRequest(method, target, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		return response.Code
	}

	if code := send(http.MethodPost, "/info", `{"md5":"d41d8cd98f00b204e9800998ecf8427e","name":"Example"}`); code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d", code, http.StatusCreated)
	}
	if created.Type != domain.DefaultThreatType || created.Severity != domain.DefaultSeverity {
		t.Fatalf("create defaults = %q/%q", created.Type, created.Severity)
	}
	if code := send(http.MethodPut, "/info/d41d8cd98f00b204e9800998ecf8427e", `{"name":"Example"}`); code != http.StatusOK {
		t.Fatalf("update status = %d, want %d", code, http.StatusOK)
	}
	if updated.Type != domain.DefaultThreatType || updated.Severity != domain.DefaultSeverity {
		t.Fatalf("update defaults = %q/%q", updated.Type, updated.Severity)
	}

	send(http.MethodPost, "/info", `{"md5":"d41d8cd98f00b204e9800998ecf8427e","name":"Example","type":"","severity":""}`)
	if created.Type != "" || created.Severity != "" {
		t.Fatalf("explicit empty values were replaced by defaults: %q/%q", created.Type, created.Severity)
	}
}

func TestUnexpectedErrorsAreLoggedButHiddenFromClients(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	server := NewRouter(NewHandlerWithOptions(fakeThreatService{get: func(context.Context, string) (domain.Threat, error) {
		return domain.Threat{}, errors.New("connection refused to 10.0.0.5")
	}}, HandlerOptions{Logger: logger}))

	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/info/d41d8cd98f00b204e9800998ecf8427e", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusInternalServerError)
	}
	if strings.Contains(response.Body.String(), "10.0.0.5") {
		t.Fatal("internal error details leaked to the client")
	}
	if !strings.Contains(logs.String(), "connection refused to 10.0.0.5") || !strings.Contains(logs.String(), "request_id") {
		t.Fatalf("root cause was not logged with a request ID: %s", logs.String())
	}
}

func TestUnencodableResponseBecomesInternalError(t *testing.T) {
	var logs bytes.Buffer
	outOfRange := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	server := NewRouter(NewHandlerWithOptions(fakeThreatService{get: func(_ context.Context, md5 string) (domain.Threat, error) {
		return domain.Threat{MD5: md5, Name: "Example", Type: domain.ThreatTypeOther, Severity: domain.SeverityLow, FirstSeenAt: &outOfRange}, nil
	}}, HandlerOptions{Logger: slog.New(slog.NewJSONHandler(&logs, nil))}))

	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/info/d41d8cd98f00b204e9800998ecf8427e", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusInternalServerError)
	}
	assertErrorResponse(t, response, "internal server error")
	if !strings.Contains(logs.String(), "encode response") {
		t.Fatalf("encoding failure was not logged: %s", logs.String())
	}
}

func TestRoutingAndBindingErrorsUseErrorResponse(t *testing.T) {
	server := newTestServer(t, fakeThreatService{})
	tests := []struct {
		method, target string
		status         int
		message        string
	}{
		{http.MethodGet, "/unknown", http.StatusNotFound, "not found"},
		{http.MethodDelete, "/info/d41d8cd98f00b204e9800998ecf8427e", http.StatusMethodNotAllowed, "method not allowed"},
		{http.MethodGet, "/info/%25zz", http.StatusBadRequest, "invalid request"},
	}
	for _, test := range tests {
		t.Run(test.method+" "+test.target, func(t *testing.T) {
			response := httptest.NewRecorder()
			server.ServeHTTP(response, httptest.NewRequest(test.method, test.target, nil))
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
			if !strings.HasPrefix(response.Header().Get("Content-Type"), "application/json") {
				t.Fatalf("Content-Type = %q, want JSON", response.Header().Get("Content-Type"))
			}
			assertErrorResponse(t, response, test.message)
		})
	}
}

func TestReadAuthorizationIsOptional(t *testing.T) {
	get := func(context.Context, string) (domain.Threat, error) {
		return domain.Threat{MD5: "d41d8cd98f00b204e9800998ecf8427e"}, nil
	}
	for _, required := range []bool{false, true} {
		server := NewRouter(NewHandlerWithOptions(fakeThreatService{get: get}, HandlerOptions{APIKey: "secret", RequireAPIKeyForReads: required}))
		response := httptest.NewRecorder()
		server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/info/d41d8cd98f00b204e9800998ecf8427e", nil))
		want := http.StatusOK
		if required {
			want = http.StatusUnauthorized
		}
		if response.Code != want {
			t.Fatalf("RequireAPIKeyForReads=%v: status = %d, want %d", required, response.Code, want)
		}
	}
}

func TestCreateThreatRejectsInvalidUTF8(t *testing.T) {
	called := false
	server := newTestServer(t, fakeThreatService{create: func(context.Context, service.CreateThreatInput) (domain.Threat, error) {
		called = true
		return domain.Threat{}, nil
	}})
	request := httptest.NewRequest(http.MethodPost, "/info", strings.NewReader("{\"md5\":\"d41d8cd98f00b204e9800998ecf8427e\",\"name\":\"\xff\"}"))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || called {
		t.Fatalf("status = %d, service called = %v; want 400 without a service call", response.Code, called)
	}
}

func TestResponseTimestampsAreUTC(t *testing.T) {
	moscow := time.FixedZone("MSK", 3*3600)
	seen := time.Date(2026, 11, 1, 15, 0, 0, 0, moscow)
	server := newTestServer(t, fakeThreatService{get: func(_ context.Context, md5 string) (domain.Threat, error) {
		return domain.Threat{MD5: md5, Name: "n", Type: domain.ThreatTypeOther, Severity: domain.SeverityLow, FirstSeenAt: &seen, CreatedAt: seen, UpdatedAt: seen}, nil
	}})
	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/info/d41d8cd98f00b204e9800998ecf8427e", nil))
	body := response.Body.String()
	if !strings.Contains(body, `"created_at":"2026-11-01T12:00:00Z"`) || !strings.Contains(body, `"first_seen_at":"2026-11-01T12:00:00Z"`) {
		t.Fatalf("timestamps are not UTC: %s", body)
	}
}

func TestStorageConstraintViolationIsClientError(t *testing.T) {
	server := newTestServer(t, fakeThreatService{get: func(context.Context, string) (domain.Threat, error) {
		return domain.Threat{}, fmt.Errorf("%w: threats_name_not_blank", domain.ErrInvalidThreat)
	}})
	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/info/d41d8cd98f00b204e9800998ecf8427e", nil))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestRequestContextHasDeadline(t *testing.T) {
	var deadline time.Time
	var ok bool
	server := NewRouter(NewHandler(fakeThreatService{get: func(ctx context.Context, md5 string) (domain.Threat, error) {
		deadline, ok = ctx.Deadline()
		return domain.Threat{MD5: md5}, nil
	}}), RouterOptions{RequestTimeout: 2 * time.Second})
	started := time.Now()
	server.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/info/d41d8cd98f00b204e9800998ecf8427e", nil))
	if !ok || deadline.Sub(started) > 2*time.Second+time.Second {
		t.Fatalf("handler context deadline = %v (set: %v), want about 2s", deadline, ok)
	}
}

func TestClientLimiterBoundsTrackedClients(t *testing.T) {
	limiter := newClientLimiter(60, 1)
	for i := 0; i < maxTrackedClients; i++ {
		limiter.clients[fmt.Sprintf("client-%d", i)] = &clientLimit{limiter: nil, lastHit: time.Now()}
	}
	if limiter.allow("new-client") {
		t.Fatal("allow() admitted a new client while the table was full of active clients")
	}
	if len(limiter.clients) > maxTrackedClients {
		t.Fatalf("tracked clients = %d, want <= %d", len(limiter.clients), maxTrackedClients)
	}
	for _, client := range limiter.clients {
		client.lastHit = time.Now().Add(-2 * time.Minute)
	}
	if !limiter.allow("new-client") {
		t.Fatal("allow() rejected a new client after idle entries could be collected")
	}
}
