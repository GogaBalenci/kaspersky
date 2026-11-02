// Package httptransport exposes the generated OpenAPI server interface over net/http.
package httptransport

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/balenci/kaspersky/api/generated"
	"github.com/balenci/kaspersky/internal/domain"
	"github.com/balenci/kaspersky/internal/service"
)

const defaultMaxRequestBodyBytes int64 = 1 << 20 // 1 MiB

type ThreatOperations interface {
	Create(ctx context.Context, input service.CreateThreatInput) (domain.Threat, error)
	GetByMD5(ctx context.Context, md5 string) (domain.Threat, error)
	Update(ctx context.Context, md5 string, input service.UpdateThreatInput) (domain.Threat, error)
}

type HealthChecker interface {
	Ping(ctx context.Context) error
}

type HandlerOptions struct {
	APIKey string
	// RequireAPIKeyForReads also protects GET /info/{md5}; writes are always protected
	// when APIKey is set.
	RequireAPIKeyForReads bool
	HealthChecker         HealthChecker
	// Logger records unexpected errors that are hidden from clients behind a generic 500.
	// When nil, slog.Default() is used.
	Logger *slog.Logger
}

// Handler implements the interface generated from api/openapi.yaml.
type Handler struct {
	generated.Unimplemented
	threats      ThreatOperations
	maxBodyBytes int64
	apiKey       string
	readAuth     bool
	health       HealthChecker
	logger       *slog.Logger
}

var _ generated.ServerInterface = (*Handler)(nil)

func NewHandler(threats ThreatOperations) *Handler {
	return NewHandlerWithOptions(threats, HandlerOptions{})
}

func NewHandlerWithMaxBodyBytes(threats ThreatOperations, maxBodyBytes int64) *Handler {
	return newHandler(threats, maxBodyBytes, HandlerOptions{})
}

func NewHandlerWithOptions(threats ThreatOperations, options HandlerOptions) *Handler {
	return newHandler(threats, defaultMaxRequestBodyBytes, options)
}

func newHandler(threats ThreatOperations, maxBodyBytes int64, options HandlerOptions) *Handler {
	if maxBodyBytes <= 0 {
		maxBodyBytes = defaultMaxRequestBodyBytes
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{threats: threats, maxBodyBytes: maxBodyBytes, apiKey: options.APIKey, readAuth: options.RequireAPIKeyForReads, health: options.HealthChecker, logger: logger}
}

func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	if h.health == nil || h.health.Ping(r.Context()) != nil {
		writeError(w, http.StatusServiceUnavailable, "service unavailable", "database is unavailable")
		return
	}
	h.writeJSON(w, r, http.StatusOK, generated.HealthResponse{Status: generated.Ok})
}

func (h *Handler) CreateThreat(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(w, r) {
		return
	}
	var request generated.ThreatCreateRequest
	if err := decodeJSON(w, r, h.maxBodyBytes, &request); err != nil {
		writeRequestError(w, err)
		return
	}

	threat, err := h.threats.Create(r.Context(), service.CreateThreatInput{
		MD5: request.Md5, Name: request.Name, Type: threatTypeOrDefault(request.Type),
		Severity: severityOrDefault(request.Severity), Description: request.Description,
		Tags: optionalTags(request.Tags), FirstSeenAt: request.FirstSeenAt, LastSeenAt: request.LastSeenAt,
	})
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, r, http.StatusCreated, responseFromThreat(threat))
}

func (h *Handler) GetThreatByMD5(w http.ResponseWriter, r *http.Request, md5 generated.Md5) {
	if h.readAuth && !h.authorized(w, r) {
		return
	}
	threat, err := h.threats.GetByMD5(r.Context(), md5)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, r, http.StatusOK, responseFromThreat(threat))
}

func (h *Handler) UpdateThreat(w http.ResponseWriter, r *http.Request, md5 generated.Md5) {
	if !h.authorized(w, r) {
		return
	}
	var request generated.ThreatUpdateRequest
	if err := decodeJSON(w, r, h.maxBodyBytes, &request); err != nil {
		writeRequestError(w, err)
		return
	}

	threat, err := h.threats.Update(r.Context(), md5, service.UpdateThreatInput{
		Name: request.Name, Type: threatTypeOrDefault(request.Type), Severity: severityOrDefault(request.Severity),
		Description: request.Description, Tags: optionalTags(request.Tags),
		FirstSeenAt: request.FirstSeenAt, LastSeenAt: request.LastSeenAt,
	})
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, r, http.StatusOK, responseFromThreat(threat))
}

func (h *Handler) authorized(w http.ResponseWriter, r *http.Request) bool {
	// An empty key is useful for isolated handler tests; application configuration
	// always requires API_KEY before constructing a production handler.
	if h.apiKey == "" {
		return true
	}
	providedKey := r.Header.Get("X-API-Key")
	if providedKey == "" || subtle.ConstantTimeCompare([]byte(providedKey), []byte(h.apiKey)) != 1 {
		writeError(w, http.StatusUnauthorized, "unauthorized", "a valid X-API-Key header is required")
		return false
	}
	return true
}

// threatTypeOrDefault applies the documented default only when the field is absent;
// an explicitly empty or unknown value is still rejected by service validation.
func threatTypeOrDefault(value *generated.ThreatType) domain.ThreatType {
	if value == nil {
		return domain.DefaultThreatType
	}
	return domain.ThreatType(*value)
}

func severityOrDefault(value *generated.Severity) domain.Severity {
	if value == nil {
		return domain.DefaultSeverity
	}
	return domain.Severity(*value)
}

func optionalTags(tags *[]string) []string {
	if tags == nil {
		return nil
	}
	return *tags
}

func responseFromThreat(threat domain.Threat) generated.ThreatResponse {
	return generated.ThreatResponse{
		Md5: threat.MD5, Name: threat.Name, Type: generated.ThreatType(threat.Type),
		Severity: generated.Severity(threat.Severity), Description: threat.Description, Tags: threat.Tags,
		FirstSeenAt: utcPointer(threat.FirstSeenAt), LastSeenAt: utcPointer(threat.LastSeenAt),
		CreatedAt: threat.CreatedAt.UTC(), UpdatedAt: threat.UpdatedAt.UTC(),
	}
}

// utcPointer returns timestamps in UTC so responses do not depend on the server time zone.
func utcPointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	utc := value.UTC()
	return &utc
}

func decodeJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, destination any) error {
	contentType := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" {
		return fmt.Errorf("Content-Type must be application/json")
	}

	// The body is read fully (bounded by MaxBytesReader) because encoding/json silently
	// replaces invalid UTF-8 with U+FFFD; such input is rejected instead of being altered.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
	if err != nil {
		return err
	}
	if !utf8.Valid(body) {
		return fmt.Errorf("request body must be valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("request body must contain a single JSON object")
		}
		return err
	}
	return nil
}

func writeRequestError(w http.ResponseWriter, err error) {
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		writeError(w, http.StatusBadRequest, "invalid request", "request body exceeds the allowed size")
		return
	}
	writeError(w, http.StatusBadRequest, "invalid request", err.Error())
}

func (h *Handler) writeServiceError(w http.ResponseWriter, r *http.Request, err error) {
	var validationError *service.ValidationError
	switch {
	case errors.As(err, &validationError):
		writeError(w, http.StatusBadRequest, "invalid request", validationError.Error())
	case errors.Is(err, domain.ErrThreatNotFound):
		writeError(w, http.StatusNotFound, "threat not found", "no threat exists for the requested MD5")
	case errors.Is(err, domain.ErrInvalidThreat):
		writeError(w, http.StatusBadRequest, "invalid request", "threat data violates storage constraints")
	case errors.Is(err, domain.ErrThreatExists):
		writeError(w, http.StatusConflict, "threat already exists", "a threat with this MD5 already exists")
	default:
		h.logger.ErrorContext(r.Context(), "unexpected service error",
			"error", err, "method", r.Method, "path", r.URL.Path, "request_id", requestIDFromContext(r))
		writeError(w, http.StatusInternalServerError, "internal server error", "an unexpected error occurred")
	}
}

func writeError(w http.ResponseWriter, status int, message, details string) {
	writeJSON(w, status, generated.ErrorResponse{Message: message, Details: &details})
}

// writeJSON encodes the payload before committing the status line so that an
// encoding failure becomes a logged 500 instead of a success status with an empty body.
func (h *Handler) writeJSON(w http.ResponseWriter, r *http.Request, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "encode response",
			"error", err, "method", r.Method, "path", r.URL.Path, "request_id", requestIDFromContext(r))
		writeError(w, http.StatusInternalServerError, "internal server error", "an unexpected error occurred")
		return
	}
	writeRawJSON(w, status, append(body, '\n'))
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		// Only static error payloads go through this helper; they always encode.
		body = []byte(`{"message":"internal server error"}`)
		status = http.StatusInternalServerError
	}
	writeRawJSON(w, status, append(body, '\n'))
}

func writeRawJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
