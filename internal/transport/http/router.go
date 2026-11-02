package httptransport

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/balenci/kaspersky/api/generated"
	"github.com/go-chi/chi/v5"
)

type RouterOptions struct {
	Logger            *slog.Logger
	RequestsPerMinute int
	RateLimitBurst    int
	// RequestTimeout bounds the context passed to handlers (and therefore database
	// calls). Zero means defaultRequestTimeout.
	RequestTimeout time.Duration
}

const (
	defaultRequestsPerMinute = 60
	defaultRateLimitBurst    = 10
	defaultRequestTimeout    = 5 * time.Second
)

// NewRouter binds the generated OpenAPI routes to the concrete handler.
func NewRouter(handler *Handler, options ...RouterOptions) http.Handler {
	var settings RouterOptions
	if len(options) > 0 {
		settings = options[0]
	}
	// Omitted and non-positive values get the same production defaults as config.Load.
	if settings.Logger == nil {
		settings.Logger = slog.Default()
	}
	if settings.RequestsPerMinute <= 0 {
		settings.RequestsPerMinute = defaultRequestsPerMinute
	}
	if settings.RateLimitBurst <= 0 {
		settings.RateLimitBurst = defaultRateLimitBurst
	}
	if settings.RequestTimeout <= 0 {
		settings.RequestTimeout = defaultRequestTimeout
	}
	router := chi.NewRouter()
	router.Use(requestID)
	router.Use(requestLogger(settings.Logger))
	router.Use(newClientLimiter(settings.RequestsPerMinute, settings.RateLimitBurst).middleware)
	router.Use(requestTimeout(settings.RequestTimeout))
	router.NotFound(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not found", "the requested endpoint does not exist")
	})
	router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", r.Method+" is not supported for this endpoint")
	})
	return generated.HandlerWithOptions(handler, generated.ChiServerOptions{
		BaseRouter: router,
		// Parameter binding errors use the same ErrorResponse body as every other error.
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeError(w, http.StatusBadRequest, "invalid request", err.Error())
		},
	})
}
