package httptransport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const requestIDHeader = "X-Request-ID"

// maxTrackedClients bounds limiter memory when many distinct addresses (for example,
// rotated IPv6 addresses) hit the service within one cleanup window.
const maxTrackedClients = 100_000

type contextKey string

const requestIDKey contextKey = "request_id"

func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := sanitizeRequestID(r.Header.Get(requestIDHeader))
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set(requestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

func newRequestID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(bytes)
}

func sanitizeRequestID(value string) string {
	value = strings.TrimSpace(value)
	if len(value) == 0 || len(value) > 128 {
		return ""
	}
	for _, char := range value {
		if char < 33 || char > 126 {
			return ""
		}
	}
	return value
}

func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			startedAt := time.Now()
			response := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(response, r)
			logger.Info("HTTP request completed",
				"method", r.Method,
				"path", r.URL.Path,
				"status", response.status,
				"duration_ms", time.Since(startedAt).Milliseconds(),
				"remote_ip", clientIP(r),
				"request_id", requestIDFromContext(r),
			)
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(payload []byte) (int, error) {
	return w.ResponseWriter.Write(payload)
}

// Unwrap lets http.ResponseController reach optional interfaces such as Flusher.
func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// requestTimeout bounds the request context so slow database calls are cancelled
// instead of holding goroutines and pool connections past the server write timeout.
func requestTimeout(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func requestIDFromContext(r *http.Request) string {
	value, _ := r.Context().Value(requestIDKey).(string)
	return value
}

type clientLimiter struct {
	mu       sync.Mutex
	clients  map[string]*clientLimit
	limit    rate.Limit
	burst    int
	lastGCAt time.Time
}

type clientLimit struct {
	limiter *rate.Limiter
	lastHit time.Time
}

func newClientLimiter(requestsPerMinute, burst int) *clientLimiter {
	return &clientLimiter{
		clients: make(map[string]*clientLimit),
		limit:   rate.Limit(float64(requestsPerMinute) / 60),
		burst:   burst,
	}
}

func (l *clientLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(clientIP(r)) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded", "too many requests from this IP address")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (l *clientLimiter) allow(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	client, exists := l.clients[ip]
	if !exists && len(l.clients) >= maxTrackedClients {
		l.collect(now, time.Minute)
		if len(l.clients) >= maxTrackedClients {
			// Fail closed for new clients rather than growing without bound.
			return false
		}
	}
	if !exists {
		client = &clientLimit{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.clients[ip] = client
	}
	client.lastHit = now
	if now.Sub(l.lastGCAt) >= 10*time.Minute {
		l.collect(now, 30*time.Minute)
		l.lastGCAt = now
	}
	return client.limiter.Allow()
}

// collect removes clients idle for longer than maxIdle. The caller holds l.mu.
func (l *clientLimiter) collect(now time.Time, maxIdle time.Duration) {
	for address, item := range l.clients {
		if now.Sub(item.lastHit) > maxIdle {
			delete(l.clients, address)
		}
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	if r.RemoteAddr == "" {
		return "unknown"
	}
	return r.RemoteAddr
}
