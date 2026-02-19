package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// basicResourceHandler always returns 200 (no rate limiting)
func basicResourceHandler(w http.ResponseWriter, r *http.Request, limiter *RateLimiter) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "ok",
		"endpoint": r.URL.Path,
	})
}

// status429Handler returns 429 after limit exceeded
func status429Handler(w http.ResponseWriter, r *http.Request, limiter *RateLimiter) {
	limit, window := parseLimitParams(r)
	key := "status-429:" + r.URL.Path

	if !limiter.Allow(key, limit, window) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "rate_limit_exceeded",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "ok",
		"endpoint": r.URL.Path,
	})
}

// status503Handler returns 503 after limit exceeded
func status503Handler(w http.ResponseWriter, r *http.Request, limiter *RateLimiter) {
	limit, window := parseLimitParams(r)
	key := "status-503:" + r.URL.Path

	if !limiter.Allow(key, limit, window) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "service_temporarily_unavailable",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "ok",
		"endpoint": r.URL.Path,
	})
}

// retryAfterSecondsHandler returns 429 with Retry-After header (seconds)
func retryAfterSecondsHandler(w http.ResponseWriter, r *http.Request, limiter *RateLimiter) {
	limit, window := parseLimitParams(r)
	key := "retry-seconds:" + r.URL.Path

	if !limiter.Allow(key, limit, window) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "rate_limit_exceeded",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "ok",
		"endpoint": r.URL.Path,
	})
}

// retryAfterDateHandler returns 429 with Retry-After header (HTTP-date)
func retryAfterDateHandler(w http.ResponseWriter, r *http.Request, limiter *RateLimiter) {
	limit, window := parseLimitParams(r)
	key := "retry-date:" + r.URL.Path

	if !limiter.Allow(key, limit, window) {
		retryTime := time.Now().Add(5 * time.Second)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", retryTime.Format(http.TimeFormat))
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "rate_limit_exceeded",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "ok",
		"endpoint": r.URL.Path,
	})
}

// rateLimitHeadersHandler returns 429 with X-RateLimit-* headers
func rateLimitHeadersHandler(w http.ResponseWriter, r *http.Request, limiter *RateLimiter) {
	limit, window := parseLimitParams(r)
	key := "ratelimit-headers:" + r.URL.Path

	allowed := limiter.Allow(key, limit, window)
	remaining := limiter.Remaining(key)
	resetTime := limiter.ResetTime(key)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))

	if !allowed {
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "rate_limit_exceeded",
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"status":   "ok",
		"endpoint": r.URL.Path,
	})
}

// bodyPlainHandler returns plain text error
func bodyPlainHandler(w http.ResponseWriter, r *http.Request, limiter *RateLimiter) {
	limit, window := parseLimitParams(r)
	key := "body-plain:" + r.URL.Path

	if !limiter.Allow(key, limit, window) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("Too Many Requests"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "ok",
		"endpoint": r.URL.Path,
	})
}

// bodyJSONHandler returns JSON error body
func bodyJSONHandler(w http.ResponseWriter, r *http.Request, limiter *RateLimiter) {
	limit, window := parseLimitParams(r)
	key := "body-json:" + r.URL.Path

	if !limiter.Allow(key, limit, window) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "rate_limit_exceeded",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "ok",
		"endpoint": r.URL.Path,
	})
}

// bodyJSONRetryHandler returns JSON error with retry_after field
func bodyJSONRetryHandler(w http.ResponseWriter, r *http.Request, limiter *RateLimiter) {
	limit, window := parseLimitParams(r)
	key := "body-json-retry:" + r.URL.Path

	if !limiter.Allow(key, limit, window) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":       "rate_limit_exceeded",
			"retry_after": 5,
			"message":     "Try again in 5 seconds",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "ok",
		"endpoint": r.URL.Path,
	})
}

// globalHandler uses shared counter across all /global/* endpoints
func globalHandler(w http.ResponseWriter, r *http.Request, limiter *RateLimiter) {
	limit, window := parseLimitParams(r)
	key := "global-shared" // Same key for all global endpoints

	if !limiter.Allow(key, limit, window) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "rate_limit_exceeded",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "ok",
		"endpoint": r.URL.Path,
	})
}

// perEndpointHandler uses independent counters per endpoint
func perEndpointHandler(w http.ResponseWriter, r *http.Request, limiter *RateLimiter) {
	limit, window := parseLimitParams(r)
	key := "per-endpoint:" + r.URL.Path // Unique key per endpoint

	if !limiter.Allow(key, limit, window) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "rate_limit_exceeded",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "ok",
		"endpoint": r.URL.Path,
	})
}

// perIPHandler rate limits per client IP
func perIPHandler(w http.ResponseWriter, r *http.Request, limiter *RateLimiter) {
	limit, window := parseLimitParams(r)
	clientIP := getClientIP(r)
	key := "per-ip:" + clientIP

	if !limiter.Allow(key, limit, window) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "rate_limit_exceeded",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "ok",
		"endpoint":  r.URL.Path,
		"client_ip": clientIP,
	})
}

// parseLimitParams extracts limit and window from query parameters
func parseLimitParams(r *http.Request) (int, time.Duration) {
	limit := 5                 // default
	window := 60 * time.Second // default

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	if windowStr := r.URL.Query().Get("window"); windowStr != "" {
		if w, err := strconv.Atoi(windowStr); err == nil && w > 0 {
			window = time.Duration(w) * time.Second
		}
	}

	return limit, window
}

// getClientIP extracts client IP from request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// registerHandlers sets up all HTTP routes
func registerHandlers(mux *http.ServeMux, limiter *RateLimiter) {
	// No rate limit endpoints
	mux.HandleFunc("/api/v1/basic/resource", func(w http.ResponseWriter, r *http.Request) {
		basicResourceHandler(w, r, limiter)
	})

	// Status code endpoints
	mux.HandleFunc("/api/v1/status-429/resource", func(w http.ResponseWriter, r *http.Request) {
		status429Handler(w, r, limiter)
	})
	mux.HandleFunc("/api/v1/status-503/resource", func(w http.ResponseWriter, r *http.Request) {
		status503Handler(w, r, limiter)
	})

	// Retry-After endpoints
	mux.HandleFunc("/api/v1/retry-seconds/resource", func(w http.ResponseWriter, r *http.Request) {
		retryAfterSecondsHandler(w, r, limiter)
	})
	mux.HandleFunc("/api/v1/retry-date/resource", func(w http.ResponseWriter, r *http.Request) {
		retryAfterDateHandler(w, r, limiter)
	})

	// X-RateLimit headers endpoint
	mux.HandleFunc("/api/v1/ratelimit-headers/resource", func(w http.ResponseWriter, r *http.Request) {
		rateLimitHeadersHandler(w, r, limiter)
	})

	// Body format endpoints
	mux.HandleFunc("/api/v1/body-plain/resource", func(w http.ResponseWriter, r *http.Request) {
		bodyPlainHandler(w, r, limiter)
	})
	mux.HandleFunc("/api/v1/body-json/resource", func(w http.ResponseWriter, r *http.Request) {
		bodyJSONHandler(w, r, limiter)
	})
	mux.HandleFunc("/api/v1/body-json-retry/resource", func(w http.ResponseWriter, r *http.Request) {
		bodyJSONRetryHandler(w, r, limiter)
	})

	// Scoping endpoints
	mux.HandleFunc("/api/v1/global/", func(w http.ResponseWriter, r *http.Request) {
		globalHandler(w, r, limiter)
	})
	mux.HandleFunc("/api/v1/per-endpoint/", func(w http.ResponseWriter, r *http.Request) {
		perEndpointHandler(w, r, limiter)
	})
	mux.HandleFunc("/api/v1/per-ip/resource", func(w http.ResponseWriter, r *http.Request) {
		perIPHandler(w, r, limiter)
	})
}

// loggingMiddleware logs all HTTP requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		fmt.Printf("[%s] %s %s", start.Format("15:04:05"), r.Method, r.URL.Path)

		// Wrap ResponseWriter to capture status code
		wrapped := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(wrapped, r)

		fmt.Printf(" -> %d (%v)\n", wrapped.status, time.Since(start))
	})
}

// statusWriter wraps http.ResponseWriter to capture status code
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(status int) {
	sw.status = status
	sw.ResponseWriter.WriteHeader(status)
}
