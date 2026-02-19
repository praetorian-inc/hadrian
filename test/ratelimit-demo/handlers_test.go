package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestBasicResourceHandler_NoRateLimit verifies baseline endpoint never rate limits
func TestBasicResourceHandler_NoRateLimit(t *testing.T) {
	limiter := NewRateLimiter()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		basicResourceHandler(w, r, limiter)
	})

	// Make 10 requests - all should succeed
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/api/v1/basic/resource", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}
}

// TestStatus429Handler_ReturnsRateLimitAfterN verifies 429 after limit exceeded
func TestStatus429Handler_ReturnsRateLimitAfterN(t *testing.T) {
	limiter := NewRateLimiter()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status429Handler(w, r, limiter)
	})

	// First 5 should succeed (default limit)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/api/v1/status-429/resource", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	// 6th should return 429
	req := httptest.NewRequest("GET", "/api/v1/status-429/resource", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
}

// TestStatus429Handler_CustomLimit verifies custom limit via query param
func TestStatus429Handler_CustomLimit(t *testing.T) {
	limiter := NewRateLimiter()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status429Handler(w, r, limiter)
	})

	// First 3 should succeed (custom limit=3)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/api/v1/status-429/resource?limit=3", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	// 4th should return 429
	req := httptest.NewRequest("GET", "/api/v1/status-429/resource?limit=3", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
}

// TestRetryAfterSecondsHandler_IncludesHeader verifies Retry-After header
func TestRetryAfterSecondsHandler_IncludesHeader(t *testing.T) {
	limiter := NewRateLimiter()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		retryAfterSecondsHandler(w, r, limiter)
	})

	// Exhaust limit
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/api/v1/retry-seconds/resource", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}

	// Rate limited request
	req := httptest.NewRequest("GET", "/api/v1/retry-seconds/resource", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}

	retryAfter := w.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("expected Retry-After header")
	}
	if retryAfter != "5" {
		t.Errorf("expected Retry-After=5, got %s", retryAfter)
	}
}

// TestRateLimitHeadersHandler_IncludesXRateLimitHeaders verifies X-RateLimit-* headers
func TestRateLimitHeadersHandler_IncludesXRateLimitHeaders(t *testing.T) {
	limiter := NewRateLimiter()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rateLimitHeadersHandler(w, r, limiter)
	})

	// Exhaust limit
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/api/v1/ratelimit-headers/resource", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}

	// Rate limited request
	req := httptest.NewRequest("GET", "/api/v1/ratelimit-headers/resource", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}

	limit := w.Header().Get("X-RateLimit-Limit")
	if limit != "5" {
		t.Errorf("expected X-RateLimit-Limit=5, got %s", limit)
	}

	remaining := w.Header().Get("X-RateLimit-Remaining")
	if remaining != "0" {
		t.Errorf("expected X-RateLimit-Remaining=0, got %s", remaining)
	}

	reset := w.Header().Get("X-RateLimit-Reset")
	if reset == "" {
		t.Error("expected X-RateLimit-Reset header")
	}
}

// TestBodyJSONHandler_ReturnsJSONError verifies JSON error response
func TestBodyJSONHandler_ReturnsJSONError(t *testing.T) {
	limiter := NewRateLimiter()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyJSONHandler(w, r, limiter)
	})

	// Exhaust limit
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/api/v1/body-json/resource", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}

	// Rate limited request
	req := httptest.NewRequest("GET", "/api/v1/body-json/resource", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %s", contentType)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if response["error"] != "rate_limit_exceeded" {
		t.Errorf("expected error=rate_limit_exceeded, got %v", response["error"])
	}
}

// TestPerIPHandler_IndependentPerIP verifies per-IP rate limiting
func TestPerIPHandler_IndependentPerIP(t *testing.T) {
	limiter := NewRateLimiter()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		perIPHandler(w, r, limiter)
	})

	// Exhaust limit for IP1
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/api/v1/per-ip/resource", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}

	// IP1 should be rate limited
	req1 := httptest.NewRequest("GET", "/api/v1/per-ip/resource", nil)
	req1.RemoteAddr = "192.168.1.1:1234"
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusTooManyRequests {
		t.Errorf("IP1: expected 429, got %d", w1.Code)
	}

	// IP2 should still be allowed
	req2 := httptest.NewRequest("GET", "/api/v1/per-ip/resource", nil)
	req2.RemoteAddr = "192.168.1.2:5678"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("IP2: expected 200, got %d", w2.Code)
	}
}

// TestGlobalHandler_SharedCounter verifies global shared counter
func TestGlobalHandler_SharedCounter(t *testing.T) {
	limiter := NewRateLimiter()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		globalHandler(w, r, limiter)
	})

	// Make 3 requests to /global/resource
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/api/v1/global/resource?limit=5", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}

	// Make 2 requests to /global/other (same counter)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/api/v1/global/other?limit=5", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}

	// 6th request should be rate limited (shared counter exhausted)
	req := httptest.NewRequest("GET", "/api/v1/global/resource?limit=5", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 (shared counter), got %d", w.Code)
	}
}

// TestWindowExpiration verifies counter resets after window
func TestWindowExpiration(t *testing.T) {
	limiter := NewRateLimiter()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status429Handler(w, r, limiter)
	})

	// Exhaust limit with 1-second window
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/api/v1/status-429/resource?limit=5&window=1", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}

	// Wait for window to expire
	time.Sleep(1100 * time.Millisecond)

	// Next request should succeed
	req := httptest.NewRequest("GET", "/api/v1/status-429/resource?limit=5&window=1", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 after window expiration, got %d", w.Code)
	}
}
