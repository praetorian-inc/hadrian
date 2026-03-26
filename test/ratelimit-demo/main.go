package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"
)

var (
	port          = flag.Int("port", 8080, "Server port")
	defaultLimit  = flag.Int("default-limit", 5, "Default rate limit")
	defaultWindow = flag.Duration("default-window", 60*time.Second, "Default time window")
)

func main() {
	flag.Parse()

	limiter := NewRateLimiter()
	mux := http.NewServeMux()
	registerHandlers(mux, limiter)

	handler := loggingMiddleware(mux)

	addr := fmt.Sprintf(":%d", *port)
	fmt.Printf("Starting Rate Limit Demo Server on %s\n", addr)
	fmt.Printf("Default settings: limit=%d, window=%v\n", *defaultLimit, *defaultWindow)
	fmt.Println("\nEndpoints:")
	fmt.Println("  GET /api/v1/basic/resource           - No rate limit (baseline)")
	fmt.Println("  GET /api/v1/status-429/resource      - Returns 429 after limit")
	fmt.Println("  GET /api/v1/status-503/resource      - Returns 503 after limit")
	fmt.Println("  GET /api/v1/retry-seconds/resource   - 429 + Retry-After: 5")
	fmt.Println("  GET /api/v1/retry-date/resource      - 429 + Retry-After: <HTTP-date>")
	fmt.Println("  GET /api/v1/ratelimit-headers/resource - 429 + X-RateLimit-* headers")
	fmt.Println("  GET /api/v1/body-plain/resource      - 429 + plain text body")
	fmt.Println("  GET /api/v1/body-json/resource       - 429 + JSON error")
	fmt.Println("  GET /api/v1/body-json-retry/resource - 429 + JSON with retry_after")
	fmt.Println("  GET /api/v1/global/*                 - Shared counter")
	fmt.Println("  GET /api/v1/per-endpoint/*           - Independent counters")
	fmt.Println("  GET /api/v1/per-ip/resource          - Rate limit per IP")
	fmt.Println("\nQuery parameters:")
	fmt.Println("  ?limit=N   - Set rate limit (default: 5)")
	fmt.Println("  ?window=N  - Set window in seconds (default: 60)")
	fmt.Println()

	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatal(err)
	}
}
