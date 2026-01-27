package http

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/praetorian-inc/hadrian/pkg/log"
)

// Client wraps stdlib HTTP client with proxy support
type Client struct {
	httpClient *http.Client
	config     *Config
}

type Config struct {
	Proxy       string        // http://localhost:8080
	CACert      string        // Path to CA certificate (Burp)
	Insecure    bool          // Skip TLS verification
	Timeout     time.Duration // Request timeout
	RequestID   bool          // Add X-Hadrian-Request-ID header to each request
}

// requestIDTransport wraps an http.RoundTripper and adds a unique
// X-Hadrian-Request-ID header to every outgoing request.
type requestIDTransport struct {
	base http.RoundTripper
}

func (t *requestIDTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	clone := req.Clone(req.Context())
	// Only add if not already set (executor may have set it)
	if clone.Header.Get("X-Hadrian-Request-ID") == "" {
		clone.Header.Set("X-Hadrian-Request-ID", uuid.New().String())
	}
	return t.base.RoundTrip(clone)
}

func New(config *Config) (*Client, error) {
	// Handle nil config with defaults
	if config == nil {
		config = &Config{
			Timeout: 30 * time.Second,
		}
	}

	// Load custom CA certificate (for Burp Suite)
	var rootCAs *x509.CertPool
	if config.CACert != "" {
		caCert, err := os.ReadFile(config.CACert)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA cert %s: %w", config.CACert, err)
		}

		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert")
		}

		// Log CA cert fingerprint for audit (HR-3)
		fingerprint := sha256.Sum256(caCert)
		log.Debug("CA cert fingerprint (SHA-256): %x", fingerprint[:16])
	}

	// Configure transport with proxy support
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,  // Respects HTTP_PROXY env var
		TLSClientConfig: &tls.Config{
			RootCAs:            rootCAs,
			InsecureSkipVerify: config.Insecure,
			MinVersion:         tls.VersionTLS13,  // TLS 1.3 enforcement (HR-3)
		},
	}

	// Override with explicit proxy if provided
	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}

		// Add proxy authentication from environment
		if username := os.Getenv("PROXY_USERNAME"); username != "" {
			password := os.Getenv("PROXY_PASSWORD")
			proxyURL.User = url.UserPassword(username, password)
		}

		transport.Proxy = http.ProxyURL(proxyURL)

		log.Warn("Using HTTP proxy: %s", config.Proxy)
	}

	// Warn if insecure mode
	if config.Insecure {
		log.Warn("TLS verification disabled (--insecure). Use only with trusted proxies.")
	}

	// Wrap transport with request ID header if enabled
	var finalTransport http.RoundTripper = transport
	if config.RequestID {
		finalTransport = &requestIDTransport{base: transport}
		log.Debug("Request ID tracking enabled: X-Hadrian-Request-ID header will be added to all requests")
	}

	return &Client{
		httpClient: &http.Client{
			Transport: finalTransport,
			Timeout:   config.Timeout,
		},
		config: config,
	}, nil
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return c.httpClient.Do(req)
}
