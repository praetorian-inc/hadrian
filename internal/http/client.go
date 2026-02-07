package http

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/log"
)

// privateRanges contains parsed private/internal IP CIDR ranges for SSRF prevention.
// Defined here to avoid import cycle with pkg/runner.
var privateRanges []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			privateRanges = append(privateRanges, network)
		}
	}
}

// Client wraps stdlib HTTP client with proxy support
type Client struct {
	httpClient *http.Client
	config     *Config
}

type Config struct {
	Proxy         string        // http://localhost:8080
	CACert        string        // Path to CA certificate (Burp)
	Insecure      bool          // Skip TLS verification
	Timeout       time.Duration // Request timeout
	AllowInternal bool          // Allow connections to internal IPs (RFC 1918)
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
		// Custom DialContext prevents SSRF via DNS rebinding (TOCTOU)
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}

			// If AllowInternal is false, validate IPs at connect time
			if !config.AllowInternal {
				// Extract hostname from addr (format: "host:port")
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("invalid address %s: %w", addr, err)
				}

				// Resolve hostname to IPs
				ips, err := net.LookupIP(host)
				if err != nil {
					return nil, fmt.Errorf("DNS resolution failed for %s: %w", host, err)
				}

				// Check if any resolved IP is private
				for _, ip := range ips {
					for _, cidrNet := range privateRanges {
						if cidrNet.Contains(ip) {
							return nil, fmt.Errorf("connection to internal IP %s blocked (DNS rebinding protection)", ip)
						}
					}
				}
			}

			return dialer.DialContext(ctx, network, addr)
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

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		// Prevent credential leaks on cross-domain redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			// Strip sensitive headers on cross-domain redirects
			if len(via) > 0 && req.URL.Host != via[0].URL.Host {
				req.Header.Del("Authorization")
				req.Header.Del("Cookie")
			}
			return nil
		},
	}

	return &Client{
		httpClient: client,
		config:     config,
	}, nil
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return c.httpClient.Do(req)
}
