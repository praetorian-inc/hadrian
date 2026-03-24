package http

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"syscall"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/log"
)

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
	TLSMinVersion uint16        // Minimum TLS version (default: TLS 1.2)
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

		// Log CA cert fingerprint for audit (TLS audit)
		fingerprint := sha256.Sum256(caCert)
		log.Debug("CA cert fingerprint (SHA-256): %x", fingerprint[:16])
	}

	// Configure transport with proxy support
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		// Control callback runs after DNS resolution with the resolved IP,
		// catching both literal IPs and hostnames that resolve to internal addresses.
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err == nil {
				if ip := net.ParseIP(host); ip != nil && isInternalIP(ip) {
					log.Warn("SECURITY: connecting to internal/reserved IP %s — ensure this is intentional", ip)
				}
			}
			return nil // warn only, do not block
		},
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment, // Respects HTTP_PROXY env var
		TLSClientConfig: &tls.Config{
			RootCAs:            rootCAs,
			InsecureSkipVerify: config.Insecure,
			MinVersion:         tlsMinVersion(config.TLSMinVersion),
		},
		DialContext: dialer.DialContext,
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

// tlsMinVersion returns the configured TLS minimum version, defaulting to TLS 1.2.
func tlsMinVersion(v uint16) uint16 {
	if v != 0 {
		return v
	}
	return tls.VersionTLS12
}

// isInternalIP returns true if the IP is in a private, loopback, link-local,
// or cloud metadata range (RFC 1918, RFC 4193, 169.254.0.0/16).
func isInternalIP(ip net.IP) bool {
	// Cloud metadata endpoint
	if ip.Equal(net.ParseIP("169.254.169.254")) {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}
