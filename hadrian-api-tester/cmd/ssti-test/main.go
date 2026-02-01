package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/injection/ssti"
)

// config holds command-line configuration
type config struct {
	target      string
	param       string
	method      string
	proxy       string
	verbose     bool
	insecure    bool
	payloadsDir string
}

// result holds detection results
type result struct {
	detected  bool
	payload   string
	engine    string
	evidence  string
	matchType string
}

func main() {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// parseFlags parses command-line flags
func parseFlags(args []string) (config, error) {
	fs := flag.NewFlagSet("ssti-test", flag.ContinueOnError)

	var cfg config
	fs.StringVar(&cfg.target, "target", "", "Target URL (required)")
	fs.StringVar(&cfg.param, "param", "message", "Parameter name to inject")
	fs.StringVar(&cfg.method, "method", "GET", "HTTP method (GET or POST)")
	fs.StringVar(&cfg.proxy, "proxy", "", "Proxy URL for Burp Suite")
	fs.BoolVar(&cfg.verbose, "verbose", false, "Show all payloads tested")
	fs.BoolVar(&cfg.insecure, "insecure", false, "Skip TLS verification")
	fs.StringVar(&cfg.payloadsDir, "payloads", "", "YAML payload source: directory, single file, or comma-separated files (optional, uses embedded defaults if not specified)")

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	if cfg.target == "" {
		return cfg, fmt.Errorf("-target is required")
	}

	// Validate method
	cfg.method = strings.ToUpper(cfg.method)
	if cfg.method != "GET" && cfg.method != "POST" {
		return cfg, fmt.Errorf("method must be GET or POST")
	}

	return cfg, nil
}

// run executes the SSTI testing
func run(cfg config) error {
	// Create SSTI module (with custom payloads if specified)
	var module *ssti.SSTIModule

	if cfg.payloadsDir != "" {
		payloads, err := ssti.LoadPayloads(cfg.payloadsDir)
		if err != nil {
			return fmt.Errorf("loading payloads: %w", err)
		}
		module = ssti.NewSSTIModuleWithPayloadList(payloads)
		fmt.Printf("[*] Loaded custom payloads from: %s\n", cfg.payloadsDir)
	} else {
		module = ssti.NewSSTIModule()
		fmt.Println("[*] Using embedded default payloads")
	}

	payloads := module.Payloads()

	// Create HTTP client
	client, err := createClient(cfg)
	if err != nil {
		return err
	}

	fmt.Printf("[*] Target: %s\n", cfg.target)
	fmt.Printf("[*] Parameter: %s\n", cfg.param)
	fmt.Printf("[*] Testing %d SSTI payloads...\n\n", len(payloads))

	var results []result
	for _, payload := range payloads {
		if cfg.verbose {
			fmt.Printf("[>] Testing: %s (%s)\n", payload.Value, payload.Description)
		}

		// Build and send request
		req, err := buildRequest(cfg, payload.Value)
		if err != nil {
			if cfg.verbose {
				fmt.Printf("    Error building request: %v\n", err)
			}
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			if cfg.verbose {
				fmt.Printf("    Error sending request: %v\n", err)
			}
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			if cfg.verbose {
				fmt.Printf("    Error reading response: %v\n", err)
			}
			continue
		}

		// Detect vulnerability
		detection := module.Detect(resp, string(body), payload)
		if detection.Detected {
			results = append(results, result{
				detected:  true,
				payload:   payload.Value,
				engine:    payload.Engine,
				evidence:  detection.Evidence,
				matchType: detection.MatchType,
			})

			fmt.Printf("[+] VULNERABLE! Payload: %s\n", payload.Value)
			fmt.Printf("    Engine: %s\n", payload.Engine)
			if len(detection.Evidence) < 100 {
				fmt.Printf("    Evidence: %s\n", detection.Evidence)
			} else {
				fmt.Printf("    Evidence: %s...\n", detection.Evidence[:100])
			}
			fmt.Printf("    Match Type: %s\n\n", detection.MatchType)
		}
	}

	// Print summary
	if len(results) > 0 {
		fmt.Printf("[*] Scan complete. Found %d SSTI indicator(s).\n", len(results))
	} else {
		fmt.Println("[*] Scan complete. No SSTI vulnerabilities detected.")
	}

	return nil
}

// createClient creates an HTTP client with optional proxy and TLS settings
func createClient(cfg config) (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.insecure,
		},
	}

	if cfg.proxy != "" {
		proxyURL, err := url.Parse(cfg.proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	return &http.Client{
		Transport: transport,
	}, nil
}

// buildRequest constructs an HTTP request with the injected payload
func buildRequest(cfg config, payload string) (*http.Request, error) {
	if cfg.method == "GET" {
		// Inject in query parameter
		u, err := url.Parse(cfg.target)
		if err != nil {
			return nil, err
		}

		q := u.Query()
		q.Set(cfg.param, payload)
		u.RawQuery = q.Encode()

		return http.NewRequest("GET", u.String(), nil)
	}

	// POST - inject in form body
	data := url.Values{}
	data.Set(cfg.param, payload)

	req, err := http.NewRequest("POST", cfg.target, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// detectVulnerability analyzes response for SSTI indicators
func detectVulnerability(resp *http.Response, body, payload, expected string) result {
	r := result{
		detected: false,
		payload:  payload,
	}

	// Error-based detection
	if expected == "error" {
		if resp.StatusCode == http.StatusInternalServerError && containsTemplateError(body) {
			r.detected = true
			r.evidence = body
			r.matchType = "error"
			return r
		}
	}

	// Exact match detection
	if strings.Contains(body, expected) {
		r.detected = true
		r.evidence = body
		r.matchType = "exact"
	}

	return r
}

// containsTemplateError checks for template error indicators
func containsTemplateError(body string) bool {
	errorIndicators := []string{
		"TemplateSyntaxError",
		"TemplateError",
		"TemplateException",
		"template",
		"syntax error",
	}

	bodyLower := strings.ToLower(body)
	for _, indicator := range errorIndicators {
		if strings.Contains(bodyLower, strings.ToLower(indicator)) {
			return true
		}
	}
	return false
}
