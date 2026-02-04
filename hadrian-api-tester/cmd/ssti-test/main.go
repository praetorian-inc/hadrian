package main

import (
	"crypto/tls"
	"flag"
	"fmt"
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
	fingerprint bool // enable fingerprinting mode (faster, detects engine family first)
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
	fs.BoolVar(&cfg.fingerprint, "fingerprint", false, "Use fingerprinting mode (faster, detects engine family first)")

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

// run executes the SSTI testing with multi-pass verification (always enabled)
func run(cfg config) error {
	// Create HTTP client
	client, err := createClient(cfg)
	if err != nil {
		return err
	}

	// Use fingerprinting mode if requested
	if cfg.fingerprint {
		return runWithFingerprinting(cfg, client)
	}

	// Create SSTI module for detection helpers
	module := ssti.NewSSTIModule()

	fmt.Println("[*] SSTI Scanner - Multi-pass Verification")
	fmt.Printf("[*] Target: %s\n", cfg.target)
	fmt.Printf("[*] Parameter: %s\n\n", cfg.param)

	// Load verification chains from YAML files (all payloads are treated as verification chain)
	engines, err := loadVerificationChains(cfg.payloadsDir)
	if err != nil {
		return fmt.Errorf("loading verification chains: %w", err)
	}

	if len(engines) == 0 {
		return fmt.Errorf("no verification chains found in payload files")
	}

	// Run verification for all engines
	results := module.RunVerification(client, cfg.target, cfg.param, cfg.method, engines)

	// Display results
	var confirmed []string
	var likely []string
	var uncertain []string

	for _, result := range results {
		fmt.Printf("[ENGINE: %s]\n", result.Engine)

		for i, pass := range result.PassResults {
			status := "✗ NOT FOUND"
			if pass.Found {
				status = "✓ FOUND"
			}
			fmt.Printf("  Pass %d/%d: %s → \"%s\"... %s\n",
				i+1, result.TotalPasses, pass.Payload, pass.Expected, status)
		}

		if result.Confirmed {
			fmt.Printf("  Result: ✓ CONFIRMED (%d/%d)\n\n", result.PassCount, result.TotalPasses)
			confirmed = append(confirmed, result.Engine)
		} else if result.PassCount >= 2 {
			fmt.Printf("  Result: ~ LIKELY (%d/%d)\n\n", result.PassCount, result.TotalPasses)
			likely = append(likely, result.Engine)
		} else if result.Uncertain {
			fmt.Printf("  Result: ? UNCERTAIN (%d/%d)\n\n", result.PassCount, result.TotalPasses)
			uncertain = append(uncertain, result.Engine)
		} else {
			fmt.Printf("  Result: ✗ NOT VULNERABLE (%d/%d)\n\n", result.PassCount, result.TotalPasses)
		}
	}

	// Print summary
	fmt.Println("[SUMMARY]")
	if len(confirmed) > 0 {
		fmt.Printf("  CONFIRMED: %s\n", strings.Join(confirmed, ", "))
	}
	if len(likely) > 0 {
		fmt.Printf("  LIKELY: %s\n", strings.Join(likely, ", "))
	}
	if len(uncertain) > 0 {
		fmt.Printf("  UNCERTAIN: %s\n", strings.Join(uncertain, ", "))
	}
	if len(confirmed) == 0 && len(likely) == 0 && len(uncertain) == 0 {
		fmt.Println("  No vulnerabilities detected")
	}

	return nil
}

// loadVerificationChains loads verification chains from YAML files (all payloads treated as chain)
func loadVerificationChains(payloadDir string) (map[string][]ssti.PayloadWithExpected, error) {
	// If no directory specified, use default
	if payloadDir == "" {
		payloadDir = "payloads/ssti"
	}

	// Check if it's a directory or file(s)
	info, err := os.Stat(payloadDir)
	if err != nil {
		return nil, err
	}

	var files []string
	if info.IsDir() {
		entries, err := os.ReadDir(payloadDir)
		if err != nil {
			return nil, err
		}

		for _, entry := range entries {
			if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".yaml") || strings.HasSuffix(entry.Name(), ".yml")) {
				files = append(files, payloadDir+"/"+entry.Name())
			}
		}
	} else {
		// Single file or comma-separated
		if strings.Contains(payloadDir, ",") {
			files = strings.Split(payloadDir, ",")
		} else {
			files = []string{payloadDir}
		}
	}

	engines := make(map[string][]ssti.PayloadWithExpected)

	for _, file := range files {
		file = strings.TrimSpace(file)
		payloadFile, err := ssti.LoadPayloadFileWithPayloads(file)
		if err != nil {
			continue // Skip files that can't be loaded
		}

		if len(payloadFile.Payloads) == 0 {
			continue // Skip if no payloads
		}

		// Convert all payloads to PayloadWithExpected (all payloads are verification chain)
		chain := make([]ssti.PayloadWithExpected, 0, len(payloadFile.Payloads))
		for _, yp := range payloadFile.Payloads {
			chain = append(chain, ssti.PayloadWithExpected{
				Value:       yp.Value,
				Expected:    yp.Expected,
				Description: yp.Description,
			})
		}

		engines[payloadFile.Engine] = chain
	}

	return engines, nil
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

// runWithFingerprinting executes SSTI testing with fingerprinting mode
func runWithFingerprinting(cfg config, client *http.Client) error {
	fmt.Println("[*] SSTI Scanner - Fingerprinting Mode")
	fmt.Printf("[*] Target: %s\n", cfg.target)
	fmt.Printf("[*] Parameter: %s\n\n", cfg.param)

	// Create fingerprinter
	fingerprinter := ssti.NewFingerprinter(client)

	// Run fingerprint and confirm workflow
	result, err := fingerprinter.FingerprintAndConfirm(cfg.target, cfg.param, cfg.method)
	if err != nil {
		return fmt.Errorf("fingerprinting failed: %w", err)
	}

	// Phase 1: Display probe results
	fmt.Println("[PHASE 1: FINGERPRINTING]")
	for _, probeResult := range result.ProbeResults {
		status := "✗ NO RESPONSE"
		if probeResult.Detected {
			status = "✓ DETECTED"
		}
		fmt.Printf("  Probe: %s (%s) → %s\n", probeResult.Probe.Payload, probeResult.Probe.TargetFamily, status)
	}

	// Show detected families
	fmt.Println()
	if len(result.DetectedFamilies) == 0 {
		fmt.Println("  No engine families detected")
		fmt.Println()
		fmt.Println("[SUMMARY]")
		fmt.Println("  No vulnerabilities detected")
		return nil
	}

	var detectedFamilyNames []string
	for family, detected := range result.DetectedFamilies {
		if detected {
			detectedFamilyNames = append(detectedFamilyNames, string(family))
		}
	}
	fmt.Printf("  Detected families: %s\n", strings.Join(detectedFamilyNames, ", "))
	fmt.Printf("  Candidate engines: %s\n", strings.Join(result.CandidateEngines, ", "))

	// Phase 2: Display confirmation results
	fmt.Println()
	fmt.Println("[PHASE 2: CONFIRMATION]")
	if len(result.ConfirmedEngines) == 0 {
		fmt.Println("  No engines confirmed (all verification chains failed)")
	} else {
		for _, engine := range result.ConfirmedEngines {
			fmt.Printf("  Testing %s... ✓ CONFIRMED\n", engine)
		}
	}

	// Calculate efficiency gain
	fmt.Println()
	fmt.Println("[SUMMARY]")
	if len(result.ConfirmedEngines) > 0 {
		fmt.Printf("  CONFIRMED: %s\n", strings.Join(result.ConfirmedEngines, ", "))
	} else {
		fmt.Println("  No vulnerabilities confirmed")
	}

	// Calculate saved requests (12 engines * 3 passes each = 36 full scan requests)
	fullScanRequests := 12 * 3
	savedRequests := fullScanRequests - result.RequestCount
	fmt.Printf("  Total requests: %d (saved ~%d requests vs full scan)\n", result.RequestCount, savedRequests)

	return nil
}
