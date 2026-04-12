package runner

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/log"
)

// productionIndicators are URL patterns that suggest a production environment.
var productionIndicators = []string{
	"prod",
	"production",
	"live",
}

// nonProductionIndicators are URL patterns that suggest a non-production environment.
var nonProductionIndicators = []string{
	"localhost",
	"127.0.0.1",
	"::1",
	"staging",
	"stage",
	"dev",
	"development",
	"test",
	"sandbox",
	"local",
	"0.0.0.0",
}

// DetectProduction checks whether a URL appears to be a production system.
// Returns true if the URL looks like production, false if it looks like
// a development/staging/local environment.
func DetectProduction(baseURL string) (bool, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return false, fmt.Errorf("failed to parse URL %q: %w", baseURL, err)
	}

	host := strings.ToLower(parsed.Hostname())

	// Check non-production indicators first
	for _, indicator := range nonProductionIndicators {
		if strings.Contains(host, indicator) {
			return false, nil
		}
	}

	// Check production indicators
	for _, indicator := range productionIndicators {
		if strings.Contains(host, indicator) {
			return true, nil
		}
	}

	// If no indicators match, assume production (fail-safe)
	return true, nil
}

// CheckProductionSafety detects if the target URL is a production system and
// prompts the user for confirmation before proceeding.
// If detection fails, it defaults to assuming production (fail-safe).
func CheckProductionSafety(baseURL string) error {
	isProduction, err := DetectProduction(baseURL)
	if err != nil {
		log.Error("Failed to detect production URL, assuming production for safety: %v", err)
		isProduction = true
	}

	if !isProduction {
		return nil
	}

	fmt.Fprintf(os.Stderr, "\n%s[WARNING]%s Target URL %q appears to be a production system.\n",
		log.ColorYellow, log.ColorReset, baseURL)
	fmt.Fprintf(os.Stderr, "Running security tests against production can cause disruption.\n")
	fmt.Fprintf(os.Stderr, "Type 'yes' to continue: ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		log.Error("Failed to read user input, aborting for safety: %v", err)
		return fmt.Errorf("failed to read confirmation input: %w", err)
	}

	input = strings.TrimSpace(strings.ToLower(input))
	if input != "yes" {
		return fmt.Errorf("aborted: user declined to test production system %q", baseURL)
	}

	return nil
}
