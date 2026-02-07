package runner

import (
	"bufio"

	"fmt"
	"github.com/praetorian-inc/hadrian/pkg/log"
	"net"
	"net/url"
	"os"
	"strings"
)

// PrivateRanges contains private IP address ranges for SSRF protection
var PrivateRanges []*net.IPNet

func init() {
	// Parse private IP ranges once at startup
	privateRangeCIDRs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",    // localhost
		"169.254.0.0/16", // AWS metadata
		"::1/128",        // IPv6 localhost
		"fc00::/7",       // IPv6 private
	}

	for _, cidr := range privateRangeCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("Failed to parse private IP range %s: %v", cidr, err))
		}
		PrivateRanges = append(PrivateRanges, network)
	}
}

// IsPrivateIP checks if a hostname resolves to a private IP address
func IsPrivateIP(hostname string) bool {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return false
	}

	for _, ip := range ips {
		for _, network := range PrivateRanges {
			if network.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// DetectProduction checks if URL appears to be a production API.
// Uses default-deny: only returns false for explicitly safe targets.
// Everything else is treated as production (requires --allow-production).
func DetectProduction(baseURL string) (bool, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return false, err
	}

	hostname := u.Hostname()

	// Check for known safe/non-production patterns (explicit allow-list)

	// 1. localhost and loopback
	if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
		return false, nil
	}

	// 2. 127.x.x.x range
	if strings.HasPrefix(hostname, "127.") {
		return false, nil
	}

	// 3. Safe TLDs
	safeTLDs := []string{".local", ".test", ".example", ".internal", ".localhost"}
	for _, tld := range safeTLDs {
		if strings.HasSuffix(hostname, tld) {
			return false, nil
		}
	}

	// 4. Non-production hostname prefixes
	nonProdPrefixes := []string{"test.", "dev.", "staging.", "qa.", "uat.", "local.", "sandbox."}
	for _, prefix := range nonProdPrefixes {
		if strings.HasPrefix(hostname, prefix) {
			return false, nil
		}
	}

	// 5. Non-production subdomains (must appear as distinct subdomain segments)
	nonProdSubdomains := []string{".dev.", ".staging.", ".qa.", ".uat."}
	for _, subdomain := range nonProdSubdomains {
		if strings.Contains(hostname, subdomain) {
			return false, nil
		}
	}

	// 6. Private IP ranges
	if IsPrivateIP(hostname) {
		return false, nil
	}

	// Default: treat as production (requires --allow-production flag)
	return true, nil
}

// BlockInternalIPs prevents SSRF attacks on internal networks (CR-4)
func BlockInternalIPs(targetURL string, allowInternal bool) error {
	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}

	// Resolve hostname to IP
	ips, err := net.LookupIP(u.Hostname())
	if err != nil {
		// DNS lookup failed - block for safety (prevents SSRF bypass via DNS failure)
		return fmt.Errorf("DNS lookup failed for %s, blocking request for safety: %w", u.Hostname(), err)
	}

	// Block private IP ranges
	for _, ip := range ips {
		for _, network := range PrivateRanges {
			if network.Contains(ip) {
				if !allowInternal {
					return fmt.Errorf("SSRF blocked: target IP %s is in private range %s (use --allow-internal to override)", ip, network.String())
				}
				log.Warn("Testing internal IP: %s", ip)
			}
		}
	}

	return nil
}

// ConfirmProductionTesting prompts user for explicit confirmation (HR-1)
func ConfirmProductionTesting(baseURL string, allowProd bool) error {
	isProduction, _ := DetectProduction(baseURL)

	if !isProduction {
		return nil // Not production, proceed
	}

	// Production URL detected
	fmt.Println()
	fmt.Println("⚠️  WARNING: Production API Detected!")
	fmt.Printf("URL: %s\n", baseURL)
	fmt.Println()
	fmt.Println("Testing production APIs can cause:")
	fmt.Println("  • Service disruption (DoS)")
	fmt.Println("  • Data corruption from mutation tests")
	fmt.Println("  • Legal liability")
	fmt.Println()

	if !allowProd {
		return fmt.Errorf("production testing blocked (use --allow-production flag)")
	}

	// Require explicit confirmation
	fmt.Print("Type 'CONFIRM PRODUCTION TESTING' to proceed: ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input != "CONFIRM PRODUCTION TESTING" {
		return fmt.Errorf("production testing not confirmed")
	}

	log.Debug("Production testing confirmed by user")
	return nil
}
