package runner

import (
	"bufio"

	"github.com/praetorian-inc/hadrian/pkg/log"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// DetectProduction checks if URL appears to be a production API
func DetectProduction(baseURL string) (bool, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return false, err
	}

	hostname := u.Hostname()

	// First check for non-production indicators
	nonProdPatterns := []string{
		`localhost`,
		`127\.0\.0\.1`,
		`\.(dev|test|staging|qa|uat|local)\.`,  // *.dev.*, *.staging.*, etc.
	}

	for _, pattern := range nonProdPatterns {
		if matched, _ := regexp.MatchString(pattern, hostname); matched {
			return false, nil
		}
	}

	// Then check for production patterns
	productionPatterns := []string{
		`^(api|www)\..*\.(com|net|org)$`,  // api.example.com
		`^.*\.prod\..*$`,                   // *.prod.*
		`^.*\.production\..*$`,             // *.production.*
	}

	for _, pattern := range productionPatterns {
		if matched, _ := regexp.MatchString(pattern, hostname); matched {
			return true, nil
		}
	}

	return false, nil
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
		// DNS lookup failed, but allow (might be valid external host with temp DNS issue)
		return nil
	}

	// Block private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",       // localhost
		"169.254.0.0/16",    // AWS metadata
		"::1/128",           // IPv6 localhost
		"fc00::/7",          // IPv6 private
	}

	for _, ip := range ips {
		for _, cidr := range privateRanges {
			_, network, _ := net.ParseCIDR(cidr)
			if network.Contains(ip) {
				if !allowInternal {
					return fmt.Errorf("SSRF blocked: target IP %s is in private range %s (use --allow-internal to override)", ip, cidr)
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
		return nil  // Not production, proceed
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
