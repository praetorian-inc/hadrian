package runner

import (
	"strings"
	"testing"
)

func TestDetectProduction_ProductionURLs(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"api subdomain", "https://api.example.com", true},
		{"www subdomain", "https://www.example.com", true},
		{"prod subdomain", "https://app.prod.company.com", true},
		{"production subdomain", "https://api.production.company.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DetectProduction(tt.url)
			if err != nil {
				t.Fatalf("DetectProduction() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("DetectProduction(%s) = %v; want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestDetectProduction_NonProductionURLs(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"localhost", "http://localhost:8080", false},
		{"staging", "https://api.staging.company.com", false},
		{"dev", "https://api.dev.company.com", false},
		{"test", "https://test.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DetectProduction(tt.url)
			if err != nil {
				t.Fatalf("DetectProduction() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("DetectProduction(%s) = %v; want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestBlockInternalIPs_Localhost(t *testing.T) {
	err := BlockInternalIPs("http://127.0.0.1:8080", false)
	if err == nil {
		t.Error("BlockInternalIPs(127.0.0.1) = nil; want error for localhost")
	}
	if err != nil && !strings.Contains(err.Error(), "SSRF blocked") {
		t.Errorf("Error message should contain 'SSRF blocked'; got %v", err)
	}
}

func TestBlockInternalIPs_PrivateIP(t *testing.T) {
	tests := []string{
		"http://10.0.0.1",
		"http://192.168.1.1",
		"http://172.16.0.1",
	}

	for _, url := range tests {
		err := BlockInternalIPs(url, false)
		if err == nil {
			t.Errorf("BlockInternalIPs(%s) = nil; want error for private IP", url)
		}
	}
}

func TestBlockInternalIPs_AWSMetadata(t *testing.T) {
	err := BlockInternalIPs("http://169.254.169.254", false)
	if err == nil {
		t.Error("BlockInternalIPs(169.254.169.254) = nil; want error for AWS metadata")
	}
	if err != nil && !strings.Contains(err.Error(), "SSRF blocked") {
		t.Errorf("Error message should contain 'SSRF blocked'; got %v", err)
	}
}

func TestBlockInternalIPs_IPv6Private(t *testing.T) {
	err := BlockInternalIPs("http://[::1]:8080", false)
	if err == nil {
		t.Error("BlockInternalIPs([::1]) = nil; want error for IPv6 localhost")
	}
}

func TestBlockInternalIPs_ExternalIP(t *testing.T) {
	err := BlockInternalIPs("https://8.8.8.8", false)
	if err != nil {
		t.Errorf("BlockInternalIPs(8.8.8.8) = %v; want nil for external IP", err)
	}
}

func TestBlockInternalIPs_AllowInternal(t *testing.T) {
	// Should not error when allowInternal = true
	err := BlockInternalIPs("http://127.0.0.1:8080", true)
	if err != nil {
		t.Errorf("BlockInternalIPs(127.0.0.1, allowInternal=true) = %v; want nil", err)
	}
}

func TestConfirmProductionTesting_NonProduction(t *testing.T) {
	// Non-production URLs should pass without interaction
	err := ConfirmProductionTesting("http://localhost:8080/api", false)
	if err != nil {
		t.Errorf("ConfirmProductionTesting(localhost) = %v; want nil for non-production URL", err)
	}
}

func TestConfirmProductionTesting_ProductionBlocked(t *testing.T) {
	// Production URL with allowProd=false should be blocked
	err := ConfirmProductionTesting("https://api.example.com", false)
	if err == nil {
		t.Error("ConfirmProductionTesting(production, allowProd=false) = nil; want error")
	}
	if err != nil && !strings.Contains(err.Error(), "production testing blocked") {
		t.Errorf("Error should contain 'production testing blocked'; got %v", err)
	}
}

// NOTE: Testing ConfirmProductionTesting with allowProd=true requires stdin interaction
// and is difficult to automate. Manual testing required for the confirmation prompt.
