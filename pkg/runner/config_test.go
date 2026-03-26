package runner

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// validRateLimitDefaults returns valid rate limit configuration for tests
func validRateLimitDefaults() (float64, string, time.Duration, int, []int) {
	return 5.0, "exponential", 60 * time.Second, 5, []int{429, 503}
}

func TestValidate_Success(t *testing.T) {
	// Create temporary test files
	tmpDir := t.TempDir()
	apiSpec := filepath.Join(tmpDir, "api.yaml")
	rolesFile := filepath.Join(tmpDir, "roles.yaml")

	if err := os.WriteFile(apiSpec, []byte("openapi: 3.0.0"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rolesFile, []byte("roles: []"), 0644); err != nil {
		t.Fatal(err)
	}

	config := &Config{
		API:                  apiSpec,
		Roles:                rolesFile,
		Output:               "terminal",
		RateLimit:            5.0,
		RateLimitBackoff:     "exponential",
		RateLimitMaxWait:     60 * time.Second,
		RateLimitMaxRetries:  5,
		RateLimitStatusCodes: []int{429, 503},
	}

	err := config.Validate()
	if err != nil {
		t.Errorf("Validate() = %v; want nil", err)
	}
}

func TestValidate_MissingAPISpec(t *testing.T) {
	config := &Config{
		API:    "/nonexistent/api.yaml",
		Roles:  "/tmp/roles.yaml",
		Output: "terminal",
	}

	err := config.Validate()
	if err == nil {
		t.Error("Validate() = nil; want error for missing API spec")
	}
}

func TestValidate_MissingRolesFile(t *testing.T) {
	// Create temporary API spec
	tmpDir := t.TempDir()
	apiSpec := filepath.Join(tmpDir, "api.yaml")
	if err := os.WriteFile(apiSpec, []byte("openapi: 3.0.0"), 0644); err != nil {
		t.Fatal(err)
	}

	config := &Config{
		API:    apiSpec,
		Roles:  "/nonexistent/roles.yaml",
		Output: "terminal",
	}

	err := config.Validate()
	if err == nil {
		t.Error("Validate() = nil; want error for missing roles file")
	}
}

func TestValidate_InvalidProxy(t *testing.T) {
	// Create temporary test files
	tmpDir := t.TempDir()
	apiSpec := filepath.Join(tmpDir, "api.yaml")
	rolesFile := filepath.Join(tmpDir, "roles.yaml")

	if err := os.WriteFile(apiSpec, []byte("openapi: 3.0.0"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rolesFile, []byte("roles: []"), 0644); err != nil {
		t.Fatal(err)
	}

	rate, backoff, maxWait, maxRetries, statusCodes := validRateLimitDefaults()
	config := &Config{
		API:                  apiSpec,
		Roles:                rolesFile,
		Proxy:                "not-a-valid-url",
		Output:               "terminal",
		RateLimit:            rate,
		RateLimitBackoff:     backoff,
		RateLimitMaxWait:     maxWait,
		RateLimitMaxRetries:  maxRetries,
		RateLimitStatusCodes: statusCodes,
	}

	err := config.Validate()
	if err == nil {
		t.Error("Validate() = nil; want error for invalid proxy URL")
	}
}

func TestValidate_InvalidOutputFormat(t *testing.T) {
	// Create temporary test files
	tmpDir := t.TempDir()
	apiSpec := filepath.Join(tmpDir, "api.yaml")
	rolesFile := filepath.Join(tmpDir, "roles.yaml")

	if err := os.WriteFile(apiSpec, []byte("openapi: 3.0.0"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rolesFile, []byte("roles: []"), 0644); err != nil {
		t.Fatal(err)
	}

	rate, backoff, maxWait, maxRetries, statusCodes := validRateLimitDefaults()
	config := &Config{
		API:                  apiSpec,
		Roles:                rolesFile,
		Output:               "xml", // Invalid format
		RateLimit:            rate,
		RateLimitBackoff:     backoff,
		RateLimitMaxWait:     maxWait,
		RateLimitMaxRetries:  maxRetries,
		RateLimitStatusCodes: statusCodes,
	}

	err := config.Validate()
	if err == nil {
		t.Error("Validate() = nil; want error for invalid output format")
	}
}

func TestToHTTPClientConfig(t *testing.T) {
	config := &Config{
		Proxy:    "http://localhost:8080",
		CACert:   "/path/to/cert.pem",
		Insecure: true,
		Timeout:  45,
	}

	httpConfig := config.ToHTTPClientConfig()

	if httpConfig.Proxy != "http://localhost:8080" {
		t.Errorf("Proxy = %s; want http://localhost:8080", httpConfig.Proxy)
	}
	if httpConfig.CACert != "/path/to/cert.pem" {
		t.Errorf("CACert = %s; want /path/to/cert.pem", httpConfig.CACert)
	}
	if !httpConfig.Insecure {
		t.Error("Insecure = false; want true")
	}
	if httpConfig.Timeout.Seconds() != 45 {
		t.Errorf("Timeout = %v; want 45s", httpConfig.Timeout)
	}

}
