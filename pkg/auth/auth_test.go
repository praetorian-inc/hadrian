package auth

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_Success(t *testing.T) {
	// Set environment variable for test
	os.Setenv("ADMIN_TOKEN", "test-admin-token-123")
	defer os.Unsetenv("ADMIN_TOKEN")

	config, err := Load("testdata/auth.yaml")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if config.Method != "bearer" {
		t.Errorf("Expected method 'bearer', got '%s'", config.Method)
	}

	if len(config.Roles) != 2 {
		t.Errorf("Expected 2 roles, got %d", len(config.Roles))
	}

	// Verify admin role with expanded env var
	admin, ok := config.Roles["admin"]
	if !ok {
		t.Fatal("admin role not found")
	}
	if admin.Token != "test-admin-token-123" {
		t.Errorf("Expected expanded token, got '%s'", admin.Token)
	}

	// Verify user role with hardcoded token
	user, ok := config.Roles["user"]
	if !ok {
		t.Fatal("user role not found")
	}
	if user.Token == "" {
		t.Error("user token should not be empty")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("nonexistent.yaml")
	if err == nil {
		t.Fatal("Expected error for nonexistent file")
	}

	// Check that the error contains the expected message
	if err.Error() != "failed to read auth file: open nonexistent.yaml: no such file or directory" {
		t.Errorf("Expected 'no such file or directory' error, got: %v", err)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	// Create temporary invalid YAML file
	tmpDir := t.TempDir()
	invalidFile := filepath.Join(tmpDir, "invalid.yaml")
	err := os.WriteFile(invalidFile, []byte("invalid: yaml: content:\n  - broken"), 0600)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	_, err = Load(invalidFile)
	if err == nil {
		t.Fatal("Expected error for invalid YAML")
	}
}

func TestLoad_FilePermissionWarning(t *testing.T) {
	// Create temporary file with insecure permissions
	tmpDir := t.TempDir()
	insecureFile := filepath.Join(tmpDir, "insecure.yaml")
	content := []byte("method: bearer\nroles:\n  admin:\n    token: test")
	err := os.WriteFile(insecureFile, content, 0644) // Insecure permissions
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Capture output (warning should be printed)
	// Note: This test verifies Load succeeds despite warning
	config, err := Load(insecureFile)
	if err != nil {
		t.Fatalf("Load should succeed despite permission warning: %v", err)
	}

	if config == nil {
		t.Fatal("Expected valid config despite permission warning")
	}
}

func TestLoad_EnvironmentVariableExpansion(t *testing.T) {
	// Create temporary file with env var references
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "envtest.yaml")
	content := `method: basic
roles:
  admin:
    username: "${TEST_USERNAME}"
    password: "${TEST_PASSWORD}"
  api_user:
    api_key: "${TEST_API_KEY}"
`
	err := os.WriteFile(testFile, []byte(content), 0600)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Set environment variables
	os.Setenv("TEST_USERNAME", "admin_user")
	os.Setenv("TEST_PASSWORD", "secret_pass")
	os.Setenv("TEST_API_KEY", "api-key-123")
	defer func() {
		os.Unsetenv("TEST_USERNAME")
		os.Unsetenv("TEST_PASSWORD")
		os.Unsetenv("TEST_API_KEY")
	}()

	config, err := Load(testFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	admin := config.Roles["admin"]
	if admin.Username != "admin_user" {
		t.Errorf("Expected 'admin_user', got '%s'", admin.Username)
	}
	if admin.Password != "secret_pass" {
		t.Errorf("Expected 'secret_pass', got '%s'", admin.Password)
	}

	apiUser := config.Roles["api_user"]
	if apiUser.APIKey != "api-key-123" {
		t.Errorf("Expected 'api-key-123', got '%s'", apiUser.APIKey)
	}
}

func TestDetectHardcodedSecret_JWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	if !detectHardcodedSecret(jwt) {
		t.Error("Expected JWT to be detected as hardcoded secret")
	}
}

func TestDetectHardcodedSecret_APIKey(t *testing.T) {
	apiKey := "sk-1234567890abcdefghijklmnopqrstuvwxyz12345678"
	if !detectHardcodedSecret(apiKey) {
		t.Error("Expected OpenAI-style API key to be detected as hardcoded secret")
	}
}

func TestDetectHardcodedSecret_LongKey(t *testing.T) {
	longKey := "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	if !detectHardcodedSecret(longKey) {
		t.Error("Expected long key (40+ chars) to be detected as hardcoded secret")
	}
}

func TestDetectHardcodedSecret_EnvironmentVariable(t *testing.T) {
	envVar := "${TOKEN_VAR}"
	if detectHardcodedSecret(envVar) {
		t.Error("Expected environment variable reference to NOT be detected as hardcoded secret")
	}
}

func TestGetAuth_Bearer(t *testing.T) {
	config := &AuthConfig{
		Method: "bearer",
		Roles: map[string]*RoleAuth{
			"admin": {Token: "test-token-123"},
		},
	}

	auth, err := config.GetAuth("admin")
	if err != nil {
		t.Fatalf("GetAuth failed: %v", err)
	}

	expected := "Bearer test-token-123"
	if auth != expected {
		t.Errorf("Expected '%s', got '%s'", expected, auth)
	}
}

func TestGetAuth_APIKey(t *testing.T) {
	config := &AuthConfig{
		Method:   "api_key",
		Location: "header",
		KeyName:  "X-API-Key",
		Roles: map[string]*RoleAuth{
			"service": {APIKey: "api-key-456"},
		},
	}

	auth, err := config.GetAuth("service")
	if err != nil {
		t.Fatalf("GetAuth failed: %v", err)
	}

	expected := "api-key-456"
	if auth != expected {
		t.Errorf("Expected '%s', got '%s'", expected, auth)
	}
}

func TestGetAuth_Basic(t *testing.T) {
	config := &AuthConfig{
		Method: "basic",
		Roles: map[string]*RoleAuth{
			"user": {
				Username: "testuser",
				Password: "testpass",
			},
		},
	}

	auth, err := config.GetAuth("user")
	if err != nil {
		t.Fatalf("GetAuth failed: %v", err)
	}

	// Verify Basic auth format
	if !isValidBasicAuth(auth, "testuser", "testpass") {
		t.Errorf("Invalid Basic auth header: %s", auth)
	}
}

func TestGetAuth_RoleNotFound(t *testing.T) {
	config := &AuthConfig{
		Method: "bearer",
		Roles:  map[string]*RoleAuth{},
	}

	_, err := config.GetAuth("nonexistent")
	if err == nil {
		t.Fatal("Expected error for nonexistent role")
	}

	expectedMsg := "role not found: nonexistent"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestGetAuth_MissingToken(t *testing.T) {
	config := &AuthConfig{
		Method: "bearer",
		Roles: map[string]*RoleAuth{
			"admin": {Token: ""}, // Empty token
		},
	}

	_, err := config.GetAuth("admin")
	if err == nil {
		t.Fatal("Expected error for missing token")
	}

	expectedMsg := "role admin: missing token"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestGetAuth_UnsupportedMethod(t *testing.T) {
	config := &AuthConfig{
		Method: "unknown_method",
		Roles: map[string]*RoleAuth{
			"admin": {Token: "test"},
		},
	}

	_, err := config.GetAuth("admin")
	if err == nil {
		t.Fatal("Expected error for unsupported auth method")
	}

	expectedMsg := "unsupported auth method: unknown_method"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error '%s', got '%s'", expectedMsg, err.Error())
	}
}

// Helper function to validate Basic auth header
func isValidBasicAuth(header, username, password string) bool {
	expectedCreds := username + ":" + password
	expectedEncoded := base64.StdEncoding.EncodeToString([]byte(expectedCreds))
	expected := "Basic " + expectedEncoded
	return header == expected
}
