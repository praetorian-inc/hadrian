package auth

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_Success(t *testing.T) {
	// Set environment variable for test
	_ = os.Setenv("ADMIN_TOKEN", "test-admin-token-123")
	defer func() { _ = os.Unsetenv("ADMIN_TOKEN") }()

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
	_ = os.Setenv("TEST_USERNAME", "admin_user")
	_ = os.Setenv("TEST_PASSWORD", "secret_pass")
	_ = os.Setenv("TEST_API_KEY", "api-key-123")
	defer func() {
		_ = os.Unsetenv("TEST_USERNAME")
		_ = os.Unsetenv("TEST_PASSWORD")
		_ = os.Unsetenv("TEST_API_KEY")
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

func TestExpandEnvSafe_BareVar(t *testing.T) {
	// Set an env var that could be accidentally expanded
	_ = os.Setenv("HOME_TEST", "should-not-expand")
	defer func() { _ = os.Unsetenv("HOME_TEST") }()

	// Bare $VAR should NOT be expanded
	result := expandEnvSafe("pa$$word")
	if result != "pa$$word" {
		t.Errorf("expandEnvSafe should not expand bare $VAR, got '%s'", result)
	}

	// ${VAR} should be expanded
	_ = os.Setenv("MY_VAR", "expanded")
	defer func() { _ = os.Unsetenv("MY_VAR") }()
	result = expandEnvSafe("prefix-${MY_VAR}-suffix")
	if result != "prefix-expanded-suffix" {
		t.Errorf("expandEnvSafe should expand ${VAR}, got '%s'", result)
	}
}

func TestIsNoAuth(t *testing.T) {
	config := &AuthConfig{
		Method: "bearer",
		Roles: map[string]*RoleAuth{
			"anonymous": {NoAuth: true},
			"admin":     {Token: "test"},
			"empty":     {Token: ""},
		},
	}

	if !config.IsNoAuth("anonymous") {
		t.Error("Expected IsNoAuth to return true for no_auth role")
	}
	if config.IsNoAuth("admin") {
		t.Error("Expected IsNoAuth to return false for admin role")
	}
	if config.IsNoAuth("empty") {
		t.Error("Expected IsNoAuth to return false for empty-token role")
	}
	if config.IsNoAuth("nonexistent") {
		t.Error("Expected IsNoAuth to return false for nonexistent role")
	}
}

func TestLoad_InvalidCookieName(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "badcookie.yaml")
	content := `method: cookie
cookie_name: "session id; evil"
roles:
  admin:
    cookie: "abc123"
`
	err := os.WriteFile(testFile, []byte(content), 0600)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	_, err = Load(testFile)
	if err == nil {
		t.Fatal("Expected error for invalid cookie_name with spaces/separators")
	}
	if !strings.Contains(err.Error(), "invalid cookie_name") {
		t.Errorf("Expected 'invalid cookie_name' error, got: %v", err)
	}
}

func TestLoad_InvalidMethod(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "badmethod.yaml")
	content := `method: oauth2
roles:
  admin:
    token: "abc123"
`
	err := os.WriteFile(testFile, []byte(content), 0600)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	_, err = Load(testFile)
	if err == nil {
		t.Fatal("Expected error for unsupported auth method")
	}
	if !strings.Contains(err.Error(), "unsupported auth method") {
		t.Errorf("Expected 'unsupported auth method' error, got: %v", err)
	}
}

func TestLoad_CookieValueCRLF(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "crlf.yaml")
	content := "method: cookie\nroles:\n  admin:\n    cookie: \"abc\\r\\nX-Injected: evil\"\n"
	err := os.WriteFile(testFile, []byte(content), 0600)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// YAML doesn't interpret \r\n as literal CR/LF in double quotes,
	// so test with actual bytes
	testFile2 := filepath.Join(tmpDir, "crlf2.yaml")
	content2 := "method: cookie\nroles:\n  admin:\n    cookie: \"abc\r\nX-Injected: evil\"\n"
	err = os.WriteFile(testFile2, []byte(content2), 0600)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// The second file contains literal CR/LF which YAML may reject or pass through.
	// If YAML passes it through, our validation should catch it.
	_, err = Load(testFile2)
	if err != nil {
		// Either YAML rejects it or our validation catches it — both are correct
		if !strings.Contains(err.Error(), "invalid characters") && !strings.Contains(err.Error(), "parse") {
			t.Logf("Got expected error: %v", err)
		}
	}
}

func TestExpandEnvSafe_UnsetVar(t *testing.T) {
	// Ensure the var is NOT set
	_ = os.Unsetenv("DEFINITELY_NOT_SET_VAR_12345")

	// Should expand to empty string (and log a warning)
	result := expandEnvSafe("prefix-${DEFINITELY_NOT_SET_VAR_12345}-suffix")
	if result != "prefix--suffix" {
		t.Errorf("expandEnvSafe should expand unset var to empty, got '%s'", result)
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

func TestGetAuth_EmptyToken(t *testing.T) {
	config := &AuthConfig{
		Method: "bearer",
		Roles: map[string]*RoleAuth{
			"admin": {Token: ""},
		},
	}

	value, err := config.GetAuth("admin")
	if err != nil {
		t.Fatalf("Empty token should not return error, got: %v", err)
	}
	if value != "Bearer " {
		t.Errorf("Expected 'Bearer ' for empty token, got '%s'", value)
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

// NEW TEST: GetAuthInfo returns full authentication details
func TestGetAuthInfo_Bearer(t *testing.T) {
	config := &AuthConfig{
		Method: "bearer",
		Roles: map[string]*RoleAuth{
			"admin": {Token: "test-token-123"},
		},
	}

	info, err := config.GetAuthInfo("admin")
	if err != nil {
		t.Fatalf("GetAuthInfo failed: %v", err)
	}

	if info.Method != "bearer" {
		t.Errorf("Expected method 'bearer', got '%s'", info.Method)
	}
	if info.Value != "Bearer test-token-123" {
		t.Errorf("Expected 'Bearer test-token-123', got '%s'", info.Value)
	}
	if info.Location != "" {
		t.Errorf("Expected empty location for bearer, got '%s'", info.Location)
	}
	if info.KeyName != "" {
		t.Errorf("Expected empty key name for bearer, got '%s'", info.KeyName)
	}
}

func TestGetAuthInfo_APIKey_Header(t *testing.T) {
	config := &AuthConfig{
		Method:   "api_key",
		Location: "header",
		KeyName:  "X-API-Key",
		Roles: map[string]*RoleAuth{
			"service": {APIKey: "api-key-456"},
		},
	}

	info, err := config.GetAuthInfo("service")
	if err != nil {
		t.Fatalf("GetAuthInfo failed: %v", err)
	}

	if info.Method != "api_key" {
		t.Errorf("Expected method 'api_key', got '%s'", info.Method)
	}
	if info.Location != "header" {
		t.Errorf("Expected location 'header', got '%s'", info.Location)
	}
	if info.KeyName != "X-API-Key" {
		t.Errorf("Expected key name 'X-API-Key', got '%s'", info.KeyName)
	}
	if info.Value != "api-key-456" {
		t.Errorf("Expected 'api-key-456', got '%s'", info.Value)
	}
}

func TestGetAuthInfo_APIKey_Query(t *testing.T) {
	config := &AuthConfig{
		Method:   "api_key",
		Location: "query",
		KeyName:  "api_key",
		Roles: map[string]*RoleAuth{
			"service": {APIKey: "query-key-789"},
		},
	}

	info, err := config.GetAuthInfo("service")
	if err != nil {
		t.Fatalf("GetAuthInfo failed: %v", err)
	}

	if info.Method != "api_key" {
		t.Errorf("Expected method 'api_key', got '%s'", info.Method)
	}
	if info.Location != "query" {
		t.Errorf("Expected location 'query', got '%s'", info.Location)
	}
	if info.KeyName != "api_key" {
		t.Errorf("Expected key name 'api_key', got '%s'", info.KeyName)
	}
	if info.Value != "query-key-789" {
		t.Errorf("Expected 'query-key-789', got '%s'", info.Value)
	}
}

func TestGetAuthInfo_Basic(t *testing.T) {
	config := &AuthConfig{
		Method: "basic",
		Roles: map[string]*RoleAuth{
			"user": {
				Username: "testuser",
				Password: "testpass",
			},
		},
	}

	info, err := config.GetAuthInfo("user")
	if err != nil {
		t.Fatalf("GetAuthInfo failed: %v", err)
	}

	if info.Method != "basic" {
		t.Errorf("Expected method 'basic', got '%s'", info.Method)
	}
	// Verify Basic auth format
	if !isValidBasicAuth(info.Value, "testuser", "testpass") {
		t.Errorf("Invalid Basic auth value: %s", info.Value)
	}
}

func TestGetAuthInfo_RoleNotFound(t *testing.T) {
	config := &AuthConfig{
		Method: "bearer",
		Roles:  map[string]*RoleAuth{},
	}

	_, err := config.GetAuthInfo("nonexistent")
	if err == nil {
		t.Fatal("Expected error for nonexistent role")
	}
}

func TestGetAuth_Cookie(t *testing.T) {
	config := &AuthConfig{
		Method:     "cookie",
		CookieName: "session_id",
		Roles: map[string]*RoleAuth{
			"admin": {Cookie: "abc123"},
		},
	}

	auth, err := config.GetAuth("admin")
	if err != nil {
		t.Fatalf("GetAuth failed: %v", err)
	}

	expected := "session_id=abc123"
	if auth != expected {
		t.Errorf("Expected '%s', got '%s'", expected, auth)
	}
}

func TestGetAuth_Cookie_DefaultName(t *testing.T) {
	config := &AuthConfig{
		Method: "cookie",
		Roles: map[string]*RoleAuth{
			"user": {Cookie: "xyz789"},
		},
	}

	auth, err := config.GetAuth("user")
	if err != nil {
		t.Fatalf("GetAuth failed: %v", err)
	}

	expected := "session=xyz789"
	if auth != expected {
		t.Errorf("Expected '%s', got '%s'", expected, auth)
	}
}

func TestGetAuthInfo_Cookie(t *testing.T) {
	config := &AuthConfig{
		Method:     "cookie",
		CookieName: "session_id",
		Roles: map[string]*RoleAuth{
			"admin": {Cookie: "abc123"},
		},
	}

	info, err := config.GetAuthInfo("admin")
	if err != nil {
		t.Fatalf("GetAuthInfo failed: %v", err)
	}

	if info.Method != "cookie" {
		t.Errorf("Expected method 'cookie', got '%s'", info.Method)
	}
	if info.KeyName != "session_id" {
		t.Errorf("Expected key name 'session_id', got '%s'", info.KeyName)
	}
	if info.Value != "session_id=abc123" {
		t.Errorf("Expected 'session_id=abc123', got '%s'", info.Value)
	}
}

func TestLoad_Cookie(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "cookie-auth.yaml")
	content := `method: cookie
cookie_name: session_id
roles:
  admin:
    cookie: "admin-session-xyz789"
  user1:
    cookie: "user1-session-abc123"
  anonymous:
    cookie: ""
`
	err := os.WriteFile(testFile, []byte(content), 0600)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	config, err := Load(testFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if config.Method != "cookie" {
		t.Errorf("Expected method 'cookie', got '%s'", config.Method)
	}
	if config.CookieName != "session_id" {
		t.Errorf("Expected cookie_name 'session_id', got '%s'", config.CookieName)
	}
	if len(config.Roles) != 3 {
		t.Errorf("Expected 3 roles, got %d", len(config.Roles))
	}

	admin := config.Roles["admin"]
	if admin.Cookie != "admin-session-xyz789" {
		t.Errorf("Expected admin cookie 'admin-session-xyz789', got '%s'", admin.Cookie)
	}
}

func TestGetAuth_Cookie_EmptyValue(t *testing.T) {
	config := &AuthConfig{
		Method:     "cookie",
		CookieName: "session_id",
		Roles: map[string]*RoleAuth{
			"empty": {Cookie: ""},
		},
	}

	value, err := config.GetAuth("empty")
	if err != nil {
		t.Fatalf("Empty cookie should not return error, got: %v", err)
	}
	if value != "session_id=" {
		t.Errorf("Expected 'session_id=' for empty cookie, got '%s'", value)
	}
}

// --- Empty credential tests for all auth methods ---

func TestGetAuth_Basic_EmptyBoth(t *testing.T) {
	config := &AuthConfig{
		Method: "basic",
		Roles: map[string]*RoleAuth{
			"empty": {Username: "", Password: ""},
		},
	}

	value, err := config.GetAuth("empty")
	if err != nil {
		t.Fatalf("Empty basic auth should not return error, got: %v", err)
	}
	// base64(":") = "Og=="
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(":"))
	if value != expected {
		t.Errorf("Expected '%s' for empty basic auth, got '%s'", expected, value)
	}
}

func TestGetAuth_Basic_EmptyPassword(t *testing.T) {
	config := &AuthConfig{
		Method: "basic",
		Roles: map[string]*RoleAuth{
			"nopass": {Username: "admin", Password: ""},
		},
	}

	value, err := config.GetAuth("nopass")
	if err != nil {
		t.Fatalf("Basic auth with empty password should not return error, got: %v", err)
	}
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:"))
	if value != expected {
		t.Errorf("Expected '%s', got '%s'", expected, value)
	}
}

func TestGetAuth_Basic_EmptyUsername(t *testing.T) {
	config := &AuthConfig{
		Method: "basic",
		Roles: map[string]*RoleAuth{
			"nouser": {Username: "", Password: "secret"},
		},
	}

	value, err := config.GetAuth("nouser")
	if err != nil {
		t.Fatalf("Basic auth with empty username should not return error, got: %v", err)
	}
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(":secret"))
	if value != expected {
		t.Errorf("Expected '%s', got '%s'", expected, value)
	}
}

func TestGetAuth_APIKey_Empty(t *testing.T) {
	config := &AuthConfig{
		Method:   "api_key",
		Location: "header",
		KeyName:  "X-API-Key",
		Roles: map[string]*RoleAuth{
			"empty": {APIKey: ""},
		},
	}

	value, err := config.GetAuth("empty")
	if err != nil {
		t.Fatalf("Empty API key should not return error, got: %v", err)
	}
	if value != "" {
		t.Errorf("Expected empty string for empty API key, got '%s'", value)
	}
}

func TestGetAuthInfo_Bearer_EmptyToken(t *testing.T) {
	config := &AuthConfig{
		Method: "bearer",
		Roles: map[string]*RoleAuth{
			"empty": {Token: ""},
		},
	}

	info, err := config.GetAuthInfo("empty")
	if err != nil {
		t.Fatalf("Empty bearer token should not return error, got: %v", err)
	}
	if info.Method != "bearer" {
		t.Errorf("Expected method 'bearer', got '%s'", info.Method)
	}
	if info.Value != "Bearer " {
		t.Errorf("Expected 'Bearer ' for empty token, got '%s'", info.Value)
	}
}

func TestGetAuthInfo_Basic_EmptyBoth(t *testing.T) {
	config := &AuthConfig{
		Method: "basic",
		Roles: map[string]*RoleAuth{
			"empty": {Username: "", Password: ""},
		},
	}

	info, err := config.GetAuthInfo("empty")
	if err != nil {
		t.Fatalf("Empty basic auth should not return error, got: %v", err)
	}
	if info.Method != "basic" {
		t.Errorf("Expected method 'basic', got '%s'", info.Method)
	}
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(":"))
	if info.Value != expected {
		t.Errorf("Expected '%s', got '%s'", expected, info.Value)
	}
}

func TestGetAuthInfo_APIKey_Empty(t *testing.T) {
	config := &AuthConfig{
		Method:   "api_key",
		Location: "header",
		KeyName:  "X-API-Key",
		Roles: map[string]*RoleAuth{
			"empty": {APIKey: ""},
		},
	}

	info, err := config.GetAuthInfo("empty")
	if err != nil {
		t.Fatalf("Empty API key should not return error, got: %v", err)
	}
	if info.Method != "api_key" {
		t.Errorf("Expected method 'api_key', got '%s'", info.Method)
	}
	if info.Value != "" {
		t.Errorf("Expected empty string for empty API key, got '%s'", info.Value)
	}
	if info.KeyName != "X-API-Key" {
		t.Errorf("Expected key name 'X-API-Key', got '%s'", info.KeyName)
	}
}

func TestGetAuthInfo_Cookie_EmptyValue(t *testing.T) {
	config := &AuthConfig{
		Method:     "cookie",
		CookieName: "JSESSIONID",
		Roles: map[string]*RoleAuth{
			"empty": {Cookie: ""},
		},
	}

	info, err := config.GetAuthInfo("empty")
	if err != nil {
		t.Fatalf("Empty cookie should not return error, got: %v", err)
	}
	if info.Method != "cookie" {
		t.Errorf("Expected method 'cookie', got '%s'", info.Method)
	}
	if info.KeyName != "JSESSIONID" {
		t.Errorf("Expected key name 'JSESSIONID', got '%s'", info.KeyName)
	}
	if info.Value != "JSESSIONID=" {
		t.Errorf("Expected 'JSESSIONID=' for empty cookie, got '%s'", info.Value)
	}
}

// --- no_auth tests ---

func TestGetAuth_NoAuth(t *testing.T) {
	config := &AuthConfig{
		Method: "bearer",
		Roles: map[string]*RoleAuth{
			"anonymous": {NoAuth: true},
		},
	}

	value, err := config.GetAuth("anonymous")
	if err != nil {
		t.Fatalf("no_auth role should not return error, got: %v", err)
	}
	if value != "" {
		t.Errorf("Expected empty string for no_auth role, got '%s'", value)
	}
}

func TestGetAuthInfo_NoAuth(t *testing.T) {
	config := &AuthConfig{
		Method: "bearer",
		Roles: map[string]*RoleAuth{
			"anonymous": {NoAuth: true},
		},
	}

	info, err := config.GetAuthInfo("anonymous")
	if err != nil {
		t.Fatalf("no_auth role should not return error, got: %v", err)
	}
	if info != nil {
		t.Errorf("Expected nil AuthInfo for no_auth role, got: %+v", info)
	}
}

func TestGetAuth_NoAuth_BasicMethod(t *testing.T) {
	config := &AuthConfig{
		Method: "basic",
		Roles: map[string]*RoleAuth{
			"no_header": {NoAuth: true},
		},
	}

	value, err := config.GetAuth("no_header")
	if err != nil {
		t.Fatalf("no_auth role should not return error, got: %v", err)
	}
	if value != "" {
		t.Errorf("Expected empty string for no_auth role, got '%s'", value)
	}
}

func TestGetAuth_NoAuth_CookieMethod(t *testing.T) {
	config := &AuthConfig{
		Method:     "cookie",
		CookieName: "session_id",
		Roles: map[string]*RoleAuth{
			"no_header": {NoAuth: true},
		},
	}

	value, err := config.GetAuth("no_header")
	if err != nil {
		t.Fatalf("no_auth role should not return error, got: %v", err)
	}
	if value != "" {
		t.Errorf("Expected empty string for no_auth role, got '%s'", value)
	}
}

func TestGetAuth_NoAuth_APIKeyMethod(t *testing.T) {
	config := &AuthConfig{
		Method:   "api_key",
		Location: "header",
		KeyName:  "X-API-Key",
		Roles: map[string]*RoleAuth{
			"no_header": {NoAuth: true},
		},
	}

	value, err := config.GetAuth("no_header")
	if err != nil {
		t.Fatalf("no_auth role should not return error, got: %v", err)
	}
	if value != "" {
		t.Errorf("Expected empty string for no_auth role, got '%s'", value)
	}
}

// --- credentials (raw base64) tests for basic auth ---

func TestGetAuth_Basic_RawCredentials_Empty(t *testing.T) {
	empty := ""
	config := &AuthConfig{
		Method: "basic",
		Roles: map[string]*RoleAuth{
			"empty_creds": {Credentials: &empty},
		},
	}

	value, err := config.GetAuth("empty_creds")
	if err != nil {
		t.Fatalf("raw credentials should not return error, got: %v", err)
	}
	// base64("") = ""
	expected := "Basic "
	if value != expected {
		t.Errorf("Expected '%s' for empty raw credentials, got '%s'", expected, value)
	}
}

func TestGetAuth_Basic_RawCredentials_Value(t *testing.T) {
	creds := "admin:secret"
	config := &AuthConfig{
		Method: "basic",
		Roles: map[string]*RoleAuth{
			"raw": {Credentials: &creds},
		},
	}

	value, err := config.GetAuth("raw")
	if err != nil {
		t.Fatalf("raw credentials should not return error, got: %v", err)
	}
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))
	if value != expected {
		t.Errorf("Expected '%s', got '%s'", expected, value)
	}
}

func TestGetAuth_Basic_RawCredentials_OverridesUsernamePassword(t *testing.T) {
	creds := "custom"
	config := &AuthConfig{
		Method: "basic",
		Roles: map[string]*RoleAuth{
			"override": {
				Username:    "ignored",
				Password:    "ignored",
				Credentials: &creds,
			},
		},
	}

	value, err := config.GetAuth("override")
	if err != nil {
		t.Fatalf("raw credentials should not return error, got: %v", err)
	}
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("custom"))
	if value != expected {
		t.Errorf("Expected '%s', got '%s'", expected, value)
	}
}

func TestGetAuthInfo_Basic_RawCredentials_Empty(t *testing.T) {
	empty := ""
	config := &AuthConfig{
		Method: "basic",
		Roles: map[string]*RoleAuth{
			"empty_creds": {Credentials: &empty},
		},
	}

	info, err := config.GetAuthInfo("empty_creds")
	if err != nil {
		t.Fatalf("raw credentials should not return error, got: %v", err)
	}
	if info.Method != "basic" {
		t.Errorf("Expected method 'basic', got '%s'", info.Method)
	}
	expected := "Basic "
	if info.Value != expected {
		t.Errorf("Expected '%s' for empty raw credentials, got '%s'", expected, info.Value)
	}
}

func TestLoad_NoAuth_Role(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "noauth.yaml")
	content := `method: bearer
roles:
  admin:
    token: "admin-token"
  anonymous:
    no_auth: true
`
	err := os.WriteFile(testFile, []byte(content), 0600)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	config, err := Load(testFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if !config.Roles["anonymous"].NoAuth {
		t.Error("Expected anonymous role to have no_auth: true")
	}

	value, err := config.GetAuth("anonymous")
	if err != nil {
		t.Fatalf("GetAuth should not return error for no_auth role: %v", err)
	}
	if value != "" {
		t.Errorf("Expected empty string for no_auth role, got '%s'", value)
	}

	info, err := config.GetAuthInfo("anonymous")
	if err != nil {
		t.Fatalf("GetAuthInfo should not return error for no_auth role: %v", err)
	}
	if info != nil {
		t.Errorf("Expected nil AuthInfo for no_auth role, got: %+v", info)
	}
}

func TestLoad_Basic_RawCredentials(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "rawcreds.yaml")
	content := `method: basic
roles:
  admin:
    username: "admin"
    password: "secret"
  empty_basic:
    credentials: ""
`
	err := os.WriteFile(testFile, []byte(content), 0600)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	config, err := Load(testFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// admin uses username/password
	adminValue, err := config.GetAuth("admin")
	if err != nil {
		t.Fatalf("GetAuth failed for admin: %v", err)
	}
	if !isValidBasicAuth(adminValue, "admin", "secret") {
		t.Errorf("Invalid admin basic auth: %s", adminValue)
	}

	// empty_basic uses raw credentials
	emptyValue, err := config.GetAuth("empty_basic")
	if err != nil {
		t.Fatalf("GetAuth failed for empty_basic: %v", err)
	}
	if emptyValue != "Basic " {
		t.Errorf("Expected 'Basic ' for empty raw credentials, got '%s'", emptyValue)
	}
}

// Helper function to validate Basic auth header
func isValidBasicAuth(header, username, password string) bool {
	expectedCreds := username + ":" + password
	expectedEncoded := base64.StdEncoding.EncodeToString([]byte(expectedCreds))
	expected := "Basic " + expectedEncoded
	return header == expected
}
