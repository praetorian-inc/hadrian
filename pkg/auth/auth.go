package auth

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/log"
	"gopkg.in/yaml.v3"
)

// DefaultCookieName is the default cookie name used when cookie_name is not specified.
const DefaultCookieName = "session"

// validCookieNameRE matches RFC 6265 cookie-name tokens:
// 1*<any CHAR except CTLs, spaces, or separators: ( ) < > @ , ; : \ " / [ ] ? = { }>
var validCookieNameRE = regexp.MustCompile(`^[!#$%&'*+\-.0-9A-Z^_` + "`" + `a-z|~]+$`)

// validMethods is the set of supported auth methods.
var validMethods = map[string]bool{
	"bearer": true, "basic": true, "api_key": true, "cookie": true,
}

// AuthConfig represents auth.yaml configuration
type AuthConfig struct {
	Method string               `yaml:"method"` // bearer, api_key, basic, cookie
	Roles  map[string]*RoleAuth `yaml:"roles"`

	// API Key specific
	Location string `yaml:"location,omitempty"` // header or query
	KeyName  string `yaml:"key_name,omitempty"` // X-API-Key

	// Cookie specific
	CookieName string `yaml:"cookie_name,omitempty"` // e.g., session_id
}

type RoleAuth struct {
	// NoAuth suppresses the authentication header entirely.
	// Requests for this role are sent without any auth header.
	NoAuth bool `yaml:"no_auth,omitempty"`

	// Bearer token
	Token string `yaml:"token,omitempty"`

	// API Key
	APIKey string `yaml:"api_key,omitempty"`

	// Basic Auth
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`

	// Credentials is a raw, pre-combined string (not pre-encoded) that gets
	// base64-encoded for Basic auth, bypassing the username:password format.
	// For example, credentials: "admin:secret" sends the same as username/password,
	// while credentials: "" sends "Authorization: Basic " with empty base64.
	Credentials *string `yaml:"credentials,omitempty"`

	// Cookie
	Cookie string `yaml:"cookie,omitempty"`
}

// Load parses auth.yaml file (CR-3: Credential Security)
func Load(filePath string) (*AuthConfig, error) {
	// Check file permissions (CR-3)
	if info, err := os.Stat(filePath); err == nil {
		mode := info.Mode().Perm()
		if mode&0077 != 0 {
			log.Warn("SECURITY: %s has insecure permissions %o (should be 0600)", filePath, mode)
			log.Warn("Run: chmod 0600 %s", filePath)
		}
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read auth file: %w", err)
	}

	var config AuthConfig
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to parse auth config: %w", err)
	}

	// Validate method field
	if !validMethods[config.Method] {
		return nil, fmt.Errorf("unsupported auth method %q (valid: bearer, basic, api_key, cookie)", config.Method)
	}

	// Validate cookie_name against RFC 6265 (M-1: prevent header injection)
	if config.CookieName != "" && !validCookieNameRE.MatchString(config.CookieName) {
		return nil, fmt.Errorf("invalid cookie_name %q: must be a valid RFC 6265 token (no spaces, separators, or control characters)", config.CookieName)
	}

	// Expand environment variables (CR-3)
	// Only expand values that look like env var references (contain ${...})
	// to avoid corrupting values that contain literal $ characters
	for roleName, roleAuth := range config.Roles {
		roleAuth.Token = expandEnvSafe(roleAuth.Token)
		roleAuth.APIKey = expandEnvSafe(roleAuth.APIKey)
		roleAuth.Username = expandEnvSafe(roleAuth.Username)
		roleAuth.Password = expandEnvSafe(roleAuth.Password)
		roleAuth.Cookie = expandEnvSafe(roleAuth.Cookie)
		if roleAuth.Credentials != nil {
			expanded := expandEnvSafe(*roleAuth.Credentials)
			roleAuth.Credentials = &expanded
		}

		// Validate cookie value against CRLF injection (defense-in-depth)
		if strings.ContainsAny(roleAuth.Cookie, "\r\n\x00") {
			return nil, fmt.Errorf("role '%s': cookie value contains invalid characters (CR, LF, or NUL)", roleName)
		}

		// Detect hardcoded secrets (CR-3)
		if detectHardcodedSecret(roleAuth.Token) {
			log.Warn("SECURITY: Role '%s' has hardcoded token. Use environment variables: ${TOKEN_VAR}", roleName)
		}
		if detectHardcodedSecret(roleAuth.APIKey) {
			log.Warn("SECURITY: Role '%s' has hardcoded API key. Use environment variables: ${KEY_VAR}", roleName)
		}
		if detectHardcodedSecret(roleAuth.Cookie) {
			log.Warn("SECURITY: Role '%s' has hardcoded cookie. Use environment variables: ${COOKIE_VAR}", roleName)
		}
		if roleAuth.Credentials != nil && detectHardcodedSecret(*roleAuth.Credentials) {
			log.Warn("SECURITY: Role '%s' has hardcoded credentials. Use environment variables: ${CREDS_VAR}", roleName)
		}

		// Info about empty credentials — requests will be sent without authentication
		if roleAuth.NoAuth {
			log.Debug("Role '%s' has no_auth: true - requests will be sent without any authentication header", roleName)
		} else if roleAuth.Token == "" && roleAuth.APIKey == "" && roleAuth.Username == "" && roleAuth.Cookie == "" && roleAuth.Credentials == nil {
			log.Warn("Role '%s' has no credentials configured - requests will be sent without authentication", roleName)
		}
	}

	return &config, nil
}

// envBraceRE matches ${VAR_NAME} patterns for targeted expansion.
var envBraceRE = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnvSafe only expands ${VAR} references (not bare $VAR).
// Plain values with literal $ characters (e.g., passwords like "pa$$word") are returned unchanged.
// Warns when a referenced environment variable is not set.
func expandEnvSafe(value string) string {
	if !strings.Contains(value, "${") {
		return value
	}
	return envBraceRE.ReplaceAllStringFunc(value, func(match string) string {
		// Extract variable name from ${NAME}
		name := match[2 : len(match)-1]
		val, ok := os.LookupEnv(name)
		if !ok {
			log.Warn("environment variable %s referenced in auth config is not set — value will be empty", name)
		}
		return val
	})
}

// Pre-compiled patterns for hardcoded secret detection (CR-3)
var hardcodedSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$`), // JWT
	regexp.MustCompile(`^sk-[A-Za-z0-9]{32,}$`),                                  // OpenAI API key
	regexp.MustCompile(`^[A-Za-z0-9]{40,}$`),                                     // Generic long key
}

// detectHardcodedSecret identifies JWT, API keys, etc. (CR-3)
func detectHardcodedSecret(value string) bool {
	if strings.HasPrefix(value, "${") {
		return false // Environment variable reference
	}
	for _, re := range hardcodedSecretPatterns {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

// AuthInfo contains full authentication details for a role
type AuthInfo struct {
	Method   string // bearer, api_key, basic, cookie
	Location string // header, query (for api_key)
	KeyName  string // Header name (e.g., X-API-Key) or query parameter name
	Value    string // The actual auth value
}

// IsNoAuth returns true if the named role has no_auth: true.
// Use this to distinguish between "no authentication" and "empty credentials"
// since GetAuth returns "" for both no_auth roles and empty api_key values.
func (c *AuthConfig) IsNoAuth(roleName string) bool {
	roleAuth, ok := c.Roles[roleName]
	if !ok {
		return false
	}
	return roleAuth.NoAuth
}

// GetAuth builds HTTP authorization header for role.
// Returns ("", nil) when the role has no_auth: true — the caller should not set any auth header.
// Note: Use IsNoAuth() to distinguish no_auth from empty credentials.
func (c *AuthConfig) GetAuth(roleName string) (string, error) {
	roleAuth, ok := c.Roles[roleName]
	if !ok {
		return "", fmt.Errorf("role not found: %s", roleName)
	}

	if roleAuth.NoAuth {
		return "", nil
	}

	switch c.Method {
	case "bearer":
		return "Bearer " + roleAuth.Token, nil

	case "api_key":
		return roleAuth.APIKey, nil

	case "basic":
		if roleAuth.Credentials != nil {
			encoded := base64.StdEncoding.EncodeToString([]byte(*roleAuth.Credentials))
			return "Basic " + encoded, nil
		}
		credentials := roleAuth.Username + ":" + roleAuth.Password
		encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
		return "Basic " + encoded, nil

	case "cookie":
		cookieName := c.CookieName
		if cookieName == "" {
			cookieName = DefaultCookieName
		}
		return cookieName + "=" + roleAuth.Cookie, nil

	default:
		return "", fmt.Errorf("unsupported auth method: %s", c.Method)
	}
}

// GetAuthInfo returns full authentication info for role (method, location, key name, value).
// Returns (nil, nil) when the role has no_auth: true — the caller should not set any auth header.
func (c *AuthConfig) GetAuthInfo(roleName string) (*AuthInfo, error) {
	role, ok := c.Roles[roleName]
	if !ok {
		return nil, fmt.Errorf("role '%s' not found in auth config", roleName)
	}

	if role.NoAuth {
		return nil, nil
	}

	info := &AuthInfo{
		Method:   c.Method,
		Location: c.Location,
		KeyName:  c.KeyName,
	}

	switch c.Method {
	case "bearer":
		info.Value = "Bearer " + role.Token
	case "api_key":
		info.Value = role.APIKey
	case "basic":
		if role.Credentials != nil {
			creds := base64.StdEncoding.EncodeToString([]byte(*role.Credentials))
			info.Value = "Basic " + creds
		} else {
			creds := base64.StdEncoding.EncodeToString([]byte(role.Username + ":" + role.Password))
			info.Value = "Basic " + creds
		}
	case "cookie":
		cookieName := c.CookieName
		if cookieName == "" {
			cookieName = DefaultCookieName
		}
		info.KeyName = cookieName
		info.Value = cookieName + "=" + role.Cookie
	default:
		return nil, fmt.Errorf("unsupported auth method: %s", c.Method)
	}

	return info, nil
}
