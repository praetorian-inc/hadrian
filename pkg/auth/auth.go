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
	// Bearer token
	Token string `yaml:"token,omitempty"`

	// API Key
	APIKey string `yaml:"api_key,omitempty"`

	// Basic Auth
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`

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

	// Expand environment variables (CR-3)
	for roleName, roleAuth := range config.Roles {
		roleAuth.Token = os.ExpandEnv(roleAuth.Token)
		roleAuth.APIKey = os.ExpandEnv(roleAuth.APIKey)
		roleAuth.Username = os.ExpandEnv(roleAuth.Username)
		roleAuth.Password = os.ExpandEnv(roleAuth.Password)
		roleAuth.Cookie = os.ExpandEnv(roleAuth.Cookie)

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

		// Warn about empty credentials (will cause tests to be skipped)
		if roleAuth.Token == "" && roleAuth.APIKey == "" && roleAuth.Username == "" && roleAuth.Cookie == "" {
			log.Warn("Role '%s' has no credentials configured - tests for this role will be skipped", roleName)
		}
	}

	return &config, nil
}

// detectHardcodedSecret identifies JWT, API keys, etc. (CR-3)
func detectHardcodedSecret(value string) bool {
	if strings.HasPrefix(value, "${") {
		return false // Environment variable reference
	}

	patterns := []string{
		`^eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$`, // JWT
		`^sk-[A-Za-z0-9]{32,}$`,                                  // OpenAI API key
		`^[A-Za-z0-9]{40,}$`,                                     // Generic long key
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, value); matched {
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

// GetAuth builds HTTP authorization header for role
func (c *AuthConfig) GetAuth(roleName string) (string, error) {
	roleAuth, ok := c.Roles[roleName]
	if !ok {
		return "", fmt.Errorf("role not found: %s", roleName)
	}

	switch c.Method {
	case "bearer":
		if roleAuth.Token == "" {
			return "", fmt.Errorf("role %s: missing token", roleName)
		}
		return "Bearer " + roleAuth.Token, nil

	case "api_key":
		if roleAuth.APIKey == "" {
			return "", fmt.Errorf("role %s: missing api_key", roleName)
		}
		// Header vs query param handled by caller
		return roleAuth.APIKey, nil

	case "basic":
		if roleAuth.Username == "" || roleAuth.Password == "" {
			return "", fmt.Errorf("role %s: missing username or password", roleName)
		}
		credentials := roleAuth.Username + ":" + roleAuth.Password
		encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
		return "Basic " + encoded, nil

	case "cookie":
		cookieName := c.CookieName
		if cookieName == "" {
			cookieName = "session"
		}
		return cookieName + "=" + roleAuth.Cookie, nil

	default:
		return "", fmt.Errorf("unsupported auth method: %s", c.Method)
	}
}

// GetAuthInfo returns full authentication info for role (method, location, key name, value)
func (c *AuthConfig) GetAuthInfo(roleName string) (*AuthInfo, error) {
	role, ok := c.Roles[roleName]
	if !ok {
		return nil, fmt.Errorf("role '%s' not found in auth config", roleName)
	}

	info := &AuthInfo{
		Method:   c.Method,
		Location: c.Location,
		KeyName:  c.KeyName,
	}

	switch c.Method {
	case "bearer":
		if role.Token == "" {
			return nil, fmt.Errorf("role '%s' has no bearer token", roleName)
		}
		info.Value = "Bearer " + role.Token
	case "api_key":
		if role.APIKey == "" {
			return nil, fmt.Errorf("role '%s' has no API key", roleName)
		}
		info.Value = role.APIKey
	case "basic":
		if role.Username == "" || role.Password == "" {
			return nil, fmt.Errorf("role '%s' missing basic auth credentials", roleName)
		}
		creds := base64.StdEncoding.EncodeToString([]byte(role.Username + ":" + role.Password))
		info.Value = "Basic " + creds
	case "cookie":
		cookieName := c.CookieName
		if cookieName == "" {
			cookieName = "session"
		}
		info.KeyName = cookieName
		info.Value = cookieName + "=" + role.Cookie
	default:
		return nil, fmt.Errorf("unsupported auth method: %s", c.Method)
	}

	return info, nil
}
