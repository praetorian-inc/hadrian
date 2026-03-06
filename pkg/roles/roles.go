package roles

import (
	"fmt"
	"os"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/log"

	"gopkg.in/yaml.v3"
)

// RoleConfig represents roles.yaml configuration
type RoleConfig struct {
	Roles     []*Role     `yaml:"roles"`
	Objects   []string    `yaml:"objects"`   // Resource types for validation
	Endpoints []*Endpoint `yaml:"endpoints"` // Endpoint → object mappings
}

type Role struct {
	Name        string       `yaml:"name"`
	ID          string       `yaml:"id"`          // User ID for this role (for BOLA testing)
	Username    string       `yaml:"username"`    // Username for this role
	Level       int          `yaml:"level"`       // Explicit privilege level (higher = more privilege)
	Description string       `yaml:"description"` // Human-readable description
	RawPerms    []string     `yaml:"permissions"` // Raw permission strings from YAML
	Permissions []Permission `yaml:"-"`           // Parsed permissions
}

type Permission struct {
	Raw    string // Original: "read:users:own"
	Action string // "read"
	Object string // "users"
	Scope  string // "own"
}

type Endpoint struct {
	Path       string `yaml:"path"`
	Object     string `yaml:"object"`
	OwnerField string `yaml:"owner_field"`
}

// Load parses roles.yaml file
func Load(filePath string) (*RoleConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read roles file: %w", err)
	}

	var config RoleConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse roles YAML: %w", err)
	}

	// Parse permission strings
	for _, role := range config.Roles {
		role.Permissions = make([]Permission, len(role.RawPerms))
		for i, permStr := range role.RawPerms {
			perm, err := ParsePermission(permStr)
			if err != nil {
				return nil, fmt.Errorf("invalid permission for role %s: %w", role.Name, err)
			}
			role.Permissions[i] = perm
		}
	}

	// Validate permissions reference valid objects
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &config, nil
}

// ParsePermission parses "<action>:<object>:<scope>" format
func ParsePermission(permStr string) (Permission, error) {
	parts := strings.Split(permStr, ":")
	if len(parts) != 3 {
		return Permission{}, fmt.Errorf("permission must be <action>:<object>:<scope>, got: %s", permStr)
	}

	return Permission{
		Raw:    permStr,
		Action: parts[0],
		Object: parts[1],
		Scope:  parts[2],
	}, nil
}

// Validate checks configuration for errors
func (c *RoleConfig) Validate() error {
	// Build valid object set
	validObjects := make(map[string]bool)
	for _, obj := range c.Objects {
		validObjects[obj] = true
	}
	validObjects["*"] = true // Wildcard is always valid

	// Validate each role's permissions
	for _, role := range c.Roles {
		for _, perm := range role.Permissions {
			// Validate action
			validActions := []string{"read", "write", "delete", "execute", "*"}
			if !contains(validActions, perm.Action) {
				return fmt.Errorf("role %s: invalid action '%s' (valid: %v)", role.Name, perm.Action, validActions)
			}

			// Validate object
			if !validObjects[perm.Object] {
				return fmt.Errorf("role %s: unknown object '%s' (defined objects: %v)", role.Name, perm.Object, c.Objects)
			}

			// Validate scope
			validScopes := []string{"public", "own", "org", "all", "*"}
			if !contains(validScopes, perm.Scope) {
				return fmt.Errorf("role %s: invalid scope '%s' (valid: %v)", role.Name, perm.Scope, validScopes)
			}
		}
	}

	return nil
}

// HasPermission checks if role has specific permission
func (r *Role) HasPermission(action, object, scope string) bool {
	for _, perm := range r.Permissions {
		if perm.Matches(action, object, scope) {
			return true
		}
	}
	return false
}

// Matches checks if permission matches criteria (with wildcard support)
func (p *Permission) Matches(action, object, scope string) bool {
	if p.Action != action && p.Action != "*" {
		return false
	}

	if p.Object != object && p.Object != "*" {
		return false
	}

	if p.Scope != scope && p.Scope != "*" && p.Scope != "all" {
		return false
	}

	return true
}

// GetRolesByPermissionLevel returns roles grouped by privilege level
func (c *RoleConfig) GetRolesByPermissionLevel(level string) []*Role {
	switch level {
	case "lower", "higher", "all":
		// Return all roles — the execution loop filters by relative level
		// (attacker.Level < victim.Level) to determine valid pairings
		result := make([]*Role, len(c.Roles))
		copy(result, c.Roles)
		return result
	case "none":
		// "none" means no authenticated role (anonymous attacker) — return empty slice
		return []*Role{}
	default:
		log.Warn("unrecognized permission level %q — returning no roles (check template for typos)", level)
		return []*Role{}
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
