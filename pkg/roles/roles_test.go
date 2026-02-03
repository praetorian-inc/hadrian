package roles

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePermission_Valid(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected Permission
	}{
		{
			name:  "full permission",
			input: "read:users:own",
			expected: Permission{
				Raw:    "read:users:own",
				Action: "read",
				Object: "users",
				Scope:  "own",
			},
		},
		{
			name:  "wildcard action",
			input: "*:posts:all",
			expected: Permission{
				Raw:    "*:posts:all",
				Action: "*",
				Object: "posts",
				Scope:  "all",
			},
		},
		{
			name:  "wildcard object",
			input: "write:*:org",
			expected: Permission{
				Raw:    "write:*:org",
				Action: "write",
				Object: "*",
				Scope:  "org",
			},
		},
		{
			name:  "wildcard scope",
			input: "delete:comments:*",
			expected: Permission{
				Raw:    "delete:comments:*",
				Action: "delete",
				Object: "comments",
				Scope:  "*",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perm, err := ParsePermission(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, perm)
		})
	}
}

func TestParsePermission_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"missing parts", "read:users"},
		{"too many parts", "read:users:own:extra"},
		{"empty string", ""},
		{"single part", "read"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePermission(tt.input)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "permission must be")
		})
	}
}

func TestLoad_Success(t *testing.T) {
	config, err := Load("testdata/roles.yaml")
	require.NoError(t, err)
	require.NotNil(t, config)

	// Verify objects
	assert.Equal(t, []string{"users", "posts", "comments"}, config.Objects)

	// Verify roles loaded
	assert.Len(t, config.Roles, 3)

	// Verify admin role
	admin := findRole(config.Roles, "admin")
	require.NotNil(t, admin)
	assert.Len(t, admin.Permissions, 1)
	assert.Equal(t, "*:*:*", admin.Permissions[0].Raw)

	// Verify moderator role
	mod := findRole(config.Roles, "moderator")
	require.NotNil(t, mod)
	assert.Len(t, mod.Permissions, 3)

	// Verify user role
	user := findRole(config.Roles, "user")
	require.NotNil(t, user)
	assert.Len(t, user.Permissions, 4)
}

func TestLoad_InvalidYAML(t *testing.T) {
	// Create invalid YAML file
	tmpfile, err := os.CreateTemp("", "invalid-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.WriteString("invalid: yaml: content: [")
	require.NoError(t, err)
	tmpfile.Close()

	_, err = Load(tmpfile.Name())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
}

func TestLoad_InvalidPermissionFormat(t *testing.T) {
	// Create YAML with invalid permission format
	tmpfile, err := os.CreateTemp("", "invalid-perm-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	content := `objects:
  - users
roles:
  - name: invalid
    permissions:
      - "read:users"
`
	_, err = tmpfile.WriteString(content)
	require.NoError(t, err)
	tmpfile.Close()

	_, err = Load(tmpfile.Name())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid permission")
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("nonexistent.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read")
}

func TestValidate_Success(t *testing.T) {
	config := &RoleConfig{
		Objects: []string{"users", "posts"},
		Roles: []*Role{
			{
				Name: "test",
				Permissions: []Permission{
					{Raw: "read:users:own", Action: "read", Object: "users", Scope: "own"},
					{Raw: "write:posts:all", Action: "write", Object: "posts", Scope: "all"},
				},
			},
		},
	}

	err := config.Validate()
	assert.NoError(t, err)
}

func TestValidate_InvalidAction(t *testing.T) {
	config := &RoleConfig{
		Objects: []string{"users"},
		Roles: []*Role{
			{
				Name: "test",
				Permissions: []Permission{
					{Raw: "invalid:users:own", Action: "invalid", Object: "users", Scope: "own"},
				},
			},
		},
	}

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid action")
}

func TestValidate_UnknownObject(t *testing.T) {
	config := &RoleConfig{
		Objects: []string{"users"},
		Roles: []*Role{
			{
				Name: "test",
				Permissions: []Permission{
					{Raw: "read:unknown:own", Action: "read", Object: "unknown", Scope: "own"},
				},
			},
		},
	}

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown object")
}

func TestValidate_InvalidScope(t *testing.T) {
	config := &RoleConfig{
		Objects: []string{"users"},
		Roles: []*Role{
			{
				Name: "test",
				Permissions: []Permission{
					{Raw: "read:users:invalid", Action: "read", Object: "users", Scope: "invalid"},
				},
			},
		},
	}

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid scope")
}

func TestHasPermission_ExactMatch(t *testing.T) {
	role := &Role{
		Name: "test",
		Permissions: []Permission{
			{Raw: "read:users:own", Action: "read", Object: "users", Scope: "own"},
		},
	}

	assert.True(t, role.HasPermission("read", "users", "own"))
	assert.False(t, role.HasPermission("write", "users", "own"))
	assert.False(t, role.HasPermission("read", "posts", "own"))
	assert.False(t, role.HasPermission("read", "users", "all"))
}

func TestHasPermission_WildcardAction(t *testing.T) {
	role := &Role{
		Name: "test",
		Permissions: []Permission{
			{Raw: "*:users:own", Action: "*", Object: "users", Scope: "own"},
		},
	}

	assert.True(t, role.HasPermission("read", "users", "own"))
	assert.True(t, role.HasPermission("write", "users", "own"))
	assert.True(t, role.HasPermission("delete", "users", "own"))
	assert.False(t, role.HasPermission("read", "posts", "own"))
}

func TestHasPermission_WildcardObject(t *testing.T) {
	role := &Role{
		Name: "test",
		Permissions: []Permission{
			{Raw: "read:*:own", Action: "read", Object: "*", Scope: "own"},
		},
	}

	assert.True(t, role.HasPermission("read", "users", "own"))
	assert.True(t, role.HasPermission("read", "posts", "own"))
	assert.True(t, role.HasPermission("read", "comments", "own"))
	assert.False(t, role.HasPermission("write", "users", "own"))
}

func TestHasPermission_WildcardScope(t *testing.T) {
	role := &Role{
		Name: "test",
		Permissions: []Permission{
			{Raw: "read:users:*", Action: "read", Object: "users", Scope: "*"},
		},
	}

	assert.True(t, role.HasPermission("read", "users", "own"))
	assert.True(t, role.HasPermission("read", "users", "org"))
	assert.True(t, role.HasPermission("read", "users", "all"))
	assert.True(t, role.HasPermission("read", "users", "public"))
	assert.False(t, role.HasPermission("write", "users", "own"))
}

func TestMatches_AllCombinations(t *testing.T) {
	tests := []struct {
		name       string
		permission Permission
		action     string
		object     string
		scope      string
		expected   bool
	}{
		{
			name:       "exact match",
			permission: Permission{Action: "read", Object: "users", Scope: "own"},
			action:     "read",
			object:     "users",
			scope:      "own",
			expected:   true,
		},
		{
			name:       "wildcard all",
			permission: Permission{Action: "*", Object: "*", Scope: "*"},
			action:     "read",
			object:     "users",
			scope:      "own",
			expected:   true,
		},
		{
			name:       "scope all matches own",
			permission: Permission{Action: "read", Object: "users", Scope: "all"},
			action:     "read",
			object:     "users",
			scope:      "own",
			expected:   true,
		},
		{
			name:       "action mismatch",
			permission: Permission{Action: "read", Object: "users", Scope: "own"},
			action:     "write",
			object:     "users",
			scope:      "own",
			expected:   false,
		},
		{
			name:       "object mismatch",
			permission: Permission{Action: "read", Object: "users", Scope: "own"},
			action:     "read",
			object:     "posts",
			scope:      "own",
			expected:   false,
		},
		{
			name:       "scope mismatch",
			permission: Permission{Action: "read", Object: "users", Scope: "own"},
			action:     "read",
			object:     "users",
			scope:      "all",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.permission.Matches(tt.action, tt.object, tt.scope)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetRolesByPermissionLevel_Lower(t *testing.T) {
	config := &RoleConfig{
		Roles: []*Role{
			{Name: "limited", Level: 10, Permissions: []Permission{{}, {}}},           // Low privilege
			{Name: "moderate", Level: 50, Permissions: []Permission{{}, {}, {}}},      // Medium privilege
			{Name: "powerful", Level: 100, Permissions: []Permission{{}, {}, {}, {}}}, // High privilege
		},
	}

	lower := config.GetRolesByPermissionLevel("lower")
	// Median of [10,50,100] = 50
	// Lower means < 50
	assert.Len(t, lower, 1)
	assert.Equal(t, "limited", lower[0].Name)
}

func TestGetRolesByPermissionLevel_Higher(t *testing.T) {
	config := &RoleConfig{
		Roles: []*Role{
			{Name: "limited", Level: 10, Permissions: []Permission{{}, {}}},           // Low privilege
			{Name: "moderate", Level: 50, Permissions: []Permission{{}, {}, {}}},      // Medium privilege
			{Name: "powerful", Level: 100, Permissions: []Permission{{}, {}, {}, {}}}, // High privilege
		},
	}

	higher := config.GetRolesByPermissionLevel("higher")
	// Median of [10,50,100] = 50
	// Higher means >= 50
	assert.Len(t, higher, 2)
	names := []string{higher[0].Name, higher[1].Name}
	assert.Contains(t, names, "moderate")
	assert.Contains(t, names, "powerful")
}

func TestGetRolesByPermissionLevel_All(t *testing.T) {
	config := &RoleConfig{
		Roles: []*Role{
			{Name: "limited", Level: 10, Permissions: []Permission{{}}},
			{Name: "moderate", Level: 50, Permissions: []Permission{{}, {}}},
			{Name: "powerful", Level: 100, Permissions: []Permission{{}, {}, {}}},
		},
	}

	all := config.GetRolesByPermissionLevel("all")
	assert.Len(t, all, 3)
}

func TestGetRolesByPermissionLevel_BOLAScenario(t *testing.T) {
	// Real scenario: admin has 1 permission (*:*:all) but is highest privilege
	// users have 11 permissions but are lower privilege
	config := &RoleConfig{
		Roles: []*Role{
			{Name: "admin", Level: 100, Permissions: []Permission{{}}},      // 1 perm, level 100
			{Name: "user1", Level: 10, Permissions: make([]Permission, 11)}, // 11 perms, level 10
			{Name: "user2", Level: 10, Permissions: make([]Permission, 11)}, // 11 perms, level 10
			{Name: "anonymous", Level: 0, Permissions: []Permission{{}}},    // 1 perm, level 0
		},
	}

	// Median of [0, 10, 10, 100] = (10 + 10) / 2 = 10
	// Higher: >= 10 → admin (100), user1 (10), user2 (10)
	// Lower: < 10 → anonymous (0)

	higher := config.GetRolesByPermissionLevel("higher")
	assert.Len(t, higher, 3)
	names := []string{higher[0].Name, higher[1].Name, higher[2].Name}
	assert.Contains(t, names, "admin")
	assert.Contains(t, names, "user1")
	assert.Contains(t, names, "user2")

	lower := config.GetRolesByPermissionLevel("lower")
	assert.Len(t, lower, 1)
	assert.Equal(t, "anonymous", lower[0].Name)
}

func TestLoad_VulnerableAPIRoles(t *testing.T) {
	// Test loading the vulnerable-api roles.yaml with level field
	config, err := Load("../../testdata/vulnerable-api/roles.yaml")
	require.NoError(t, err)
	require.NotNil(t, config)

	// Verify roles loaded with correct levels
	admin := findRole(config.Roles, "admin")
	require.NotNil(t, admin)
	assert.Equal(t, 100, admin.Level)

	user1 := findRole(config.Roles, "user1")
	require.NotNil(t, user1)
	assert.Equal(t, 10, user1.Level)

	user2 := findRole(config.Roles, "user2")
	require.NotNil(t, user2)
	assert.Equal(t, 10, user2.Level)

	anonymous := findRole(config.Roles, "anonymous")
	require.NotNil(t, anonymous)
	assert.Equal(t, 0, anonymous.Level)

	// Verify GetRolesByPermissionLevel behavior
	// Median of [0, 10, 10, 100] = 10
	higher := config.GetRolesByPermissionLevel("higher")
	assert.Len(t, higher, 3) // admin, user1, user2

	lower := config.GetRolesByPermissionLevel("lower")
	assert.Len(t, lower, 1) // anonymous
	assert.Equal(t, "anonymous", lower[0].Name)
}

// Helper function
func findRole(roles []*Role, name string) *Role {
	for _, r := range roles {
		if r.Name == name {
			return r
		}
	}
	return nil
}
