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
			{Name: "limited", Permissions: []Permission{{}, {}}},          // 2 perms
			{Name: "moderate", Permissions: []Permission{{}, {}, {}}},     // 3 perms
			{Name: "powerful", Permissions: []Permission{{}, {}, {}, {}}}, // 4 perms
		},
	}

	lower := config.GetRolesByPermissionLevel("lower")
	// Median of [2,3,4] = 3
	// Lower means < 3
	assert.Len(t, lower, 1)
	assert.Equal(t, "limited", lower[0].Name)
}

func TestGetRolesByPermissionLevel_Higher(t *testing.T) {
	config := &RoleConfig{
		Roles: []*Role{
			{Name: "limited", Permissions: []Permission{{}, {}}},          // 2 perms
			{Name: "moderate", Permissions: []Permission{{}, {}, {}}},     // 3 perms
			{Name: "powerful", Permissions: []Permission{{}, {}, {}, {}}}, // 4 perms
		},
	}

	higher := config.GetRolesByPermissionLevel("higher")
	// Median of [2,3,4] = 3
	// Higher means >= 3
	assert.Len(t, higher, 2)
	names := []string{higher[0].Name, higher[1].Name}
	assert.Contains(t, names, "moderate")
	assert.Contains(t, names, "powerful")
}

func TestGetRolesByPermissionLevel_All(t *testing.T) {
	config := &RoleConfig{
		Roles: []*Role{
			{Name: "limited", Permissions: []Permission{{}}},
			{Name: "moderate", Permissions: []Permission{{}, {}}},
			{Name: "powerful", Permissions: []Permission{{}, {}, {}}},
		},
	}

	all := config.GetRolesByPermissionLevel("all")
	assert.Len(t, all, 3)
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
