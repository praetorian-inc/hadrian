package llm

import (
	"context"
	"testing"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClaudeClient_Name(t *testing.T) {
	// Arrange
	client := NewClaudeClient("test-key")

	// Act
	name := client.Name()

	// Assert
	assert.Equal(t, "claude", name)
}

func TestClaudeClient_Triage(t *testing.T) {
	// Arrange
	client := NewClaudeClient("test-key")

	attackerRole := &roles.Role{
		Name: "viewer",
		Permissions: []roles.Permission{
			{Raw: "read:users:own", Action: "read", Object: "users", Scope: "own"},
		},
	}

	victimRole := &roles.Role{
		Name: "admin",
		Permissions: []roles.Permission{
			{Raw: "read:users:all", Action: "read", Object: "users", Scope: "all"},
		},
	}

	finding := &model.Finding{
		Category: "API2",
		Method:   "GET",
		Endpoint: "/api/users/123",
		Evidence: model.Evidence{
			Response: model.HTTPResponse{
				StatusCode: 200,
				Body:       `{"id":"123","email":"user@example.com","role":"admin"}`,
			},
		},
		Timestamp: time.Now(),
	}

	req := &TriageRequest{
		Finding:      finding,
		AttackerRole: attackerRole,
		VictimRole:   victimRole,
	}

	// Act
	result, err := client.Triage(context.Background(), req)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "claude", result.Provider)
	assert.True(t, result.IsVulnerability) // Mock always returns true
	assert.GreaterOrEqual(t, result.Confidence, 0.0)
	assert.LessOrEqual(t, result.Confidence, 1.0)
	assert.NotEmpty(t, result.Reasoning)
}

func TestClaudeClient_BuildPrompt(t *testing.T) {
	// Arrange
	client := NewClaudeClient("test-key")

	attackerRole := &roles.Role{
		Name: "viewer",
		Permissions: []roles.Permission{
			{Raw: "read:users:own", Action: "read", Object: "users", Scope: "own"},
		},
	}

	victimRole := &roles.Role{
		Name: "admin",
		Permissions: []roles.Permission{
			{Raw: "read:users:all", Action: "read", Object: "users", Scope: "all"},
			{Raw: "write:users:all", Action: "write", Object: "users", Scope: "all"},
		},
	}

	finding := &model.Finding{
		Category: "API2",
		Method:   "GET",
		Endpoint: "/api/users/123",
		Evidence: model.Evidence{
			Response: model.HTTPResponse{
				StatusCode: 200,
				Body:       `{"id":"123","role":"admin"}`,
			},
		},
	}

	req := &TriageRequest{
		Finding:      finding,
		AttackerRole: attackerRole,
		VictimRole:   victimRole,
	}

	// Act
	prompt := client.buildPrompt(req)

	// Assert
	assert.Contains(t, prompt, "API2")
	assert.Contains(t, prompt, "GET")
	assert.Contains(t, prompt, "/api/users/123")
	assert.Contains(t, prompt, "viewer")
	assert.Contains(t, prompt, "admin")
	assert.Contains(t, prompt, "read:users:own")
	assert.Contains(t, prompt, "read:users:all, write:users:all")
	assert.Contains(t, prompt, "Status: 200")
	assert.Contains(t, prompt, "[REDACTED]") // Auth header should be redacted
}

func TestClaudeClient_PIIRedaction(t *testing.T) {
	// This is the CRITICAL test for CR-1 compliance
	tests := []struct {
		name         string
		responseBody string
		shouldRedact string
	}{
		{
			name:         "email redaction",
			responseBody: `{"email":"john.doe@example.com","name":"John"}`,
			shouldRedact: "john.doe@example.com",
		},
		{
			name:         "SSN redaction",
			responseBody: `{"ssn":"123-45-6789","name":"John"}`,
			shouldRedact: "123-45-6789",
		},
		{
			name:         "credit card redaction",
			responseBody: `{"card":"4532-1234-5678-9010","name":"John"}`,
			shouldRedact: "4532-1234-5678-9010",
		},
		{
			name:         "phone redaction",
			responseBody: `{"phone":"(555) 123-4567","name":"John"}`,
			shouldRedact: "(555) 123-4567",
		},
		{
			name:         "JWT redaction",
			responseBody: `{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc"}`,
			shouldRedact: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			client := NewClaudeClient("test-key")

			attackerRole := &roles.Role{
				Name:        "viewer",
				Permissions: []roles.Permission{},
			}

			finding := &model.Finding{
				Category: "API2",
				Method:   "GET",
				Endpoint: "/api/test",
				Evidence: model.Evidence{
					Response: model.HTTPResponse{
						StatusCode: 200,
						Body:       tt.responseBody,
					},
				},
			}

			req := &TriageRequest{
				Finding:      finding,
				AttackerRole: attackerRole,
				VictimRole:   nil,
			}

			// Act
			prompt := client.buildPrompt(req)

			// Assert - PII should NOT appear in prompt
			assert.NotContains(t, prompt, tt.shouldRedact,
				"PII was not redacted from LLM prompt - CR-1 VIOLATION")
			assert.Contains(t, prompt, "REDACTED",
				"REDACTED marker should appear where PII was removed")
		})
	}
}

func TestClaudeClient_ResponseTruncation(t *testing.T) {
	// Arrange
	client := NewClaudeClient("test-key")

	// Create a response larger than 8KB
	largeBody := string(make([]byte, 10000)) // 10KB

	attackerRole := &roles.Role{
		Name:        "viewer",
		Permissions: []roles.Permission{},
	}

	finding := &model.Finding{
		Category: "API2",
		Method:   "GET",
		Endpoint: "/api/test",
		Evidence: model.Evidence{
			Response: model.HTTPResponse{
				StatusCode: 200,
				Body:       largeBody,
			},
		},
	}

	req := &TriageRequest{
		Finding:      finding,
		AttackerRole: attackerRole,
		VictimRole:   nil,
	}

	// Act
	prompt := client.buildPrompt(req)

	// Assert - Response should be truncated
	assert.Contains(t, prompt, "[TRUNCATED")
}

func TestFormatPermissions(t *testing.T) {
	// Arrange
	perms := []roles.Permission{
		{Raw: "read:users:own", Action: "read", Object: "users", Scope: "own"},
		{Raw: "write:posts:own", Action: "write", Object: "posts", Scope: "own"},
	}

	// Act
	result := formatPermissions(perms)

	// Assert
	assert.Equal(t, "read:users:own, write:posts:own", result)
}

func TestGetVictimRoleName(t *testing.T) {
	t.Run("nil role", func(t *testing.T) {
		// Act
		name := getVictimRoleName(nil)

		// Assert
		assert.Equal(t, "(none)", name)
	})

	t.Run("with role", func(t *testing.T) {
		// Arrange
		role := &roles.Role{Name: "admin"}

		// Act
		name := getVictimRoleName(role)

		// Assert
		assert.Equal(t, "admin", name)
	})
}

func TestGetVictimRolePermissions(t *testing.T) {
	t.Run("nil role", func(t *testing.T) {
		// Act
		perms := getVictimRolePermissions(nil)

		// Assert
		assert.Equal(t, "(none)", perms)
	})

	t.Run("with permissions", func(t *testing.T) {
		// Arrange
		role := &roles.Role{
			Name: "admin",
			Permissions: []roles.Permission{
				{Raw: "read:users:all"},
			},
		}

		// Act
		perms := getVictimRolePermissions(role)

		// Assert
		assert.Equal(t, "read:users:all", perms)
	})
}
