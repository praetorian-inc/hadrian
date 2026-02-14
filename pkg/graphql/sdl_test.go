package graphql

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSchemaFromFile(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) string
		wantErr bool
		checks  func(t *testing.T, schema *Schema)
	}{
		{
			name: "loads valid GraphQL SDL file",
			setup: func(t *testing.T) string {
				// Create temporary SDL file
				tmpDir := t.TempDir()
				schemaFile := filepath.Join(tmpDir, "schema.graphql")
				content := `
type Query {
  user(id: ID!): User
  users: [User!]!
}

type User {
  id: ID!
  name: String!
  email: String
}
`
				if err := os.WriteFile(schemaFile, []byte(content), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return schemaFile
			},
			wantErr: false,
			checks: func(t *testing.T, schema *Schema) {
				// Check query fields
				if len(schema.Queries) != 2 {
					t.Errorf("Expected 2 queries, got %d", len(schema.Queries))
				}

				// Check that User type exists
				userType, ok := schema.GetType("User")
				if !ok {
					t.Error("Expected User type to exist")
				}
				if userType != nil && len(userType.Fields) != 3 {
					t.Errorf("Expected User to have 3 fields, got %d", len(userType.Fields))
				}
			},
		},
		{
			name: "returns error for non-existent file",
			setup: func(t *testing.T) string {
				return "/nonexistent/schema.graphql"
			},
			wantErr: true,
			checks:  nil,
		},
		{
			name: "returns error for invalid SDL syntax",
			setup: func(t *testing.T) string {
				tmpDir := t.TempDir()
				schemaFile := filepath.Join(tmpDir, "bad.graphql")
				content := `
type Query {
  invalid syntax here @#$%
}
`
				if err := os.WriteFile(schemaFile, []byte(content), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return schemaFile
			},
			wantErr: true,
			checks:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filepath := tt.setup(t)
			schema, err := LoadSchemaFromFile(filepath)

			if (err != nil) != tt.wantErr {
				t.Errorf("LoadSchemaFromFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.checks != nil && schema != nil {
				tt.checks(t, schema)
			}
		})
	}
}
