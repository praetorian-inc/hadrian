package orchestrator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadTemplates_DeterministicOrder(t *testing.T) {
	// Create temp dir with templates in non-alphabetical order
	tmpDir := t.TempDir()

	// Create templates with names that would be out of order if not sorted
	templates := []string{"03-c.yaml", "01-a.yaml", "02-b.yaml"}
	for _, name := range templates {
		content := `id: ` + name[:4] + `
info:
  name: "Test"
  category: "API1:2023"
  severity: "HIGH"
  test_pattern: "simple"
endpoint_selector:
  has_path_parameter: true
  requires_auth: true
  methods: ["GET"]
role_selector:
  attacker_permission_level: "lower"
  victim_permission_level: "higher"
detection:
  success_indicators:
    - type: status_code
      status_code: 200
  vulnerability_pattern: "test"
`
		err := os.WriteFile(filepath.Join(tmpDir, name), []byte(content), 0644)
		require.NoError(t, err)
	}

	// Load templates multiple times and verify order is always the same
	for i := 0; i < 5; i++ {
		loaded, err := LoadTemplates(filepath.Join(tmpDir, "*.yaml"))
		require.NoError(t, err)
		require.Len(t, loaded, 3)

		// Should always be in alphabetical order
		assert.Equal(t, "01-a", loaded[0].ID)
		assert.Equal(t, "02-b", loaded[1].ID)
		assert.Equal(t, "03-c", loaded[2].ID)
	}
}
