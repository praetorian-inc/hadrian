package templates

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOWASPTagsConvention guards against tag-drift in the convention-bound
// OWASP template directories: every YAML template in these directories must
// carry both "owasp" and "owasp-api-top10" in info.tags so that
// --category owasp filtering stays consistent across GraphQL, gRPC, and test
// templates (LAB-2104).
func TestOWASPTagsConvention(t *testing.T) {
	dirs := []string{
		"../../templates/graphql",
		"../../templates/grpc",
		"../../test/dvga/templates/owasp",
		"../../test/grpc-server/templates/owasp",
	}

	for _, dir := range dirs {
		t.Run(dir, func(t *testing.T) {
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)

			yamlFiles := 0
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
					continue
				}
				yamlFiles++
				path := filepath.Join(dir, e.Name())

				tmpl, err := Parse(path)
				require.NoError(t, err, "%s must parse", path)

				assert.Contains(t, tmpl.Info.Tags, "owasp",
					`%s is missing the "owasp" tag`, path)
				assert.Contains(t, tmpl.Info.Tags, "owasp-api-top10",
					`%s is missing the "owasp-api-top10" tag`, path)
			}
			require.Greater(t, yamlFiles, 0, "expected at least one YAML template in %s", dir)
		})
	}
}
