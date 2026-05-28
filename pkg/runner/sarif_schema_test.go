package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/templates"
)

// loadSARIFSchema compiles the SARIF v2.1.0 JSON Schema bundled in testdata.
// The file is a verbatim copy of https://json.schemastore.org/sarif-2.1.0.json
// — refreshing it from upstream is the only maintenance burden.
func loadSARIFSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	path := filepath.Join("testdata", "sarif-2.1.0.json")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	var schemaDoc any
	require.NoError(t, json.Unmarshal(raw, &schemaDoc))

	c := jsonschema.NewCompiler()
	require.NoError(t, c.AddResource("sarif-2.1.0.json", schemaDoc))
	schema, err := c.Compile("sarif-2.1.0.json")
	require.NoError(t, err)
	return schema
}

// validateAgainstSARIFSchema parses the file at `path` and validates it against
// the SARIF v2.1.0 schema. Fails the test with a readable error on mismatch.
func validateAgainstSARIFSchema(t *testing.T, schema *jsonschema.Schema, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc any
	require.NoError(t, json.Unmarshal(raw, &doc))
	if err := schema.Validate(doc); err != nil {
		t.Fatalf("SARIF document at %s does not validate against schema:\n%s", path, err)
	}
}

// TestSARIFReporter_ValidatesAgainstSchema is the load-bearing acceptance test
// for LAB-2747: the file must validate against the canonical SARIF v2.1.0
// schema, which is exactly what GitHub Code Scanning enforces on upload.
func TestSARIFReporter_ValidatesAgainstSchema(t *testing.T) {
	schema := loadSARIFSchema(t)

	out := filepath.Join(t.TempDir(), "report.sarif")
	tmpl := sampleTemplate("01-api1-bola-read")
	rep, err := NewSARIFReporter(out, []*templates.CompiledTemplate{tmpl})
	require.NoError(t, err)

	findings := []*model.Finding{
		sampleFinding(),
		{
			ID:           "02-api2-broken-auth-1",
			TemplateID:   "04-api2-broken-auth-no-token",
			Category:     "API2:2023",
			Name:         "Missing authentication",
			Description:  "Endpoint accepts requests without a token",
			Severity:     model.SeverityCritical,
			Method:       "GET",
			Endpoint:     "/api/admin/users",
			AttackerRole: "anonymous",
		},
		{
			ID:         "graphql-introspection-1",
			TemplateID: "introspection-disclosure",
			Category:   "API8:2023 Security Misconfiguration",
			Name:       "introspection-disclosure",
			Severity:   model.SeverityMedium,
			Method:     "POST",
			Endpoint:   "/graphql",
		},
	}

	require.NoError(t, rep.GenerateReport(findings, &Stats{}))
	validateAgainstSARIFSchema(t, schema, out)
}

func TestSARIFReporter_ValidatesAgainstSchema_Empty(t *testing.T) {
	// Empty result set is also valid SARIF (a scan that found nothing).
	schema := loadSARIFSchema(t)
	out := filepath.Join(t.TempDir(), "empty.sarif")
	rep, err := NewSARIFReporter(out, nil)
	require.NoError(t, err)
	require.NoError(t, rep.GenerateReport(nil, &Stats{}))
	validateAgainstSARIFSchema(t, schema, out)
}
