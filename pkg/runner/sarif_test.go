package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/templates"
)

func sampleFinding() *model.Finding {
	return &model.Finding{
		ID:              "01-api1-bola-read-GET-/api/users/{id}-attacker-victim",
		TemplateID:      "01-api1-bola-read",
		Category:        "API1:2023",
		Name:            "BOLA - Cross-User Resource Access (Read)",
		Description:     "Lower-privileged attacker read victim's resource",
		Severity:        model.SeverityHigh,
		Endpoint:        "/api/users/{id}",
		Method:          "GET",
		AttackerRole:    "attacker",
		VictimRole:      "victim",
		IsVulnerability: true,
		Confidence:      0.9,
		Timestamp:       time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
	}
}

func sampleTemplate(id string) *templates.CompiledTemplate {
	return &templates.CompiledTemplate{
		Template: &templates.Template{
			ID: id,
			Info: templates.TemplateInfo{
				Name:        "BOLA - Cross-User Resource Access (Read)",
				Category:    "API1:2023",
				Severity:    "HIGH",
				Description: "Tests GET endpoints for unauthorized cross-user resource access",
				Tags:        []string{"bola", "owasp"},
			},
		},
		FilePath: "templates/rest/01-api1-bola-read.yaml",
	}
}

func TestNewSARIFReporter_RequiresOutputFile(t *testing.T) {
	_, err := NewSARIFReporter("", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--output-file")
}

func TestSARIFReporter_GenerateReport_Empty(t *testing.T) {
	out := filepath.Join(t.TempDir(), "empty.sarif")
	rep, err := NewSARIFReporter(out, nil)
	require.NoError(t, err)
	require.NoError(t, rep.GenerateReport(nil, &Stats{}))

	doc := readSARIF(t, out)
	assert.Equal(t, "2.1.0", doc.Version)
	assert.Equal(t, sarifSchema, doc.Schema)
	require.Len(t, doc.Runs, 1)
	assert.Equal(t, "Hadrian", doc.Runs[0].Tool.Driver.Name)
	assert.Empty(t, doc.Runs[0].Tool.Driver.Rules)
	assert.Empty(t, doc.Runs[0].Results)
}

func TestSARIFReporter_GenerateReport_SingleFinding(t *testing.T) {
	out := filepath.Join(t.TempDir(), "single.sarif")
	tmpl := sampleTemplate("01-api1-bola-read")
	rep, err := NewSARIFReporter(out, []*templates.CompiledTemplate{tmpl})
	require.NoError(t, err)

	f := sampleFinding()
	require.NoError(t, rep.GenerateReport([]*model.Finding{f}, &Stats{}))

	doc := readSARIF(t, out)
	require.Len(t, doc.Runs, 1)
	run := doc.Runs[0]

	// Rule
	require.Len(t, run.Tool.Driver.Rules, 1)
	rule := run.Tool.Driver.Rules[0]
	assert.Equal(t, "01-api1-bola-read", rule.ID)
	assert.Equal(t, "BOLA - Cross-User Resource Access (Read)", rule.ShortDescription.Text)
	assert.Equal(t, "Tests GET endpoints for unauthorized cross-user resource access", rule.FullDescription.Text)
	assert.Equal(t, "https://github.com/praetorian-inc/hadrian/blob/main/templates/rest/01-api1-bola-read.yaml", rule.HelpURI)
	require.NotNil(t, rule.DefaultConfiguration)
	assert.Equal(t, "error", rule.DefaultConfiguration.Level)
	require.NotNil(t, rule.Properties)
	assert.Contains(t, rule.Properties.Tags, "API1:2023")
	assert.Contains(t, rule.Properties.Tags, "bola")
	assert.Contains(t, rule.Properties.Tags, "security")

	// Result
	require.Len(t, run.Results, 1)
	res := run.Results[0]
	assert.Equal(t, "01-api1-bola-read", res.RuleID)
	assert.Equal(t, 0, res.RuleIndex)
	assert.Equal(t, "error", res.Level)
	assert.Contains(t, res.Message.Text, "BOLA")
	assert.Contains(t, res.Message.Text, "attacker")
	assert.Contains(t, res.Message.Text, "victim")
	require.Len(t, res.Locations, 1)
	assert.Equal(t, "/api/users/{id}", res.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	assert.Equal(t, "GET /api/users/{id}", res.Locations[0].LogicalLocations[0].Name)
	require.Contains(t, res.PartialFingerprints, "primaryLocationHash/v1")
	assert.Len(t, res.PartialFingerprints["primaryLocationHash/v1"], 64, "expected sha256 hex digest")
}

func TestSARIFReporter_GenerateReport_DeduplicatesRulesByTemplateID(t *testing.T) {
	out := filepath.Join(t.TempDir(), "dupes.sarif")
	rep, err := NewSARIFReporter(out, []*templates.CompiledTemplate{sampleTemplate("01-api1-bola-read")})
	require.NoError(t, err)

	a := sampleFinding()
	b := sampleFinding()
	b.AttackerRole = "guest"
	c := sampleFinding()
	c.Endpoint = "/api/orders/{id}"

	require.NoError(t, rep.GenerateReport([]*model.Finding{a, b, c}, &Stats{}))

	doc := readSARIF(t, out)
	require.Len(t, doc.Runs[0].Tool.Driver.Rules, 1, "same TemplateID should collapse to a single rule")
	require.Len(t, doc.Runs[0].Results, 3)
	for _, r := range doc.Runs[0].Results {
		assert.Equal(t, "01-api1-bola-read", r.RuleID)
		assert.Equal(t, 0, r.RuleIndex)
	}
}

func TestSARIFReporter_GenerateReport_RulesAreDeterministicallyOrdered(t *testing.T) {
	out := filepath.Join(t.TempDir(), "ordered.sarif")
	rep, err := NewSARIFReporter(out, nil)
	require.NoError(t, err)

	a := sampleFinding()
	a.TemplateID = "zz-last"
	b := sampleFinding()
	b.TemplateID = "aa-first"
	c := sampleFinding()
	c.TemplateID = "mm-middle"

	require.NoError(t, rep.GenerateReport([]*model.Finding{a, b, c}, &Stats{}))

	doc := readSARIF(t, out)
	require.Len(t, doc.Runs[0].Tool.Driver.Rules, 3)
	ids := []string{doc.Runs[0].Tool.Driver.Rules[0].ID, doc.Runs[0].Tool.Driver.Rules[1].ID, doc.Runs[0].Tool.Driver.Rules[2].ID}
	assert.Equal(t, []string{"aa-first", "mm-middle", "zz-last"}, ids)
}

func TestSARIFReporter_PartialFingerprintsAreStable(t *testing.T) {
	// Identical identity fields with different transient state must hash to the
	// same value — that is what makes GitHub Code Scanning treat two runs as
	// referring to the same alert.
	a := sampleFinding()
	a.Timestamp = time.Now()
	a.RequestIDs = []string{"req-1"}
	a.Evidence = model.Evidence{Response: model.HTTPResponse{Body: "first run"}}

	b := sampleFinding()
	b.Timestamp = time.Now().Add(1 * time.Hour)
	b.RequestIDs = []string{"req-different"}
	b.Evidence = model.Evidence{Response: model.HTTPResponse{Body: "second run"}}
	b.LLMAnalysis = &model.LLMTriage{Provider: "openai", Confidence: 0.95}

	assert.Equal(t, buildPartialFingerprints(a), buildPartialFingerprints(b),
		"fingerprints should not depend on transient state")
}

func TestSARIFReporter_PartialFingerprintsDifferWhenIdentityChanges(t *testing.T) {
	base := sampleFinding()
	cases := []struct {
		name   string
		mutate func(f *model.Finding)
	}{
		{"TemplateID", func(f *model.Finding) { f.TemplateID = "different-rule" }},
		{"Method", func(f *model.Finding) { f.Method = "POST" }},
		{"Endpoint", func(f *model.Finding) { f.Endpoint = "/different/path" }},
		{"AttackerRole", func(f *model.Finding) { f.AttackerRole = "different-attacker" }},
		{"VictimRole", func(f *model.Finding) { f.VictimRole = "different-victim" }},
	}
	baseFP := buildPartialFingerprints(base)["primaryLocationHash/v1"]
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			mutated := sampleFinding()
			tc.mutate(mutated)
			assert.NotEqual(t, baseFP, buildPartialFingerprints(mutated)["primaryLocationHash/v1"],
				"%s change should produce a different fingerprint", tc.name)
		})
	}
}

// QUAL-006 / SEC-BE-002 regression test: two findings whose identity fields
// would collide under a printable delimiter (e.g. "|") must still produce
// distinct fingerprints. The NUL separator guarantees this.
func TestSARIFReporter_PartialFingerprintsResistDelimiterCollision(t *testing.T) {
	// Without NUL separation, both joins would collapse to:
	//   "tpl|GET|/foo|attacker|"
	// Two distinct (TemplateID, Endpoint) tuples can shift the boundary so
	// joined strings match; assert their hashes differ regardless.
	a := &model.Finding{
		TemplateID:   "tpl",
		Method:       "GET",
		Endpoint:     "/foo|attacker|",
		AttackerRole: "",
		VictimRole:   "",
	}
	b := &model.Finding{
		TemplateID:   "tpl",
		Method:       "GET",
		Endpoint:     "/foo",
		AttackerRole: "attacker",
		VictimRole:   "",
	}
	assert.NotEqual(t,
		buildPartialFingerprints(a)["primaryLocationHash/v1"],
		buildPartialFingerprints(b)["primaryLocationHash/v1"],
		"delimiter-collision-resistant fingerprinting expected")
}

func TestSeverityToSARIFLevel(t *testing.T) {
	cases := map[model.Severity]string{
		model.SeverityCritical: "error",
		model.SeverityHigh:     "error",
		model.SeverityMedium:   "warning",
		model.SeverityLow:      "note",
		model.SeverityInfo:     "note",
		model.Severity(""):     "warning",
	}
	for sev, expected := range cases {
		assert.Equal(t, expected, severityToSARIFLevel(sev), "severity %q", sev)
	}
}

func TestTemplateHelpURI(t *testing.T) {
	cases := []struct {
		name     string
		filePath string
		want     string
	}{
		{"empty path", "", templateWikiURL},
		{"built-in rest", "templates/rest/01-api1-bola-read.yaml", templateBaseURL + "templates/rest/01-api1-bola-read.yaml"},
		{"built-in graphql with leading ./", "./templates/graphql/foo.yaml", templateBaseURL + "templates/graphql/foo.yaml"},
		{"built-in grpc with Windows separators", "templates\\rest\\01-api1-bola-read.yaml", templateBaseURL + "templates/rest/01-api1-bola-read.yaml"},
		// QUAL-005 fix: absolute paths that contain "templates/" as a non-prefix
		// segment must NOT be mapped to hadrian's GitHub blob — they are custom
		// templates that live outside the built-in tree.
		{"custom abs path with templates/ as a non-prefix segment", "/abs/path/templates/grpc/bar.yaml", templateWikiURL},
		{"custom path with sub-templates dir", "/opt/work/sub-templates/api.yaml", templateWikiURL},
		{"custom path with my-templates dir", "/home/user/my-templates/foo.yaml", templateWikiURL},
		{"completely custom path", "/some/custom/path/my-template.yaml", templateWikiURL},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, templateHelpURI(tc.filePath))
		})
	}
}

func TestSARIFReporter_FallsBackWhenNoTemplate(t *testing.T) {
	out := filepath.Join(t.TempDir(), "no-tmpl.sarif")
	rep, err := NewSARIFReporter(out, nil)
	require.NoError(t, err)
	require.NoError(t, rep.GenerateReport([]*model.Finding{sampleFinding()}, &Stats{}))

	doc := readSARIF(t, out)
	require.Len(t, doc.Runs[0].Tool.Driver.Rules, 1)
	rule := doc.Runs[0].Tool.Driver.Rules[0]
	assert.Equal(t, templateWikiURL, rule.HelpURI, "expected wiki fallback when no template registered")
	assert.Equal(t, "BOLA - Cross-User Resource Access (Read)", rule.ShortDescription.Text,
		"rule short description should come from the finding when no template is registered")
}

func TestSARIFReporter_HandlesMissingTemplateID(t *testing.T) {
	out := filepath.Join(t.TempDir(), "missing-id.sarif")
	rep, err := NewSARIFReporter(out, nil)
	require.NoError(t, err)

	orphan := sampleFinding()
	orphan.TemplateID = ""

	require.NoError(t, rep.GenerateReport([]*model.Finding{orphan}, &Stats{}))

	doc := readSARIF(t, out)
	require.Len(t, doc.Runs[0].Tool.Driver.Rules, 1)
	assert.Equal(t, "hadrian.unknown", doc.Runs[0].Tool.Driver.Rules[0].ID)
	require.Len(t, doc.Runs[0].Results, 1)
	assert.Equal(t, "hadrian.unknown", doc.Runs[0].Results[0].RuleID)
}

func TestSARIFReporter_OutputValidatesAsSchemaShape(t *testing.T) {
	// Light shape check — verifies the produced document contains every
	// required SARIF v2.1.0 top-level/run-level field that GitHub Code
	// Scanning rejects when missing. Full JSON-Schema validation is exercised
	// in the integration test that downloads the official schema.
	out := filepath.Join(t.TempDir(), "shape.sarif")
	rep, err := NewSARIFReporter(out, []*templates.CompiledTemplate{sampleTemplate("01-api1-bola-read")})
	require.NoError(t, err)
	require.NoError(t, rep.GenerateReport([]*model.Finding{sampleFinding()}, &Stats{}))

	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	var v map[string]any
	require.NoError(t, json.Unmarshal(raw, &v))
	assert.Equal(t, "2.1.0", v["version"])
	assert.NotEmpty(t, v["$schema"])
	runs, ok := v["runs"].([]any)
	require.True(t, ok)
	require.Len(t, runs, 1)
	run := runs[0].(map[string]any)
	assert.Contains(t, run, "tool")
	assert.Contains(t, run, "results")
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	assert.Equal(t, "Hadrian", driver["name"])
	assert.NotEmpty(t, driver["version"])
	assert.NotEmpty(t, driver["informationUri"])
}

func TestBuildResultMessage(t *testing.T) {
	cases := []struct {
		name     string
		f        *model.Finding
		contains []string
	}{
		{
			name:     "complete",
			f:        sampleFinding(),
			contains: []string{"BOLA", "GET /api/users/{id}", "attacker=attacker", "victim=victim", "victim's resource"},
		},
		{
			name: "no roles",
			f: &model.Finding{
				TemplateID: "x",
				Name:       "X",
				Method:     "POST",
				Endpoint:   "/a",
			},
			contains: []string{"X", "POST /a"},
		},
		{
			name:     "fallback name",
			f:        &model.Finding{TemplateID: "anon"},
			contains: []string{"anon"},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			msg := buildResultMessage(tc.f)
			for _, want := range tc.contains {
				assert.Contains(t, msg, want)
			}
		})
	}
}

func TestDedupeStrings(t *testing.T) {
	got := dedupeStrings([]string{"a", "", "b", "a", "c", "b", ""})
	assert.Equal(t, []string{"a", "b", "c"}, got)
}

// LLM-triaged findings should surface llmConfidence and llmProvider in the
// result properties so downstream consumers (and the GitHub UI) see the AI
// signal alongside the raw detection metadata.
func TestSARIFReporter_LLMPropertiesAreCarriedThrough(t *testing.T) {
	out := filepath.Join(t.TempDir(), "llm.sarif")
	rep, err := NewSARIFReporter(out, nil)
	require.NoError(t, err)
	f := sampleFinding()
	f.LLMAnalysis = &model.LLMTriage{
		Provider:        "anthropic",
		Confidence:      0.92,
		IsVulnerability: true,
		Reasoning:       "endpoint returned victim's data",
	}
	require.NoError(t, rep.GenerateReport([]*model.Finding{f}, &Stats{}))

	doc := readSARIF(t, out)
	require.Len(t, doc.Runs[0].Results, 1)
	props := doc.Runs[0].Results[0].Properties
	require.NotNil(t, props)
	assert.Equal(t, "anthropic", props["llmProvider"])
	assert.InDelta(t, 0.92, props["llmConfidence"], 1e-9)
}

// ReportFinding is a no-op so SARIF stays a batched format. The contract test
// just confirms it doesn't panic and doesn't mutate state — anything else
// would surprise callers iterating findings during LLM triage.
func TestSARIFReporter_ReportFindingIsNoOp(t *testing.T) {
	out := filepath.Join(t.TempDir(), "noop.sarif")
	rep, err := NewSARIFReporter(out, nil)
	require.NoError(t, err)
	for i := 0; i < 5; i++ {
		rep.ReportFinding(sampleFinding())
	}
	require.NoError(t, rep.GenerateReport(nil, &Stats{}))
	doc := readSARIF(t, out)
	assert.Empty(t, doc.Runs[0].Results, "ReportFinding must not mutate state")
}

// SARIF documents are documented as upload-ready to GitHub Code Scanning, so
// any tokens / PII the scanned API returned in a Finding.Description must be
// redacted before they reach the SARIF document. Counterpart to SEC-BE-001.
func TestSARIFReporter_RedactsTokensInResultMessage(t *testing.T) {
	out := filepath.Join(t.TempDir(), "redacted.sarif")
	rep, err := NewSARIFReporter(out, nil)
	require.NoError(t, err)
	leaky := sampleFinding()
	leaky.Description = "response carried bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def and an email user@example.com"
	require.NoError(t, rep.GenerateReport([]*model.Finding{leaky}, &Stats{}))
	doc := readSARIF(t, out)
	require.Len(t, doc.Runs[0].Results, 1)
	msg := doc.Runs[0].Results[0].Message.Text
	assert.NotContains(t, msg, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def", "JWT must be redacted")
	assert.NotContains(t, msg, "user@example.com", "email must be redacted")
}

// QUAL-005 / SEC-BE: SARIF files may carry sensitive content, so the file
// must be written with owner-only (0600) permissions.
func TestSARIFReporter_WritesFileWith0600Mode(t *testing.T) {
	out := filepath.Join(t.TempDir(), "mode.sarif")
	rep, err := NewSARIFReporter(out, nil)
	require.NoError(t, err)
	require.NoError(t, rep.GenerateReport([]*model.Finding{sampleFinding()}, &Stats{}))
	info, err := os.Stat(out)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

// Findings with no endpoint must still produce a syntactically valid SARIF
// location — the spec requires an artifactLocation.uri.
func TestSARIFReporter_HandlesEmptyEndpoint(t *testing.T) {
	out := filepath.Join(t.TempDir(), "noendpoint.sarif")
	rep, err := NewSARIFReporter(out, nil)
	require.NoError(t, err)
	f := sampleFinding()
	f.Endpoint = ""
	require.NoError(t, rep.GenerateReport([]*model.Finding{f}, &Stats{}))
	doc := readSARIF(t, out)
	require.Len(t, doc.Runs[0].Results, 1)
	require.Len(t, doc.Runs[0].Results[0].Locations, 1)
	assert.Equal(t, "unknown", doc.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
}

// ruleFor has conditional branches for missing template description / sample
// name. Both should emit a valid (if minimal) rule object.
func TestSARIFReporter_RuleForEmptyBranches(t *testing.T) {
	t.Run("template with empty description", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "tmpl-emptydesc.sarif")
		tmpl := sampleTemplate("01-api1-bola-read")
		tmpl.Info.Description = ""
		rep, err := NewSARIFReporter(out, []*templates.CompiledTemplate{tmpl})
		require.NoError(t, err)
		require.NoError(t, rep.GenerateReport([]*model.Finding{sampleFinding()}, &Stats{}))
		doc := readSARIF(t, out)
		require.Len(t, doc.Runs[0].Tool.Driver.Rules, 1)
		assert.Nil(t, doc.Runs[0].Tool.Driver.Rules[0].FullDescription, "empty template description should omit FullDescription")
	})

	t.Run("finding with empty Name and no template", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "nomatch.sarif")
		rep, err := NewSARIFReporter(out, nil)
		require.NoError(t, err)
		f := sampleFinding()
		f.Name = ""
		f.Description = ""
		require.NoError(t, rep.GenerateReport([]*model.Finding{f}, &Stats{}))
		doc := readSARIF(t, out)
		require.Len(t, doc.Runs[0].Tool.Driver.Rules, 1)
		assert.Nil(t, doc.Runs[0].Tool.Driver.Rules[0].ShortDescription, "empty finding name should omit ShortDescription")
		assert.Nil(t, doc.Runs[0].Tool.Driver.Rules[0].FullDescription, "empty finding description should omit FullDescription")
	})
}

// readSARIF reads and parses a SARIF document, failing the test on any error.
func readSARIF(t *testing.T, path string) SARIFReport {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc SARIFReport
	require.NoError(t, json.Unmarshal(data, &doc))
	// Sanity: the produced JSON should round-trip without losing the schema
	// declaration (we hard-fail here so accidental removals show up).
	require.True(t, strings.HasPrefix(doc.Schema, "https://"), "schema must be a URL")
	return doc
}
