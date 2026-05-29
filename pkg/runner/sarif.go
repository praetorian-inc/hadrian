package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/log"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/reporter"
	"github.com/praetorian-inc/hadrian/pkg/templates"
)

// SARIF v2.1.0 output (https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).
//
// Hadrian emits one SARIF "run" containing:
//   - tool.driver.rules[] — one rule per unique TemplateID that produced a finding
//   - results[] — one entry per Finding
//
// Each result carries a stable partialFingerprints["primaryLocationHash/v1"]
// derived from (TemplateID, Method, Endpoint, AttackerRole, VictimRole). GitHub
// Code Scanning uses these to deduplicate alerts across runs.

const (
	sarifVersion = "2.1.0"
	// sarifSchema points at the canonical SARIF v2.1.0 JSON Schema on the
	// oasis-tcs/sarif-spec main branch — the old master/Schemata URL returns 404.
	sarifSchema           = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
	hadrianInformationURI = "https://github.com/praetorian-inc/hadrian"
	templateBaseURL       = "https://github.com/praetorian-inc/hadrian/blob/main/"
	templateWikiURL       = "https://github.com/praetorian-inc/hadrian/wiki/Template-System"

	// builtInTemplatePrefix gates templateHelpURI: only paths rooted at
	// "templates/" map to the hadrian GitHub blob URL. A custom template at
	// /home/user/my-templates/foo.yaml would otherwise match a naive substring
	// search and produce a broken URL.
	builtInTemplatePrefix = "templates/"

	// fingerprintFieldSep separates identity fields when computing
	// partialFingerprints. NUL is used because it cannot legitimately appear in
	// any of the inputs (template IDs, HTTP methods, paths, role names) — joining
	// with a printable delimiter risks collisions if a user-supplied field
	// contains the delimiter.
	fingerprintFieldSep = "\x00"
)

// SARIFReport is the top-level SARIF v2.1.0 document.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool              SARIFTool           `json:"tool"`
	Results           []SARIFResult       `json:"results"`
	AutomationDetails *SARIFRunAutomation `json:"automationDetails,omitempty"`
	ColumnKind        string              `json:"columnKind,omitempty"`
}

type SARIFRunAutomation struct {
	ID string `json:"id"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID                   string               `json:"id"`
	Name                 string               `json:"name,omitempty"`
	ShortDescription     *SARIFMessage        `json:"shortDescription,omitempty"`
	FullDescription      *SARIFMessage        `json:"fullDescription,omitempty"`
	HelpURI              string               `json:"helpUri,omitempty"`
	DefaultConfiguration *SARIFConfiguration  `json:"defaultConfiguration,omitempty"`
	Properties           *SARIFRuleProperties `json:"properties,omitempty"`
}

type SARIFConfiguration struct {
	Level string `json:"level"`
}

type SARIFRuleProperties struct {
	Tags      []string `json:"tags,omitempty"`
	Precision string   `json:"precision,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             SARIFMessage      `json:"message"`
	Locations           []SARIFLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type SARIFLocation struct {
	PhysicalLocation *SARIFPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations,omitempty"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine"`
}

type SARIFLogicalLocation struct {
	Name string `json:"name,omitempty"`
	Kind string `json:"kind,omitempty"`
}

// SARIFReporter writes findings as a SARIF v2.1.0 document.
//
// Templates passed at construction time are used to enrich the rules section
// (full description, helpUri, tags). They are optional: if absent, rules are
// derived from the findings themselves.
//
// Free-text content (Finding.Description, embedded response excerpts) is
// passed through reporter.Redactor before being written so that tokens and
// PII the scanned API returned cannot leak into a SARIF document that the
// PR documents as upload-ready to GitHub Code Scanning.
type SARIFReporter struct {
	outputFile string
	templates  map[string]*templates.CompiledTemplate
	redactor   *reporter.Redactor
}

// NewSARIFReporter constructs a SARIFReporter. `tmpls` may be nil for callers
// (notably the GraphQL non-template scanner path) that produce findings without
// matching CompiledTemplate metadata.
func NewSARIFReporter(outputFile string, tmpls []*templates.CompiledTemplate) (*SARIFReporter, error) {
	if outputFile == "" {
		return nil, fmt.Errorf("sarif output requires --output-file")
	}
	idx := make(map[string]*templates.CompiledTemplate, len(tmpls))
	for _, t := range tmpls {
		if t == nil {
			continue
		}
		idx[t.ID] = t
	}
	return &SARIFReporter{
		outputFile: outputFile,
		templates:  idx,
		redactor:   reporter.NewRedactor(),
	}, nil
}

// ReportFinding is a no-op; SARIF output is batched in GenerateReport.
func (r *SARIFReporter) ReportFinding(_ *model.Finding) {}

// GenerateReport writes the SARIF document to outputFile.
func (r *SARIFReporter) GenerateReport(findings []*model.Finding, _ *Stats) error {
	report := r.build(findings)

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SARIF report: %w", err)
	}

	if err := os.WriteFile(r.outputFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write SARIF report: %w", err)
	}
	return nil
}

// Close is a no-op for SARIFReporter (no resources held).
func (r *SARIFReporter) Close() error { return nil }

// build assembles the SARIF document from findings.
func (r *SARIFReporter) build(findings []*model.Finding) SARIFReport {
	rules, ruleIndex := r.buildRules(findings)
	results := make([]SARIFResult, 0, len(findings))
	for _, f := range findings {
		ruleID := f.TemplateID
		if ruleID == "" {
			ruleID = "hadrian.unknown"
		}
		idx, ok := ruleIndex[ruleID]
		if !ok {
			// buildRules walks the same finding set, so this branch indicates
			// an invariant violation (refactor regression, future loader bug,
			// concurrent mutation). Surface it rather than silently emitting a
			// SARIF result that points at the wrong rule.
			log.Warn("SARIF: dropping finding with ruleID %q — no matching entry in driver.rules (invariant violation)", ruleID)
			continue
		}
		results = append(results, SARIFResult{
			RuleID:              ruleID,
			RuleIndex:           idx,
			Level:               severityToSARIFLevel(f.Severity),
			Message:             SARIFMessage{Text: r.redactor.Redact(buildResultMessage(f))},
			Locations:           buildLocations(f),
			PartialFingerprints: buildPartialFingerprints(f),
			Properties:          buildResultProperties(f),
		})
	}

	return SARIFReport{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []SARIFRun{{
			Tool: SARIFTool{
				Driver: SARIFDriver{
					Name:           "Hadrian",
					InformationURI: hadrianInformationURI,
					Version:        Version,
					Rules:          rules,
				},
			},
			Results: results,
			AutomationDetails: &SARIFRunAutomation{
				ID: "hadrian",
			},
			ColumnKind: "utf16CodeUnits",
		}},
	}
}

// buildRules emits one SARIFRule per unique TemplateID found in `findings`.
// Returns the slice in deterministic order plus a TemplateID->index map.
func (r *SARIFReporter) buildRules(findings []*model.Finding) ([]SARIFRule, map[string]int) {
	type seen struct {
		first *model.Finding
	}
	uniq := map[string]seen{}
	order := []string{}
	for _, f := range findings {
		id := f.TemplateID
		if id == "" {
			id = "hadrian.unknown"
		}
		if _, ok := uniq[id]; !ok {
			uniq[id] = seen{first: f}
			order = append(order, id)
		}
	}
	sort.Strings(order)

	rules := make([]SARIFRule, 0, len(order))
	idx := make(map[string]int, len(order))
	for i, id := range order {
		rules = append(rules, r.ruleFor(id, uniq[id].first))
		idx[id] = i
	}
	return rules, idx
}

// ruleFor builds a SARIFRule for a TemplateID. When a matching CompiledTemplate
// is registered it provides richer metadata (description, helpUri, tags);
// otherwise we synthesize a minimal rule from a sample finding.
func (r *SARIFReporter) ruleFor(id string, sample *model.Finding) SARIFRule {
	rule := SARIFRule{
		ID:   id,
		Name: id,
	}

	if tmpl, ok := r.templates[id]; ok {
		rule.ShortDescription = &SARIFMessage{Text: tmpl.Info.Name}
		if tmpl.Info.Description != "" {
			// Built-in template descriptions are author-controlled YAML, so
			// PII contamination is unlikely — but the redactor is cheap and
			// keeps the rule-description path symmetric with the result path.
			rule.FullDescription = &SARIFMessage{Text: r.redactor.Redact(tmpl.Info.Description)}
		}
		rule.HelpURI = templateHelpURI(tmpl.FilePath)
		rule.DefaultConfiguration = &SARIFConfiguration{
			Level: severityToSARIFLevel(model.Severity(tmpl.Info.Severity)),
		}
		tags := []string{"security"}
		if tmpl.Info.Category != "" {
			tags = append(tags, tmpl.Info.Category)
		}
		tags = append(tags, tmpl.Info.Tags...)
		rule.Properties = &SARIFRuleProperties{
			Tags: dedupeStrings(tags),
			// Hadrian templates don't carry a per-rule precision signal today;
			// "medium" is a conservative default that avoids overstating
			// confidence to SARIF consumers (GitHub UI, Code Scanning APIs).
			Precision: "medium",
		}
		return rule
	}

	if sample != nil {
		if sample.Name != "" {
			rule.ShortDescription = &SARIFMessage{Text: sample.Name}
		}
		if sample.Description != "" {
			// Fallback rule path is the one the GraphQL non-template scanner
			// hits (TemplateIDs like "bola"/"bfla"/"introspection-disclosure"
			// have no compiled-template entry). CheckBOLA et al. embed
			// response-derived victim IDs in Description, so redaction here
			// is the actual leak fix — not just defense-in-depth.
			rule.FullDescription = &SARIFMessage{Text: r.redactor.Redact(sample.Description)}
		}
		rule.HelpURI = templateWikiURL
		rule.DefaultConfiguration = &SARIFConfiguration{
			Level: severityToSARIFLevel(sample.Severity),
		}
		tags := []string{"security"}
		if sample.Category != "" {
			tags = append(tags, sample.Category)
		}
		rule.Properties = &SARIFRuleProperties{
			Tags: dedupeStrings(tags),
			// Hadrian templates don't carry a per-rule precision signal today;
			// "medium" is a conservative default that avoids overstating
			// confidence to SARIF consumers (GitHub UI, Code Scanning APIs).
			Precision: "medium",
		}
	} else {
		rule.HelpURI = templateWikiURL
	}
	return rule
}

// templateHelpURI returns a stable GitHub URL for built-in templates and a
// fallback wiki URL otherwise.
//
// A built-in template is identified by a FilePath rooted at "templates/"
// (optionally prefixed with "./"). Earlier versions of this function matched
// the substring "templates/" anywhere in the path, which produced broken URLs
// for legitimate custom layouts like /home/user/my-templates/foo.yaml.
func templateHelpURI(filePath string) string {
	if filePath == "" {
		return templateWikiURL
	}
	// Normalize Windows separators and strip a leading "./" so a built-in
	// template loaded via the default relative path still matches.
	normalized := strings.TrimPrefix(strings.ReplaceAll(filePath, "\\", "/"), "./")
	if strings.HasPrefix(normalized, builtInTemplatePrefix) {
		return templateBaseURL + normalized
	}
	return templateWikiURL
}

// severityToSARIFLevel maps Hadrian severities to SARIF's notification levels.
// SARIF values: "error", "warning", "note", "none".
func severityToSARIFLevel(s model.Severity) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	case model.SeverityLow, model.SeverityInfo:
		return "note"
	default:
		return "warning"
	}
}

// buildLocations renders a SARIF location pair (physical + logical) describing
// the API endpoint that produced the finding. SARIF requires a physical
// location for results that participate in code scanning, so we synthesize one
// from the operation's METHOD + PATH.
func buildLocations(f *model.Finding) []SARIFLocation {
	uri := f.Endpoint
	if uri == "" {
		uri = "unknown"
	}
	logical := strings.TrimSpace(strings.ToUpper(f.Method) + " " + f.Endpoint)
	return []SARIFLocation{{
		PhysicalLocation: &SARIFPhysicalLocation{
			ArtifactLocation: SARIFArtifactLocation{
				URI: uri,
			},
			Region: &SARIFRegion{StartLine: 1},
		},
		LogicalLocations: []SARIFLogicalLocation{{
			Name: logical,
			Kind: "function",
		}},
	}}
}

// buildPartialFingerprints emits a stable fingerprint GitHub Code Scanning
// uses to deduplicate alerts across runs.
//
// Inputs are intentionally limited to stable identity fields. We deliberately
// exclude timestamps, request IDs, response bodies, and LLM analysis output.
//
// Fields are joined with NUL (\x00) so that no user-controllable value can
// shift the boundary between fields and produce a collision with a different
// (template, endpoint, role) tuple.
func buildPartialFingerprints(f *model.Finding) map[string]string {
	parts := []string{
		f.TemplateID,
		strings.ToUpper(f.Method),
		f.Endpoint,
		f.AttackerRole,
		f.VictimRole,
	}
	h := sha256.Sum256([]byte(strings.Join(parts, fingerprintFieldSep)))
	return map[string]string{
		"primaryLocationHash/v1": hex.EncodeToString(h[:]),
	}
}

// buildResultMessage renders the human-readable message for a SARIF result.
func buildResultMessage(f *model.Finding) string {
	header := f.Name
	if header == "" {
		header = f.TemplateID
	}
	if header == "" {
		header = "Security finding"
	}

	var b strings.Builder
	b.WriteString(header)
	if f.Method != "" || f.Endpoint != "" {
		b.WriteString(" on ")
		b.WriteString(strings.TrimSpace(strings.ToUpper(f.Method) + " " + f.Endpoint))
	}
	if f.AttackerRole != "" {
		b.WriteString(" (attacker=")
		b.WriteString(f.AttackerRole)
		if f.VictimRole != "" {
			b.WriteString(", victim=")
			b.WriteString(f.VictimRole)
		}
		b.WriteString(")")
	}
	if f.Description != "" {
		b.WriteString(". ")
		b.WriteString(f.Description)
	}
	return b.String()
}

// buildResultProperties carries Hadrian-specific metadata that SARIF consumers
// (e.g., GitHub Code Scanning UI) display under "Properties".
func buildResultProperties(f *model.Finding) map[string]any {
	props := map[string]any{
		"category":        f.Category,
		"isVulnerability": f.IsVulnerability,
	}
	if f.AttackerRole != "" {
		props["attackerRole"] = f.AttackerRole
	}
	if f.VictimRole != "" {
		props["victimRole"] = f.VictimRole
	}
	if f.Confidence > 0 {
		props["confidence"] = f.Confidence
	}
	if f.LLMAnalysis != nil {
		props["llmConfidence"] = f.LLMAnalysis.Confidence
		props["llmProvider"] = f.LLMAnalysis.Provider
	}
	return props
}

// dedupeStrings returns the input slice with empty values removed and
// duplicates collapsed, preserving first-seen order.
func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
