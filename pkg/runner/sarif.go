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
	results := r.buildResults(findings, ruleIndex)

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
			// Static run id. GitHub Code Scanning separates runs by the
			// upload-sarif `category` parameter (see the example workflow), not
			// by automationDetails.id, so a constant value is intentional here —
			// it is not a per-run unique identifier.
			AutomationDetails: &SARIFRunAutomation{
				ID: "hadrian",
			},
			ColumnKind: "utf16CodeUnits",
		}},
	}
}

// ruleID returns the SARIF rule identifier for a finding: its TemplateID, or
// the "hadrian.unknown" sentinel when the finding carries no template ID.
// buildRules, buildResults, and buildPartialFingerprints all route through this
// so a result's ruleId and its partialFingerprint can never derive from
// different values (an empty TemplateID would otherwise hash "" while the rule
// is named "hadrian.unknown").
func ruleID(f *model.Finding) string {
	if f.TemplateID == "" {
		return "hadrian.unknown"
	}
	return f.TemplateID
}

// buildResults maps findings to SARIF results given a TemplateID→index map.
//
// Extracted from build() so the invariant-violation branch (a finding whose
// ruleID is not in ruleIndex) is unit-testable. In normal flow buildRules
// produces ruleIndex from the same finding set, so the !ok case should never
// fire — but the defensive log.Warn+skip exists to surface future refactor
// regressions, and a regression test for it must be able to inject an
// inconsistent ruleIndex.
func (r *SARIFReporter) buildResults(findings []*model.Finding, ruleIndex map[string]int) []SARIFResult {
	results := make([]SARIFResult, 0, len(findings))
	for _, f := range findings {
		rid := ruleID(f)
		idx, ok := ruleIndex[rid]
		if !ok {
			// buildRules walks the same finding set, so this branch indicates
			// an invariant violation (refactor regression, future loader bug,
			// concurrent mutation). Surface it rather than silently emitting a
			// SARIF result that points at the wrong rule.
			log.Warn("SARIF: dropping finding with ruleID %q — no matching entry in driver.rules (invariant violation)", rid)
			continue
		}
		results = append(results, SARIFResult{
			RuleID:              rid,
			RuleIndex:           idx,
			Level:               severityToSARIFLevel(f.Severity),
			Message:             SARIFMessage{Text: r.redactor.Redact(buildResultMessage(f))},
			Locations:           buildLocations(f),
			PartialFingerprints: buildPartialFingerprints(f),
			Properties:          buildResultProperties(f),
		})
	}
	return results
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
		id := ruleID(f)
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

	// Template-enriched path: a CompiledTemplate is registered for this id, so
	// description/helpUri/tags/severity come from its author-controlled metadata.
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

	// Finding-derived fallback: no template registered (e.g. the GraphQL
	// non-template scanner), so synthesize a minimal rule from a sample finding
	// and point helpUri at the wiki.
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

// builtInTemplateDirs are the canonical subdirectories of Hadrian's built-in
// template tree. A FilePath that contains one of these as a path segment is
// linked to its GitHub blob, regardless of how the loader reached it.
var builtInTemplateDirs = []string{"templates/rest/", "templates/graphql/", "templates/grpc/"}

// templateHelpURI returns a stable GitHub URL for built-in templates and a
// fallback wiki URL otherwise.
//
// A built-in template is identified by a FilePath that contains one of
// builtInTemplateDirs as a path segment. Anchoring on the
// templates/{rest,graphql,grpc}/ segment (rather than a leading "templates/"
// prefix) is what lets the canonical blob URL resolve no matter how the loader
// reached the file: the relative default ("templates/rest/x.yaml"), an absolute
// --template-dir ("/opt/hadrian/templates/grpc/x.yaml"), $HADRIAN_TEMPLATES, or
// a "../../templates/rest/x.yaml" relative path all map to the same blob.
//
// The segment must sit on a path boundary (string start or after a "/"), so
// custom layouts like /home/user/my-templates/foo.yaml or
// /opt/work/sub-templates/api.yaml still fall through to the wiki URL instead
// of producing a broken blob link.
func templateHelpURI(filePath string) string {
	if filePath == "" {
		return templateWikiURL
	}
	// Normalize Windows separators and strip a leading "./" so a built-in
	// template loaded via the default relative path still matches.
	normalized := strings.TrimPrefix(strings.ReplaceAll(filePath, "\\", "/"), "./")
	for _, seg := range builtInTemplateDirs {
		i := strings.LastIndex(normalized, seg)
		if i == 0 || (i > 0 && normalized[i-1] == '/') {
			return templateBaseURL + normalized[i:]
		}
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
	logical := formatMethodEndpoint(f)
	if logical == "" {
		// Mirror the physical URI fallback so the logical name is never blank.
		logical = "unknown"
	}
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
//
// INVARIANT: one (TemplateID, Method, Endpoint, AttackerRole, VictimRole) tuple
// must map to at most one finding. Category and Severity are deliberately NOT
// part of the hash — today that tuple uniquely identifies a finding, so adding
// them would only churn fingerprints (and reopen GitHub Code Scanning alerts)
// without improving uniqueness. If a future change ever lets the same tuple
// emit two findings that differ only by Category or Severity, they will collide
// to a single alert and one will be hidden; at that point Category/Severity
// must be folded into the hash here (a new "/v2" key, leaving v1 intact so
// existing alerts are not orphaned).
func buildPartialFingerprints(f *model.Finding) map[string]string {
	parts := []string{
		// Use the normalized rule id (not the raw TemplateID) so the fingerprint
		// matches the ruleId emitted in the same SARIFResult — an empty
		// TemplateID must hash "hadrian.unknown", not "".
		ruleID(f),
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

// formatMethodEndpoint renders a finding's operation as "METHOD /path" (method
// upper-cased, surrounding whitespace trimmed). Returns "" when both fields are
// empty. Shared by buildLocations (logical-location name) and buildResultMessage.
func formatMethodEndpoint(f *model.Finding) string {
	return strings.TrimSpace(strings.ToUpper(f.Method) + " " + f.Endpoint)
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
		b.WriteString(formatMethodEndpoint(f))
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
		"isVulnerability": f.IsVulnerability,
	}
	if f.Category != "" {
		props["category"] = f.Category
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
