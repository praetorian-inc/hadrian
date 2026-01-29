package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	http "github.com/praetorian-inc/hadrian/internal/http"
	"github.com/praetorian-inc/hadrian/pkg/log"
	"github.com/praetorian-inc/hadrian/pkg/llm"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/plugins"
	_ "github.com/praetorian-inc/hadrian/pkg/plugins/rest" // Register REST plugin
	"github.com/praetorian-inc/hadrian/pkg/reporter"
	"github.com/praetorian-inc/hadrian/pkg/roles"
)

// =============================================================================
// PUBLIC API (Helper functions for CLI workflow)
// =============================================================================

// parseAPISpec parses API specification using registered plugins
func parseAPISpec(path string) (*model.APISpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read API spec: %w", err)
	}

	// Auto-detect plugin based on file content
	plugin, found := plugins.AutoDetect(data, path)
	if !found {
		return nil, fmt.Errorf("unsupported API specification format")
	}

	spec, err := plugin.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse API spec: %w", err)
	}

	return spec, nil
}

// createHTTPClient creates HTTP client with proxy, TLS, and timeout settings
func createHTTPClient(config Config) (*http.Client, error) {
	httpConfig := config.ToHTTPClientConfig()
	return http.New(httpConfig)
}

// Reporter interface for test output
type Reporter interface {
	ReportFinding(finding *model.Finding)
	GenerateReport(findings []*model.Finding, stats *Stats) error
	Close() error
}

// Stats holds test execution statistics
type Stats struct {
	TotalTests      int           `json:"total_tests"`
	Passed          int           `json:"passed"`
	Failed          int           `json:"failed"`
	Skipped         int           `json:"skipped"`
	Findings        int           `json:"findings"`
	Critical        int           `json:"critical"`
	High            int           `json:"high"`
	Medium          int           `json:"medium"`
	Low             int           `json:"low"`
	Info            int           `json:"info"`
	Duration        time.Duration `json:"duration"`
	OperationCount  int           `json:"operation_count"`
	RoleCount       int           `json:"role_count"`
	TemplatesLoaded int           `json:"templates_loaded"`
}

// createReporter creates appropriate reporter based on output format
func createReporter(format, outputFile string, requestIDsLimit int) (Reporter, error) {
	switch format {
	case "terminal":
		return NewTerminalReporter(os.Stdout, requestIDsLimit), nil
	case "json":
		return NewJSONReporter(outputFile, requestIDsLimit)
	case "markdown":
		return NewMarkdownReporter(outputFile, requestIDsLimit)
	default:
		return nil, fmt.Errorf("unsupported output format: %s", format)
	}
}

// triageWithLLM runs LLM triage on findings
func triageWithLLM(ctx context.Context, findings []*model.Finding, rolesCfg *roles.RoleConfig) ([]*model.Finding, error) {
	client, err := llm.NewClient(ctx)
	if err != nil {
		// LLM is optional - return findings without triage
		log.Warn("LLM triage disabled: %v", err)
		return findings, nil
	}

	redactor := reporter.NewRedactor()

	for _, finding := range findings {
		// Skip already-triaged findings
		if finding.LLMAnalysis != nil {
			continue
		}

		// Find attacker and victim roles
		var attackerRole, victimRole *roles.Role
		for _, role := range rolesCfg.Roles {
			if role.Name == finding.AttackerRole {
				attackerRole = role
			}
			if role.Name == finding.VictimRole {
				victimRole = role
			}
		}

		// Redact sensitive data before sending to LLM (CR-1)
		redactedFinding := *finding
		redactedFinding.Evidence.Request.Body = redactor.RedactForLLM(finding.Evidence.Request.Body)
		redactedFinding.Evidence.Response.Body = redactor.RedactForLLM(finding.Evidence.Response.Body)

		req := &llm.TriageRequest{
			Finding:      &redactedFinding,
			AttackerRole: attackerRole,
			VictimRole:   victimRole,
			RoleConfig:   rolesCfg,
		}

		result, err := client.Triage(ctx, req)
		if err != nil {
			log.Warn("LLM triage failed for %s: %v", finding.ID, err)
			continue
		}

		finding.LLMAnalysis = &model.LLMTriage{
			Provider:        result.Provider,
			IsVulnerability: result.IsVulnerability,
			Confidence:      result.Confidence,
			Reasoning:       result.Reasoning,
			Recommendations: result.Recommendations,
		}
		finding.Confidence = result.Confidence
		finding.IsVulnerability = result.IsVulnerability
	}

	return findings, nil
}

// calculateStats computes summary statistics from findings
func calculateStats(findings []*model.Finding, startTime time.Time) *Stats {
	stats := &Stats{
		Findings: len(findings),
		Duration: time.Since(startTime),
	}

	for _, f := range findings {
		switch f.Severity {
		case model.SeverityCritical:
			stats.Critical++
		case model.SeverityHigh:
			stats.High++
		case model.SeverityMedium:
			stats.Medium++
		case model.SeverityLow:
			stats.Low++
		case model.SeverityInfo:
			stats.Info++
		}
	}

	return stats
}

// =============================================================================
// REPORTER IMPLEMENTATIONS
// =============================================================================

// TerminalReporter outputs findings to terminal with colors
type TerminalReporter struct {
	writer          *os.File
	redactor        *reporter.Redactor
	requestIDsLimit int
}

func NewTerminalReporter(w *os.File, requestIDsLimit int) *TerminalReporter {
	return &TerminalReporter{
		writer:          w,
		redactor:        reporter.NewRedactor(),
		requestIDsLimit: requestIDsLimit,
	}
}

func (r *TerminalReporter) ReportFinding(finding *model.Finding) {
	severityColor := getSeverityColor(finding.Severity)
	fmt.Fprintf(r.writer, "%s[%s]%s %s - %s %s\n",
		severityColor, finding.Severity, colorReset,
		finding.Category, finding.Name,
		finding.Method+" "+finding.Endpoint)

	// Show role information
	if finding.AttackerRole != "" && finding.VictimRole != "" {
		fmt.Fprintf(r.writer, "  Roles: attacker=%s, victim=%s\n", finding.AttackerRole, finding.VictimRole)
	} else if finding.AttackerRole != "" {
		fmt.Fprintf(r.writer, "  Role: %s\n", finding.AttackerRole)
	}

	if finding.IsVulnerability {
		fmt.Fprintf(r.writer, "  Vulnerability confirmed (confidence: %.0f%%)\n", finding.Confidence*100)
	}

	// Show request IDs if available (limited by requestIDsLimit)
	if len(finding.RequestIDs) > 0 {
		requestIDs := finding.RequestIDs
		// Apply limit: 0 or negative = show all, positive = limit to last N
		if r.requestIDsLimit > 0 && len(requestIDs) > r.requestIDsLimit {
			requestIDs = requestIDs[len(requestIDs)-r.requestIDsLimit:]
		}
		fmt.Fprintf(r.writer, "  Request IDs: %s\n", strings.Join(requestIDs, ", "))
	}
}

func (r *TerminalReporter) GenerateReport(findings []*model.Finding, stats *Stats) error {
	fmt.Fprintf(r.writer, "\n=== Hadrian Security Test Results ===\n\n")

	fmt.Fprintf(r.writer, "Duration: %s\n", stats.Duration.Round(time.Second))
	fmt.Fprintf(r.writer, "Operations tested: %d\n", stats.OperationCount)
	fmt.Fprintf(r.writer, "Roles tested: %d\n", stats.RoleCount)
	fmt.Fprintf(r.writer, "Templates loaded: %d\n\n", stats.TemplatesLoaded)

	fmt.Fprintf(r.writer, "Findings Summary:\n")
	if stats.Critical > 0 {
		fmt.Fprintf(r.writer, "  %sCRITICAL: %d%s\n", colorRed, stats.Critical, colorReset)
	}
	if stats.High > 0 {
		fmt.Fprintf(r.writer, "  %sHIGH: %d%s\n", colorOrange, stats.High, colorReset)
	}
	if stats.Medium > 0 {
		fmt.Fprintf(r.writer, "  %sMEDIUM: %d%s\n", colorYellow, stats.Medium, colorReset)
	}
	if stats.Low > 0 {
		fmt.Fprintf(r.writer, "  %sLOW: %d%s\n", colorBlue, stats.Low, colorReset)
	}
	if stats.Info > 0 {
		fmt.Fprintf(r.writer, "  %sINFO: %d%s\n", colorGreen, stats.Info, colorReset)
	}

	fmt.Fprintf(r.writer, "\nTotal findings: %d\n", stats.Findings)
	return nil
}

func (r *TerminalReporter) Close() error {
	return nil
}

// JSONReporter outputs findings to JSON file
type JSONReporter struct {
	outputFile      string
	findings        []*model.Finding
	redactor        *reporter.Redactor
	requestIDsLimit int
}

func NewJSONReporter(outputFile string, requestIDsLimit int) (*JSONReporter, error) {
	return &JSONReporter{
		outputFile:      outputFile,
		findings:        make([]*model.Finding, 0),
		redactor:        reporter.NewRedactor(),
		requestIDsLimit: requestIDsLimit,
	}, nil
}

func (r *JSONReporter) ReportFinding(finding *model.Finding) {
	r.findings = append(r.findings, finding)
}

func (r *JSONReporter) GenerateReport(findings []*model.Finding, stats *Stats) error {
	// Limit request IDs in findings
	limitedFindings := make([]*model.Finding, len(findings))
	for i, f := range findings {
		limited := *f // Copy finding
		if len(limited.RequestIDs) > 0 && r.requestIDsLimit > 0 && len(limited.RequestIDs) > r.requestIDsLimit {
			limited.RequestIDs = limited.RequestIDs[len(limited.RequestIDs)-r.requestIDsLimit:]
		}
		limitedFindings[i] = &limited
	}

	report := map[string]interface{}{
		"stats":    stats,
		"findings": limitedFindings,
	}

	var output *os.File
	var err error

	if r.outputFile != "" {
		output, err = os.Create(r.outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer output.Close()
	} else {
		output = os.Stdout
	}

	// Pretty print JSON
	return writeJSON(output, report)
}

func (r *JSONReporter) Close() error {
	return nil
}

// MarkdownReporter outputs findings to Markdown file
type MarkdownReporter struct {
	outputFile      string
	findings        []*model.Finding
	redactor        *reporter.Redactor
	requestIDsLimit int
}

func NewMarkdownReporter(outputFile string, requestIDsLimit int) (*MarkdownReporter, error) {
	return &MarkdownReporter{
		outputFile:      outputFile,
		findings:        make([]*model.Finding, 0),
		redactor:        reporter.NewRedactor(),
		requestIDsLimit: requestIDsLimit,
	}, nil
}

func (r *MarkdownReporter) ReportFinding(finding *model.Finding) {
	r.findings = append(r.findings, finding)
}

func (r *MarkdownReporter) GenerateReport(findings []*model.Finding, stats *Stats) error {
	var output *os.File
	var err error

	if r.outputFile != "" {
		output, err = os.Create(r.outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer output.Close()
	} else {
		output = os.Stdout
	}

	// Write markdown header
	fmt.Fprintf(output, "# Hadrian Security Test Report\n\n")
	fmt.Fprintf(output, "**Duration:** %s\n\n", stats.Duration.Round(time.Second))

	// Summary table
	fmt.Fprintf(output, "## Summary\n\n")
	fmt.Fprintf(output, "| Severity | Count |\n")
	fmt.Fprintf(output, "|----------|-------|\n")
	fmt.Fprintf(output, "| Critical | %d |\n", stats.Critical)
	fmt.Fprintf(output, "| High | %d |\n", stats.High)
	fmt.Fprintf(output, "| Medium | %d |\n", stats.Medium)
	fmt.Fprintf(output, "| Low | %d |\n", stats.Low)
	fmt.Fprintf(output, "| Info | %d |\n", stats.Info)
	fmt.Fprintf(output, "| **Total** | **%d** |\n\n", stats.Findings)

	// Findings
	fmt.Fprintf(output, "## Findings\n\n")
	for i, f := range findings {
		fmt.Fprintf(output, "### %d. [%s] %s - %s\n\n", i+1, f.Severity, f.Category, f.Name)
		fmt.Fprintf(output, "**Endpoint:** `%s %s`\n\n", f.Method, f.Endpoint)
		fmt.Fprintf(output, "**Description:** %s\n\n", f.Description)

		if f.AttackerRole != "" {
			fmt.Fprintf(output, "**Attacker Role:** %s\n\n", f.AttackerRole)
		}
		if f.VictimRole != "" {
			fmt.Fprintf(output, "**Victim Role:** %s\n\n", f.VictimRole)
		}

		// Show limited request IDs if available
		if len(f.RequestIDs) > 0 {
			requestIDs := f.RequestIDs
			if r.requestIDsLimit > 0 && len(requestIDs) > r.requestIDsLimit {
				requestIDs = requestIDs[len(requestIDs)-r.requestIDsLimit:]
			}
			fmt.Fprintf(output, "**Request IDs:** %s\n\n", strings.Join(requestIDs, ", "))
		}

		if f.LLMAnalysis != nil {
			fmt.Fprintf(output, "**LLM Analysis:**\n")
			fmt.Fprintf(output, "- Vulnerability: %t (%.0f%% confidence)\n", f.LLMAnalysis.IsVulnerability, f.LLMAnalysis.Confidence*100)
			fmt.Fprintf(output, "- Reasoning: %s\n\n", f.LLMAnalysis.Reasoning)
		}

		fmt.Fprintf(output, "---\n\n")
	}

	return nil
}

func (r *MarkdownReporter) Close() error {
	return nil
}

// =============================================================================
// HELPERS
// =============================================================================

// Import color constants from pkg/log to avoid duplication (DRY)
const (
	colorReset   = log.ColorReset
	colorRed     = log.ColorRed
	colorYellow  = log.ColorYellow
	colorGreen   = log.ColorGreen
	colorBlue    = log.ColorBlue
	colorMagenta = log.ColorMagenta
	colorBold    = log.ColorBold
	colorOrange  = "\033[38;5;208m" // 256-color orange
)

func getSeverityColor(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical:
		return colorRed
	case model.SeverityHigh:
		return colorOrange
	case model.SeverityMedium:
		return colorYellow
	case model.SeverityLow:
		return colorBlue
	case model.SeverityInfo:
		return colorGreen
	default:
		return colorReset
	}
}

// writeJSON writes value to writer with pretty formatting
func writeJSON(w io.Writer, v interface{}) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(v)
}
