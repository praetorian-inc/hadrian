package reporter

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/model"
)

// MarkdownReporter outputs findings in readable markdown format
type MarkdownReporter struct {
	outputPath string
	redactor   *Redactor
}

// NewMarkdownReporter creates a new MarkdownReporter with the specified output path
func NewMarkdownReporter(outputPath string) *MarkdownReporter {
	return &MarkdownReporter{
		outputPath: outputPath,
		redactor:   NewRedactor(),
	}
}

// ReportFinding is a no-op for Markdown reporter (batch output only)
func (r *MarkdownReporter) ReportFinding(finding *model.Finding) error {
	// Markdown reporter only outputs during GenerateReport (batch mode)
	return nil
}

// GenerateReport creates the final markdown report with all findings
func (r *MarkdownReporter) GenerateReport(findings []*model.Finding, stats *Stats) error {
	var sb strings.Builder

	// Header
	sb.WriteString("# Hadrian Security Report\n\n")
	fmt.Fprintf(&sb, "**Generated:** %s\n\n", time.Now().Format(time.RFC3339))

	// Summary section
	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")
	fmt.Fprintf(&sb, "| Duration | %s |\n", stats.Duration.String())
	fmt.Fprintf(&sb, "| Operations | %d |\n", stats.TotalOperations)
	fmt.Fprintf(&sb, "| Templates | %d |\n", stats.TotalTemplates)
	fmt.Fprintf(&sb, "| Total Findings | %d |\n", stats.TotalFindings)
	sb.WriteString("\n")

	// Severity breakdown
	sb.WriteString("### Findings by Severity\n\n")
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|-------|\n")
	severityOrder := []model.Severity{
		model.SeverityCritical,
		model.SeverityHigh,
		model.SeverityMedium,
		model.SeverityLow,
		model.SeverityInfo,
	}
	for _, sev := range severityOrder {
		count := stats.BySeverity[sev]
		fmt.Fprintf(&sb, "| %s | %d |\n", sev, count)
	}
	sb.WriteString("\n")

	// Category breakdown if present
	if len(stats.ByCategory) > 0 {
		sb.WriteString("### Findings by Category\n\n")
		sb.WriteString("| Category | Count |\n")
		sb.WriteString("|----------|-------|\n")
		for category, count := range stats.ByCategory {
			fmt.Fprintf(&sb, "| %s | %d |\n", category, count)
		}
		sb.WriteString("\n")
	}

	// Findings section
	sb.WriteString("---\n\n")
	sb.WriteString("## Findings\n\n")

	if len(findings) == 0 {
		sb.WriteString("**No findings were detected during this scan.**\n\n")
	} else {
		// Group findings by severity
		grouped := r.groupBySeverity(findings)

		for _, sev := range severityOrder {
			if sevFindings, ok := grouped[sev]; ok && len(sevFindings) > 0 {
				fmt.Fprintf(&sb, "### %s\n\n", r.formatSeverityTitle(sev))

				for i, finding := range sevFindings {
					r.writeFinding(&sb, finding, i+1)
				}
			}
		}
	}

	return os.WriteFile(r.outputPath, []byte(sb.String()), 0600)
}

// groupBySeverity groups findings by their severity level
func (r *MarkdownReporter) groupBySeverity(findings []*model.Finding) map[model.Severity][]*model.Finding {
	grouped := make(map[model.Severity][]*model.Finding)
	for _, f := range findings {
		grouped[f.Severity] = append(grouped[f.Severity], f)
	}

	// Sort each group by confidence (highest first)
	for sev := range grouped {
		sort.Slice(grouped[sev], func(i, j int) bool {
			return grouped[sev][i].Confidence > grouped[sev][j].Confidence
		})
	}

	return grouped
}

// formatSeverityTitle formats severity for section headers
func (r *MarkdownReporter) formatSeverityTitle(sev model.Severity) string {
	switch sev {
	case model.SeverityCritical:
		return "Critical"
	case model.SeverityHigh:
		return "High"
	case model.SeverityMedium:
		return "Medium"
	case model.SeverityLow:
		return "Low"
	case model.SeverityInfo:
		return "Informational"
	default:
		return string(sev)
	}
}

// writeFinding writes a single finding to the markdown output
func (r *MarkdownReporter) writeFinding(sb *strings.Builder, finding *model.Finding, index int) {
	// Finding header
	fmt.Fprintf(sb, "#### %d. %s (%s)\n\n", index, finding.Name, finding.Category)

	// Description
	fmt.Fprintf(sb, "**Description:** %s\n\n", finding.Description)

	// Metadata
	fmt.Fprintf(sb, "- **Endpoint:** `%s`\n", finding.Endpoint)
	fmt.Fprintf(sb, "- **Confidence:** %.0f%%\n", finding.Confidence*100)
	if finding.AttackerRole != "" {
		fmt.Fprintf(sb, "- **Attacker Role:** %s\n", finding.AttackerRole)
	}
	if finding.VictimRole != "" {
		fmt.Fprintf(sb, "- **Victim Role:** %s\n", finding.VictimRole)
	}
	if len(finding.RequestIDs) > 0 {
		fmt.Fprintf(sb, "- **Request IDs:** %s\n", strings.Join(finding.RequestIDs, ", "))
	}
	sb.WriteString("\n")

	// Evidence section
	sb.WriteString("**Evidence:**\n\n")

	// Request
	sb.WriteString("*Request:*\n")
	sb.WriteString("```http\n")
	fmt.Fprintf(sb, "%s %s\n", finding.Evidence.Request.Method, finding.Evidence.Request.URL)
	for k, v := range finding.Evidence.Request.Headers {
		fmt.Fprintf(sb, "%s: %s\n", k, r.redactor.Redact(v))
	}
	if finding.Evidence.Request.Body != "" {
		sb.WriteString("\n")
		sb.WriteString(r.redactor.Redact(finding.Evidence.Request.Body))
		sb.WriteString("\n")
	}
	sb.WriteString("```\n\n")

	// Response
	sb.WriteString("*Response:*\n")
	sb.WriteString("```http\n")
	fmt.Fprintf(sb, "HTTP %d\n", finding.Evidence.Response.StatusCode)
	for k, v := range finding.Evidence.Response.Headers {
		fmt.Fprintf(sb, "%s: %s\n", k, r.redactor.Redact(v))
	}
	if finding.Evidence.Response.Body != "" {
		sb.WriteString("\n")
		// Truncate long response bodies
		body := r.redactor.Redact(finding.Evidence.Response.Body)
		if len(body) > 500 {
			body = body[:500] + "\n... [truncated]"
		}
		sb.WriteString(body)
		sb.WriteString("\n")
	}
	sb.WriteString("```\n\n")

	// Remediation section (if LLM analysis available)
	if finding.LLMAnalysis != nil && finding.LLMAnalysis.Recommendations != "" {
		sb.WriteString("**Remediation:**\n\n")
		sb.WriteString(finding.LLMAnalysis.Recommendations)
		sb.WriteString("\n\n")

		if finding.LLMAnalysis.Reasoning != "" {
			sb.WriteString("*Analysis:* ")
			sb.WriteString(finding.LLMAnalysis.Reasoning)
			sb.WriteString("\n\n")
		}
	}

	sb.WriteString("---\n\n")
}
