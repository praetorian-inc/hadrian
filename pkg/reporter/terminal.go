package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/model"
)

// ANSI color codes
const (
	colorReset    = "\033[0m"
	colorRed      = "\033[31m"
	colorRedBold  = "\033[1;31m"
	colorYellow   = "\033[33m"
	colorCyan     = "\033[36m"
	colorGreen    = "\033[32m"
	colorWhite    = "\033[37m"
	colorGray     = "\033[90m"
)

// TerminalReporter outputs findings to a terminal with optional color support
type TerminalReporter struct {
	writer   io.Writer
	useColor bool
	redactor *Redactor
}

// NewTerminalReporter creates a new TerminalReporter
func NewTerminalReporter(w io.Writer, useColor bool) *TerminalReporter {
	return &TerminalReporter{
		writer:   w,
		useColor: useColor,
		redactor: NewRedactor(),
	}
}

// ReportFinding outputs a single finding immediately to the terminal
func (r *TerminalReporter) ReportFinding(finding *model.Finding) error {
	// Get severity color
	severityColor := r.getSeverityColor(finding.Severity)

	// Format the finding output
	var sb strings.Builder

	// Severity and name line
	if r.useColor {
		sb.WriteString(fmt.Sprintf("[%s%s%s] ", severityColor, finding.Severity, colorReset))
	} else {
		sb.WriteString(fmt.Sprintf("[%s] ", finding.Severity))
	}
	sb.WriteString(fmt.Sprintf("%s (%s)\n", finding.Name, finding.Category))

	// Endpoint
	sb.WriteString(fmt.Sprintf("  Endpoint: %s\n", finding.Endpoint))

	// Description (truncated if too long)
	desc := finding.Description
	if len(desc) > 100 {
		desc = desc[:100] + "..."
	}
	sb.WriteString(fmt.Sprintf("  Description: %s\n", desc))

	// Confidence
	sb.WriteString(fmt.Sprintf("  Confidence: %.0f%%\n", finding.Confidence*100))

	// Redact and show response body summary if available
	if finding.Evidence.Response.Body != "" {
		body := r.redactor.Redact(finding.Evidence.Response.Body)
		if len(body) > 80 {
			body = body[:80] + "..."
		}
		sb.WriteString(fmt.Sprintf("  Response: %s\n", body))
	}

	sb.WriteString("\n")

	_, err := r.writer.Write([]byte(sb.String()))
	return err
}

// GenerateReport prints a summary banner with statistics
func (r *TerminalReporter) GenerateReport(findings []*model.Finding, stats *Stats) error {
	var sb strings.Builder

	// Header
	sb.WriteString("\n")
	sb.WriteString(r.formatLine("=", 60))
	sb.WriteString("  HADRIAN SCAN SUMMARY\n")
	sb.WriteString(r.formatLine("=", 60))

	// Statistics
	sb.WriteString(fmt.Sprintf("  Duration:        %s\n", stats.Duration.String()))
	sb.WriteString(fmt.Sprintf("  Operations:      %d\n", stats.TotalOperations))
	sb.WriteString(fmt.Sprintf("  Templates:       %d\n", stats.TotalTemplates))
	sb.WriteString(fmt.Sprintf("  Total Findings:  %d\n", stats.TotalFindings))
	sb.WriteString("\n")

	// Severity breakdown
	sb.WriteString("  Findings by Severity:\n")
	severityOrder := []model.Severity{
		model.SeverityCritical,
		model.SeverityHigh,
		model.SeverityMedium,
		model.SeverityLow,
		model.SeverityInfo,
	}

	for _, sev := range severityOrder {
		count := stats.BySeverity[sev]
		if count > 0 || sev == model.SeverityCritical || sev == model.SeverityHigh {
			if r.useColor {
				color := r.getSeverityColor(sev)
				sb.WriteString(fmt.Sprintf("    %s%-10s%s %d\n", color, sev, colorReset, count))
			} else {
				sb.WriteString(fmt.Sprintf("    %-10s %d\n", sev, count))
			}
		}
	}

	// Category breakdown if present
	if len(stats.ByCategory) > 0 {
		sb.WriteString("\n  Findings by Category:\n")
		for category, count := range stats.ByCategory {
			sb.WriteString(fmt.Sprintf("    %-10s %d\n", category, count))
		}
	}

	sb.WriteString("\n")
	sb.WriteString(r.formatLine("=", 60))

	_, err := r.writer.Write([]byte(sb.String()))
	return err
}

// getSeverityColor returns the ANSI color code for a severity level
func (r *TerminalReporter) getSeverityColor(severity model.Severity) string {
	if !r.useColor {
		return ""
	}

	switch severity {
	case model.SeverityCritical:
		return colorRedBold
	case model.SeverityHigh:
		return colorRed
	case model.SeverityMedium:
		return colorYellow
	case model.SeverityLow:
		return colorCyan
	case model.SeverityInfo:
		return colorWhite
	default:
		return colorWhite
	}
}

// formatLine creates a line of repeated characters
func (r *TerminalReporter) formatLine(char string, length int) string {
	return strings.Repeat(char, length) + "\n"
}
