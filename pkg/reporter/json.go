package reporter

import (
	"encoding/json"
	"os"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/model"
)

// JSONReporter outputs findings in structured JSON format
type JSONReporter struct {
	outputPath string
	redactor   *Redactor
}

// NewJSONReporter creates a new JSONReporter with the specified output path
func NewJSONReporter(outputPath string) *JSONReporter {
	return &JSONReporter{
		outputPath: outputPath,
		redactor:   NewRedactor(),
	}
}

// JSONReport is the top-level structure for JSON output
type JSONReport struct {
	Metadata JSONMetadata     `json:"metadata"`
	Summary  JSONSummary      `json:"summary"`
	Findings []*model.Finding `json:"findings"`
}

// JSONMetadata contains report metadata
type JSONMetadata struct {
	Tool      string    `json:"tool"`
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
}

// JSONSummary contains aggregated statistics
type JSONSummary struct {
	TotalOperations int                    `json:"total_operations"`
	TotalTemplates  int                    `json:"total_templates"`
	TotalFindings   int                    `json:"total_findings"`
	Duration        string                 `json:"duration"`
	BySeverity      map[model.Severity]int `json:"by_severity"`
	ByCategory      map[string]int         `json:"by_category"`
}

// ReportFinding is a no-op for JSON reporter (batch output only)
func (r *JSONReporter) ReportFinding(finding *model.Finding) error {
	// JSON reporter only outputs during GenerateReport (batch mode)
	return nil
}

// GenerateReport creates the final JSON report with all findings
func (r *JSONReporter) GenerateReport(findings []*model.Finding, stats *Stats) error {
	// Create redacted copies of findings
	redactedFindings := make([]*model.Finding, len(findings))
	for i, f := range findings {
		redactedFindings[i] = r.redactFinding(f)
	}

	report := JSONReport{
		Metadata: JSONMetadata{
			Tool:      "hadrian",
			Version:   "1.0.0",
			Timestamp: time.Now(),
		},
		Summary: JSONSummary{
			TotalOperations: stats.TotalOperations,
			TotalTemplates:  stats.TotalTemplates,
			TotalFindings:   len(findings),
			Duration:        stats.Duration.String(),
			BySeverity:      stats.BySeverity,
			ByCategory:      stats.ByCategory,
		},
		Findings: redactedFindings,
	}

	// Marshal to JSON with indentation for readability
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(r.outputPath, data, 0600)
}

// redactFinding creates a copy of the finding with sensitive data redacted
func (r *JSONReporter) redactFinding(f *model.Finding) *model.Finding {
	// Create a deep copy by marshaling and unmarshaling
	data, err := json.Marshal(f)
	if err != nil {
		return f // Return original if copy fails
	}

	var copy model.Finding
	if err := json.Unmarshal(data, &copy); err != nil {
		return f // Return original if copy fails
	}

	// Redact sensitive fields using the Redactor (PII protection)
	copy.Evidence.Request.Body = r.redactor.Redact(copy.Evidence.Request.Body)
	copy.Evidence.Response.Body = r.redactor.Redact(copy.Evidence.Response.Body)

	// Redact headers that may contain sensitive data
	for k, v := range copy.Evidence.Request.Headers {
		copy.Evidence.Request.Headers[k] = r.redactor.Redact(v)
	}
	for k, v := range copy.Evidence.Response.Headers {
		copy.Evidence.Response.Headers[k] = r.redactor.Redact(v)
	}

	// Redact optional response bodies
	if copy.Evidence.SetupResponse != nil {
		copy.Evidence.SetupResponse.Body = r.redactor.Redact(copy.Evidence.SetupResponse.Body)
	}
	if copy.Evidence.AttackResponse != nil {
		copy.Evidence.AttackResponse.Body = r.redactor.Redact(copy.Evidence.AttackResponse.Body)
	}
	if copy.Evidence.VerifyResponse != nil {
		copy.Evidence.VerifyResponse.Body = r.redactor.Redact(copy.Evidence.VerifyResponse.Body)
	}

	return &copy
}
