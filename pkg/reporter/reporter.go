package reporter

import (
	"time"

	"github.com/praetorian-inc/hadrian/pkg/model"
)

// Reporter outputs security findings in a specific format
type Reporter interface {
	// ReportFinding outputs a single finding in real-time (for terminal)
	ReportFinding(finding *model.Finding) error

	// GenerateReport creates the final report from all findings
	GenerateReport(findings []*model.Finding, stats *Stats) error
}

// Stats contains summary statistics for a security scan
type Stats struct {
	TotalOperations int
	TotalTemplates  int
	TotalFindings   int
	Duration        time.Duration
	BySeverity      map[model.Severity]int
	ByCategory      map[string]int
}

// NewStats creates a new Stats instance with initialized maps
func NewStats() *Stats {
	return &Stats{
		BySeverity: make(map[model.Severity]int),
		ByCategory: make(map[string]int),
	}
}
