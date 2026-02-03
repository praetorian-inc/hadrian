package reporter

import (
	"bytes"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTerminalReporter_NoFindings verifies that when no findings are generated,
// no request IDs appear (even though requests were made)
func TestTerminalReporter_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewTerminalReporter(&buf, false)

	stats := NewStats()
	stats.TotalOperations = 10
	stats.TotalTemplates = 5

	// Generate report with NO findings (requests were made, but none matched)
	err := reporter.GenerateReport([]*model.Finding{}, stats)

	require.NoError(t, err)
	output := buf.String()

	// Should show summary but no findings
	assert.Contains(t, output, "SUMMARY")
	assert.Contains(t, output, "0", "should show 0 findings")

	// Should NOT show any request IDs (no findings to report)
	assert.NotContains(t, output, "Request IDs:")
}
