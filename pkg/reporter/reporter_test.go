package reporter

import (
	"testing"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStats(t *testing.T) {
	stats := NewStats()

	require.NotNil(t, stats)
	assert.NotNil(t, stats.BySeverity, "BySeverity map should be initialized")
	assert.NotNil(t, stats.ByCategory, "ByCategory map should be initialized")
	assert.Equal(t, 0, stats.TotalOperations)
	assert.Equal(t, 0, stats.TotalTemplates)
	assert.Equal(t, 0, stats.TotalFindings)
	assert.Equal(t, time.Duration(0), stats.Duration)
}

func TestStatsCanTrackSeverityCounts(t *testing.T) {
	stats := NewStats()

	stats.BySeverity[model.SeverityCritical] = 2
	stats.BySeverity[model.SeverityHigh] = 5
	stats.BySeverity[model.SeverityMedium] = 10

	assert.Equal(t, 2, stats.BySeverity[model.SeverityCritical])
	assert.Equal(t, 5, stats.BySeverity[model.SeverityHigh])
	assert.Equal(t, 10, stats.BySeverity[model.SeverityMedium])
}

func TestStatsCanTrackCategoryCounts(t *testing.T) {
	stats := NewStats()

	stats.ByCategory["API1"] = 3
	stats.ByCategory["API2"] = 7

	assert.Equal(t, 3, stats.ByCategory["API1"])
	assert.Equal(t, 7, stats.ByCategory["API2"])
}

// Helper to create a test finding
func createTestFinding(severity model.Severity, category string) *model.Finding {
	return &model.Finding{
		ID:              "test-finding-1",
		Category:        category,
		Name:            "Test Finding",
		Description:     "This is a test finding",
		Severity:        severity,
		Confidence:      0.95,
		IsVulnerability: true,
		Endpoint:        "GET /api/users/{id}",
		Method:          "GET",
		AttackerRole:    "attacker",
		VictimRole:      "victim",
		Evidence: model.Evidence{
			Request: model.HTTPRequest{
				Method:  "GET",
				URL:     "https://api.example.com/users/123",
				Headers: map[string]string{"Authorization": "Bearer token123"},
				Body:    "",
			},
			Response: model.HTTPResponse{
				StatusCode: 200,
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       `{"id": 123, "email": "user@example.com"}`,
				BodyHash:   "abc123",
				Size:       40,
				Truncated:  false,
			},
		},
		Timestamp: time.Now(),
	}
}

// createTestStats creates a Stats instance with sample data for testing
func createTestStats() *Stats {
	stats := NewStats()
	stats.TotalOperations = 100
	stats.TotalTemplates = 25
	stats.TotalFindings = 5
	stats.Duration = 30 * time.Second
	stats.BySeverity[model.SeverityCritical] = 1
	stats.BySeverity[model.SeverityHigh] = 2
	stats.BySeverity[model.SeverityMedium] = 2
	stats.ByCategory["API1"] = 3
	stats.ByCategory["API2"] = 2
	return stats
}
