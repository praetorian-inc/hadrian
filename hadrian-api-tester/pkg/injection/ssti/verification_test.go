package ssti

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyEngine_AllPassesConfirmed(t *testing.T) {
	// TDD RED: This test should fail until we implement verification chain logic
	module := NewSSTIModule()

	// Create test server that returns expected values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("test")

		// Return expected values for verification chain
		switch param {
		case "{{7*191}}":
			w.Write([]byte("Result: 1337"))
		case "{{13*37}}":
			w.Write([]byte("Result: 481"))
		case "{{17*89}}":
			w.Write([]byte("Result: 1513"))
		default:
			w.Write([]byte("Unknown"))
		}
	}))
	defer server.Close()

	// Create verification chain
	chain := []PayloadWithExpected{
		{Value: "{{7*191}}", Expected: "1337", Description: "Pass 1"},
		{Value: "{{13*37}}", Expected: "481", Description: "Pass 2"},
		{Value: "{{17*89}}", Expected: "1513", Description: "Pass 3"},
	}

	result := module.VerifyEngine(server.Client(), server.URL, "test", "GET", "jinja2", chain)

	assert.Equal(t, "jinja2", result.Engine)
	assert.Equal(t, 3, result.PassCount)
	assert.Equal(t, 3, result.TotalPasses)
	assert.True(t, result.Confirmed)
	assert.False(t, result.Uncertain)
	assert.Len(t, result.PassResults, 3)

	// All passes should be found
	for _, pass := range result.PassResults {
		assert.True(t, pass.Found)
	}
}

func TestVerifyEngine_PartialMatch_Uncertain(t *testing.T) {
	module := NewSSTIModule()

	// Server returns only first expected value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("test")

		if param == "{{7*191}}" {
			w.Write([]byte("Result: 1337"))
		} else {
			w.Write([]byte("No match"))
		}
	}))
	defer server.Close()

	chain := []PayloadWithExpected{
		{Value: "{{7*191}}", Expected: "1337", Description: "Pass 1"},
		{Value: "{{13*37}}", Expected: "481", Description: "Pass 2"},
		{Value: "{{17*89}}", Expected: "1513", Description: "Pass 3"},
	}

	result := module.VerifyEngine(server.Client(), server.URL, "test", "GET", "jinja2", chain)

	assert.Equal(t, 1, result.PassCount)
	assert.Equal(t, 3, result.TotalPasses)
	assert.False(t, result.Confirmed)
	assert.True(t, result.Uncertain)
	assert.True(t, result.PassResults[0].Found)
	assert.False(t, result.PassResults[1].Found)
	assert.False(t, result.PassResults[2].Found)
}

func TestVerifyEngine_NoMatches(t *testing.T) {
	module := NewSSTIModule()

	// Server returns no expected values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("No SSTI here"))
	}))
	defer server.Close()

	chain := []PayloadWithExpected{
		{Value: "{{7*191}}", Expected: "1337", Description: "Pass 1"},
		{Value: "{{13*37}}", Expected: "481", Description: "Pass 2"},
		{Value: "{{17*89}}", Expected: "1513", Description: "Pass 3"},
	}

	result := module.VerifyEngine(server.Client(), server.URL, "test", "GET", "jinja2", chain)

	assert.Equal(t, 0, result.PassCount)
	assert.False(t, result.Confirmed)
	assert.False(t, result.Uncertain)
}

func TestRunVerification_MultipleEngines(t *testing.T) {
	module := NewSSTIModule()

	// Server that responds to jinja2 but not twig
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("test")

		// Only respond to jinja2-style payloads
		switch param {
		case "{{7*191}}", "{{13*37}}", "{{17*89}}":
			// Extract and calculate
			if param == "{{7*191}}" {
				w.Write([]byte("1337"))
			} else if param == "{{13*37}}" {
				w.Write([]byte("481"))
			} else if param == "{{17*89}}" {
				w.Write([]byte("1513"))
			}
		default:
			w.Write([]byte("No match"))
		}
	}))
	defer server.Close()

	// Create engine configs with verification chains
	engines := map[string][]PayloadWithExpected{
		"jinja2": {
			{Value: "{{7*191}}", Expected: "1337", Description: "Pass 1"},
			{Value: "{{13*37}}", Expected: "481", Description: "Pass 2"},
			{Value: "{{17*89}}", Expected: "1513", Description: "Pass 3"},
		},
		"twig": {
			{Value: "{{7*191}}", Expected: "1337", Description: "Pass 1"},
			{Value: "{{13*37}}", Expected: "481", Description: "Pass 2"},
			{Value: "{{17*89}}", Expected: "1513", Description: "Pass 3"},
		},
	}

	results := module.RunVerification(server.Client(), server.URL, "test", "GET", engines)

	require.Len(t, results, 2)

	// Find jinja2 and twig results
	var jinja2Result, twigResult *VerificationResult
	for i := range results {
		if results[i].Engine == "jinja2" {
			jinja2Result = &results[i]
		} else if results[i].Engine == "twig" {
			twigResult = &results[i]
		}
	}

	require.NotNil(t, jinja2Result)
	require.NotNil(t, twigResult)

	// Jinja2 should be confirmed
	assert.True(t, jinja2Result.Confirmed)
	assert.Equal(t, 3, jinja2Result.PassCount)

	// Twig should be confirmed too (same syntax works)
	assert.True(t, twigResult.Confirmed)
}

func TestLoadPayloadFileWithPayloads(t *testing.T) {
	// Test loading YAML with payloads field (all payloads are verification chain)
	yamlContent := `engine: jinja2
payloads:
  - value: "{{7*191}}"
    expected: "1337"
    description: "Pass 1: Uncommon multiplication"

  - value: "{{13*37}}"
    expected: "481"
    description: "Pass 2: Prime multiplication"

  - value: "{{17*89}}"
    expected: "1513"
    description: "Pass 3: Large prime multiplication"
`

	// Write temp file
	tmpDir := t.TempDir()
	testFile := tmpDir + "/test.yaml"
	require.NoError(t, os.WriteFile(testFile, []byte(yamlContent), 0644))

	// Load and verify
	payloadFile, err := LoadPayloadFileWithPayloads(testFile)
	require.NoError(t, err)

	assert.Equal(t, "jinja2", payloadFile.Engine)
	assert.Len(t, payloadFile.Payloads, 3)

	// Verify payload contents (all payloads are treated as verification chain)
	assert.Equal(t, "{{7*191}}", payloadFile.Payloads[0].Value)
	assert.Equal(t, "1337", payloadFile.Payloads[0].Expected)
	assert.Equal(t, "{{13*37}}", payloadFile.Payloads[1].Value)
	assert.Equal(t, "481", payloadFile.Payloads[1].Expected)
	assert.Equal(t, "{{17*89}}", payloadFile.Payloads[2].Value)
	assert.Equal(t, "1513", payloadFile.Payloads[2].Expected)
}
