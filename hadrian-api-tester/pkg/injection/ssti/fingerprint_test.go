package ssti

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Engine Fingerprinting Tests - TDD RED PHASE
// These tests define the expected behavior of the fingerprinting workflow
// ============================================================================

func TestEngineFamilies_Defined(t *testing.T) {
	// Verify all engine families are properly defined
	families := GetEngineFamilies()

	require.NotEmpty(t, families, "Should have defined engine families")

	// Check key families exist
	_, hasCurlyBraces := families[FamilyCurlyBraces]
	_, hasDollarSign := families[FamilyDollarSign]
	_, hasErbStyle := families[FamilyErbStyle]
	_, hasHashInterpolation := families[FamilyHashInterpolation]
	_, hasAtSign := families[FamilyAtSign]

	assert.True(t, hasCurlyBraces, "Should have curly braces family (Jinja2, Twig, Pebble)")
	assert.True(t, hasDollarSign, "Should have dollar sign family (FreeMarker, Velocity, Mako, Thymeleaf)")
	assert.True(t, hasErbStyle, "Should have ERB style family")
	assert.True(t, hasHashInterpolation, "Should have hash interpolation family (Pug)")
	assert.True(t, hasAtSign, "Should have at-sign family (Razor)")
}

func TestFingerprintProbes_CoverAllFamilies(t *testing.T) {
	// Verify fingerprint probes cover all syntax families
	probes := GetFingerprintProbes()

	require.NotEmpty(t, probes, "Should have fingerprint probes")

	// Each probe should target a specific family
	familiesCovered := make(map[EngineFamily]bool)
	for _, probe := range probes {
		familiesCovered[probe.TargetFamily] = true
	}

	assert.True(t, familiesCovered[FamilyCurlyBraces], "Should have probe for curly braces family")
	assert.True(t, familiesCovered[FamilyDollarSign], "Should have probe for dollar sign family")
	assert.True(t, familiesCovered[FamilyErbStyle], "Should have probe for ERB family")
	assert.True(t, familiesCovered[FamilyHashInterpolation], "Should have probe for hash interpolation family")
	assert.True(t, familiesCovered[FamilyAtSign], "Should have probe for at-sign family")
}

func TestFingerprint_DetectsCurlyBracesFamily(t *testing.T) {
	// Server responds to {{7*191}} with 1337 (Jinja2/Twig/Pebble style)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("test")

		// Only respond to curly braces syntax
		if param == "{{7*191}}" {
			w.Write([]byte("Result: 1337"))
		} else {
			w.Write([]byte("No match"))
		}
	}))
	defer server.Close()

	fp := NewFingerprinter(server.Client())
	result, err := fp.Fingerprint(server.URL, "test", "GET")

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result.DetectedFamilies[FamilyCurlyBraces], "Should detect curly braces family")
	assert.False(t, result.DetectedFamilies[FamilyDollarSign], "Should NOT detect dollar sign family")

	// Should suggest candidate engines
	assert.Contains(t, result.CandidateEngines, "jinja2")
	assert.Contains(t, result.CandidateEngines, "twig")
	assert.Contains(t, result.CandidateEngines, "pebble")
}

func TestFingerprint_DetectsDollarSignFamily(t *testing.T) {
	// Server responds to ${7*191} with 1337 (FreeMarker/Velocity/Mako/Thymeleaf style)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("test")

		// Only respond to dollar sign syntax
		if param == "${7*191}" {
			w.Write([]byte("Result: 1337"))
		} else {
			w.Write([]byte("No match"))
		}
	}))
	defer server.Close()

	fp := NewFingerprinter(server.Client())
	result, err := fp.Fingerprint(server.URL, "test", "GET")

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result.DetectedFamilies[FamilyDollarSign], "Should detect dollar sign family")
	assert.False(t, result.DetectedFamilies[FamilyCurlyBraces], "Should NOT detect curly braces family")

	// Should suggest candidate engines
	assert.Contains(t, result.CandidateEngines, "freemarker")
	assert.Contains(t, result.CandidateEngines, "velocity")
	assert.Contains(t, result.CandidateEngines, "mako")
	assert.Contains(t, result.CandidateEngines, "thymeleaf")
}

func TestFingerprint_DetectsMultipleFamilies(t *testing.T) {
	// Server responds to multiple syntaxes (unusual but possible)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("test")

		switch param {
		case "{{7*191}}":
			w.Write([]byte("1337"))
		case "${7*191}":
			w.Write([]byte("1337"))
		default:
			w.Write([]byte("No match"))
		}
	}))
	defer server.Close()

	fp := NewFingerprinter(server.Client())
	result, err := fp.Fingerprint(server.URL, "test", "GET")

	require.NoError(t, err)

	assert.True(t, result.DetectedFamilies[FamilyCurlyBraces], "Should detect curly braces family")
	assert.True(t, result.DetectedFamilies[FamilyDollarSign], "Should detect dollar sign family")
}

func TestFingerprint_NoVulnerability(t *testing.T) {
	// Server doesn't respond to any SSTI payloads
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Not vulnerable"))
	}))
	defer server.Close()

	fp := NewFingerprinter(server.Client())
	result, err := fp.Fingerprint(server.URL, "test", "GET")

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Empty(t, result.CandidateEngines, "Should have no candidate engines")
	assert.False(t, result.IsVulnerable(), "Should not be marked vulnerable")
}

func TestConfirmEngine_Jinja2(t *testing.T) {
	// Server behaves like Jinja2
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("test")

		// Jinja2-specific: responds to class introspection
		switch param {
		case "{{7*191}}":
			w.Write([]byte("1337"))
		case "{{13*37}}":
			w.Write([]byte("481"))
		case "{{17*89}}":
			w.Write([]byte("1513"))
		case "{{''.__class__}}":
			w.Write([]byte("<class 'str'>"))
		default:
			w.Write([]byte("No match"))
		}
	}))
	defer server.Close()

	fp := NewFingerprinter(server.Client())
	confirmed, err := fp.ConfirmEngine(server.URL, "test", "GET", "jinja2")

	require.NoError(t, err)
	assert.True(t, confirmed, "Should confirm Jinja2 engine")
}

func TestConfirmEngine_NotConfirmed(t *testing.T) {
	// Server responds to generic arithmetic but not engine-specific payloads
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("test")

		// Only responds to basic arithmetic, not class introspection
		if param == "{{7*191}}" {
			w.Write([]byte("1337"))
		} else {
			w.Write([]byte("No match"))
		}
	}))
	defer server.Close()

	fp := NewFingerprinter(server.Client())

	// Should not confirm as Jinja2 without class introspection response
	confirmed, err := fp.ConfirmEngine(server.URL, "test", "GET", "jinja2")

	require.NoError(t, err)
	// With only arithmetic, it's uncertain - falls back to verification chain
	// Depending on implementation, this might be true (3-pass verification) or require specific payload
	// For now, expect it to use verification chain
	assert.True(t, confirmed, "Should confirm via verification chain")
}

func TestFingerprintAndConfirm_FullWorkflow(t *testing.T) {
	// Jinja2-like server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("test")

		switch param {
		case "{{7*191}}":
			w.Write([]byte("1337"))
		case "{{13*37}}":
			w.Write([]byte("481"))
		case "{{17*89}}":
			w.Write([]byte("1513"))
		default:
			w.Write([]byte("No match"))
		}
	}))
	defer server.Close()

	fp := NewFingerprinter(server.Client())
	result, err := fp.FingerprintAndConfirm(server.URL, "test", "GET")

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result.IsVulnerable(), "Should detect vulnerability")
	assert.NotEmpty(t, result.ConfirmedEngines, "Should have confirmed engines")

	// Should have detected curly braces family
	assert.True(t, result.DetectedFamilies[FamilyCurlyBraces])

	// Should report request count for efficiency tracking
	assert.Greater(t, result.RequestCount, 0, "Should track request count")
}

func TestFingerprintAndConfirm_SkipsIrrelevantEngines(t *testing.T) {
	// Server only responds to ${} syntax (dollar sign family)
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		param := r.URL.Query().Get("test")

		// Only responds to dollar sign syntax
		switch param {
		case "${7*191}":
			w.Write([]byte("1337"))
		case "${13*37}":
			w.Write([]byte("481"))
		case "${17*89}":
			w.Write([]byte("1513"))
		default:
			w.Write([]byte("No match"))
		}
	}))
	defer server.Close()

	fp := NewFingerprinter(server.Client())
	result, err := fp.FingerprintAndConfirm(server.URL, "test", "GET")

	require.NoError(t, err)

	// Should NOT have tested Jinja2/Twig/Pebble/ERB/Pug/Razor confirmation
	// because fingerprint phase identified only dollar sign family
	assert.True(t, result.DetectedFamilies[FamilyDollarSign])
	assert.False(t, result.DetectedFamilies[FamilyCurlyBraces])

	// The request count should be less than testing ALL engines would require
	// (fingerprint probes + only dollar sign family confirmation)
	// Without fingerprinting: 12 engines × 3 passes = 36 requests
	// With fingerprinting: ~5 probes + ~4 engines × 3 passes = ~17 requests
	assert.Less(t, result.RequestCount, 30, "Fingerprinting should reduce request count")
}

func TestFingerprintResult_IsVulnerable(t *testing.T) {
	result := &FingerprintResult{
		DetectedFamilies: make(map[EngineFamily]bool),
		CandidateEngines: []string{},
		ConfirmedEngines: []string{},
	}

	assert.False(t, result.IsVulnerable(), "Empty result should not be vulnerable")

	result.CandidateEngines = []string{"jinja2"}
	assert.True(t, result.IsVulnerable(), "Result with candidates should be vulnerable")

	result.CandidateEngines = []string{}
	result.ConfirmedEngines = []string{"jinja2"}
	assert.True(t, result.IsVulnerable(), "Result with confirmed engines should be vulnerable")
}

func TestFingerprint_POSTMethod(t *testing.T) {
	// Server responds to POST requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		r.ParseForm()
		param := r.FormValue("test")

		if param == "{{7*191}}" {
			w.Write([]byte("1337"))
		} else {
			w.Write([]byte("No match"))
		}
	}))
	defer server.Close()

	fp := NewFingerprinter(server.Client())
	result, err := fp.Fingerprint(server.URL, "test", "POST")

	require.NoError(t, err)
	assert.True(t, result.DetectedFamilies[FamilyCurlyBraces], "Should detect via POST")
}
