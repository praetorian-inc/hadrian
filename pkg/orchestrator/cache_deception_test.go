package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/hadrian/pkg/templates"
)

// --- bodyLeaked ---

func TestBodyLeaked_ShortCanaryGuard(t *testing.T) {
	// A short/low-entropy canary value (e.g. an "id" field extracting "1")
	// must fail safe: not-leaked, empty canary — this is must-fix M3.
	cfg := &templates.CacheDeception{CanaryField: "id"}
	primeBody := `{"id":1}`
	anonBody := `{"id":1,"other":"anything"}`

	leaked, canary := bodyLeaked(primeBody, anonBody, cfg)

	assert.False(t, leaked)
	assert.Empty(t, canary)
}

func TestBodyLeaked_CanaryHappyPath(t *testing.T) {
	cfg := &templates.CacheDeception{CanaryField: "email"}
	primeBody := `{"email":"victim@example.com"}`
	anonBody := `{"email":"victim@example.com","cached":true}`

	leaked, canary := bodyLeaked(primeBody, anonBody, cfg)

	assert.True(t, leaked)
	assert.Equal(t, "victim@example.com", canary)
}

func TestBodyLeaked_CanaryPresentButAbsentFromAnonBody(t *testing.T) {
	cfg := &templates.CacheDeception{CanaryField: "email"}
	primeBody := `{"email":"victim@example.com"}`
	anonBody := `{"email":"someone-else@example.com"}`

	leaked, canary := bodyLeaked(primeBody, anonBody, cfg)

	assert.False(t, leaked)
	assert.Equal(t, "victim@example.com", canary)
}

func TestBodyLeaked_CanaryFieldMissingFromPrimeBody(t *testing.T) {
	cfg := &templates.CacheDeception{CanaryField: "email"}
	primeBody := `{"id":1}` // no "email" field present
	anonBody := `{"id":1}`

	leaked, canary := bodyLeaked(primeBody, anonBody, cfg)

	assert.False(t, leaked)
	assert.Empty(t, canary)
}

func TestBodyLeaked_BodyEqualityMode_NilConfig_IdenticalNonEmptyBodies(t *testing.T) {
	body := `{"data":"victim content"}`

	leaked, canary := bodyLeaked(body, body, nil)

	assert.True(t, leaked)
	assert.Empty(t, canary)
}

func TestBodyLeaked_BodyEqualityMode_EmptyCanaryField_IdenticalNonEmptyBodies(t *testing.T) {
	cfg := &templates.CacheDeception{CanaryField: ""}
	body := `{"data":"victim content"}`

	leaked, canary := bodyLeaked(body, body, cfg)

	assert.True(t, leaked)
	assert.Empty(t, canary)
}

func TestBodyLeaked_BodyEqualityMode_DifferingBodies(t *testing.T) {
	leaked, canary := bodyLeaked(`{"data":"victim content"}`, `{"data":"different content"}`, nil)

	assert.False(t, leaked)
	assert.Empty(t, canary)
}

func TestBodyLeaked_BodyEqualityMode_BothEmpty(t *testing.T) {
	leaked, canary := bodyLeaked("", "", nil)

	assert.False(t, leaked)
	assert.Empty(t, canary)
}

func TestBodyLeaked_BodyEqualityMode_AnonEmptyPrimeNonEmpty(t *testing.T) {
	leaked, canary := bodyLeaked(`{"data":"victim content"}`, "", nil)

	assert.False(t, leaked)
	assert.Empty(t, canary)
}

// --- hasCacheHitHeader ---

func TestHasCacheHitHeader_Default_CFCacheStatusHit(t *testing.T) {
	headers := map[string]string{"Cf-Cache-Status": "HIT"}

	assert.True(t, hasCacheHitHeader(headers, nil))
}

func TestHasCacheHitHeader_Default_XCacheTCPHit(t *testing.T) {
	headers := map[string]string{"X-Cache": "TCP_HIT"}

	assert.True(t, hasCacheHitHeader(headers, nil))
}

func TestHasCacheHitHeader_Default_AgeHeaderOnly_NoMatch(t *testing.T) {
	headers := map[string]string{"Age": "120"}

	assert.False(t, hasCacheHitHeader(headers, nil))
}

func TestHasCacheHitHeader_Default_UnrelatedHeaderOnly_NoMatch(t *testing.T) {
	headers := map[string]string{"X-Iinfo": "some-value"}

	assert.False(t, hasCacheHitHeader(headers, nil))
}

func TestHasCacheHitHeader_Default_NoCacheHeader_NoMatch(t *testing.T) {
	headers := map[string]string{"Content-Type": "application/json"}

	assert.False(t, hasCacheHitHeader(headers, nil))
}

func TestHasCacheHitHeader_CustomValidRegex_Matches(t *testing.T) {
	cfg := &templates.CacheDeception{
		CacheHitHeaders: []string{`(?i)^x-served-by:\s*varnish-hit`},
	}
	headers := map[string]string{"X-Served-By": "varnish-hit"}

	assert.True(t, hasCacheHitHeader(headers, cfg))
}

func TestHasCacheHitHeader_CustomValidRegex_DefaultHeaderNoLongerMatches(t *testing.T) {
	// A configured cache_hit_headers list REPLACES the built-in defaults, so a
	// default-style header (Cf-Cache-Status) that would match without cfg must
	// NOT match once custom patterns are configured and don't include it.
	cfg := &templates.CacheDeception{
		CacheHitHeaders: []string{`(?i)^x-served-by:\s*varnish-hit`},
	}
	headers := map[string]string{"Cf-Cache-Status": "HIT"}

	assert.False(t, hasCacheHitHeader(headers, cfg))
}

func TestHasCacheHitHeader_OneInvalidOneValidRegex_ValidStillMatches(t *testing.T) {
	cfg := &templates.CacheDeception{
		CacheHitHeaders: []string{
			`(unclosed`, // invalid, must be skipped
			`(?i)^x-served-by:\s*varnish-hit`,
		},
	}
	headers := map[string]string{"X-Served-By": "varnish-hit"}

	assert.True(t, hasCacheHitHeader(headers, cfg))
}

func TestHasCacheHitHeader_AllInvalidRegexes_DetectionDisabled(t *testing.T) {
	cfg := &templates.CacheDeception{
		CacheHitHeaders: []string{`(unclosed`, `[invalid`},
	}
	// Even a header that would satisfy the built-in defaults must NOT match,
	// because all-invalid custom patterns disables detection rather than
	// falling back to defaults.
	headers := map[string]string{"Cf-Cache-Status": "HIT"}

	assert.False(t, hasCacheHitHeader(headers, cfg))
}
