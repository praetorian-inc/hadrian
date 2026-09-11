package orchestrator

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

// F4 (round-3 review): trivial/structural bodies must never count as a leak in
// body-equality mode, even when the (trivial) prime and anon bodies match
// exactly.

func TestBodyLeaked_BodyEqualityMode_EmptyObject_NotLeaked(t *testing.T) {
	leaked, canary := bodyLeaked(`{}`, `{}`, nil)

	assert.False(t, leaked)
	assert.Empty(t, canary)
}

func TestBodyLeaked_BodyEqualityMode_EmptyArray_NotLeaked(t *testing.T) {
	leaked, canary := bodyLeaked(`[]`, `[]`, nil)

	assert.False(t, leaked)
	assert.Empty(t, canary)
}

func TestBodyLeaked_BodyEqualityMode_ShortIdenticalBody_NotLeaked(t *testing.T) {
	// 11 chars — below minBodyLen (16) — must not count as a leak even though
	// prime and anon bodies match exactly.
	body := `{"ok":true}`

	leaked, canary := bodyLeaked(body, body, nil)

	assert.False(t, leaked)
	assert.Empty(t, canary)
}

// --- canary placeholder blacklist (F5) ---

func TestBodyLeaked_CanaryPlaceholderBlacklist(t *testing.T) {
	blacklisted := []string{
		"", "undefined", "null", "none", "nil", "placeholder",
		"anonymous", "not_found", "n/a", "unknown",
	}
	for _, v := range blacklisted {
		t.Run(fmt.Sprintf("%q", v), func(t *testing.T) {
			cfg := &templates.CacheDeception{CanaryField: "name"}
			primeBody := fmt.Sprintf(`{"name":%q}`, v)
			anonBody := fmt.Sprintf(`{"name":%q,"other":"x"}`, v)

			leaked, canary := bodyLeaked(primeBody, anonBody, cfg)

			assert.False(t, leaked, "placeholder canary %q must not be trusted as a leak signal", v)
			assert.Empty(t, canary)
		})
	}
}

func TestBodyLeaked_CanaryPlaceholderBlacklist_CaseInsensitive(t *testing.T) {
	cfg := &templates.CacheDeception{CanaryField: "name"}
	primeBody := `{"name":"UNDEFINED"}`
	anonBody := `{"name":"UNDEFINED","other":"x"}`

	leaked, canary := bodyLeaked(primeBody, anonBody, cfg)

	assert.False(t, leaked, "blacklist match must be case-insensitive")
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

// --- ExecuteCacheDeception: truncation fail-closed guard (F2, round-3 review) ---
//
// bodyLeaked itself has no notion of truncation — the guard lives in
// ExecuteCacheDeception, which overrides bodyLeaked's result to not-leaked
// whenever either side's body was (or may have been) truncated at
// maxResponseBodySize. These tests exercise ExecuteCacheDeception end-to-end
// with a MockHTTPClient (reused from mutation_test.go, same package) so the
// real fail-closed code path — not a re-implementation of it — is what's
// under test.

func TestExecuteCacheDeception_PrimeBodyAtCap_FailsClosed(t *testing.T) {
	// A prime body read at exactly the maxResponseBodySize cap is
	// indistinguishable from one that was truncated, so ExecuteCacheDeception
	// must fail closed even though the (identical) bodies and the cache-HIT
	// header would otherwise indicate a leak.
	bigBody := strings.Repeat("a", maxResponseBodySize)

	primeResp1 := newMockResponse(200, bigBody)
	primeResp2 := newMockResponse(200, bigBody)
	anonResp := newMockResponse(200, bigBody)
	anonResp.Header.Set("Cf-Cache-Status", "HIT")

	client := &MockHTTPClient{responses: []*http.Response{primeResp1, primeResp2, anonResp}}
	executor := NewCacheDeceptionExecutor(client, nil)

	tmpl := &templates.Template{ID: "t-cap", CacheDeception: &templates.CacheDeception{PrimeRepeat: 2}}
	authInfos := makeAuthInfos("", "victim-token")

	result, err := executor.ExecuteCacheDeception(context.Background(), tmpl, "/api/account/statement", "victim", authInfos, "http://example.test")

	require.NoError(t, err)
	assert.False(t, result.Matched,
		"must fail closed when the prime body sits at the truncation cap, even though the (equal) bodies and cache-HIT header would otherwise indicate a leak")
}

func TestExecuteCacheDeception_AnonBodyTruncated_FailsClosed(t *testing.T) {
	// The anonymous reply is far larger than the truncation cap but carries
	// the canary substring at its very start, so bodyLeaked alone would
	// report a leak; ExecuteCacheDeception's truncation guard must override
	// that to not-leaked because the compared body is only a (possibly
	// misleading) prefix.
	canary := "canary-token-abcdef" // >= minCanaryLen, not blacklisted
	primeBody := fmt.Sprintf(`{"token":%q}`, canary)
	anonBody := canary + strings.Repeat("z", maxResponseBodySize+100)

	primeResp1 := newMockResponse(200, primeBody)
	primeResp2 := newMockResponse(200, primeBody)
	anonResp := newMockResponse(200, anonBody)
	anonResp.Header.Set("Cf-Cache-Status", "HIT")

	client := &MockHTTPClient{responses: []*http.Response{primeResp1, primeResp2, anonResp}}
	executor := NewCacheDeceptionExecutor(client, nil)

	tmpl := &templates.Template{
		ID:             "t-trunc",
		CacheDeception: &templates.CacheDeception{PrimeRepeat: 2, CanaryField: "token"},
	}
	authInfos := makeAuthInfos("", "victim-token")

	result, err := executor.ExecuteCacheDeception(context.Background(), tmpl, "/api/account/statement", "victim", authInfos, "http://example.test")

	require.NoError(t, err)
	require.NotNil(t, result.AnonResponse)
	assert.True(t, result.AnonResponse.Truncated, "sanity check: the anonymous reply must actually be flagged truncated")
	assert.False(t, result.Matched,
		"must fail closed when the anonymous body is truncated, even though the (untrimmed) canary substring would otherwise indicate a leak")
}

// --- Fix E: operator custom headers must never leak onto the anonymous replay ---
//
// executeAnonymousReplay deliberately bypasses executePhase/applyHeaders so the
// replay carries none of the operator's --header values (nor Authorization/
// Cookie). This test locks that structural invariant by inspecting every
// request MockHTTPClient actually captured, proving the prime phases DO carry
// the operator header (and auth) while the replay carries NEITHER.

func TestExecuteCacheDeception_OperatorHeadersStrippedFromAnonymousReplay(t *testing.T) {
	primeResp1 := newMockResponse(200, `{"email":"victim@example.com"}`)
	primeResp2 := newMockResponse(200, `{"email":"victim@example.com"}`)
	anonResp := newMockResponse(200, `{"email":"victim@example.com"}`)
	anonResp.Header.Set("Cf-Cache-Status", "HIT")

	client := &MockHTTPClient{responses: []*http.Response{primeResp1, primeResp2, anonResp}}
	customHeaders := map[string]string{"X-Operator": "secret"}
	executor := NewCacheDeceptionExecutor(client, customHeaders)

	tmpl := &templates.Template{ID: "t-headers", CacheDeception: &templates.CacheDeception{PrimeRepeat: 2}}
	authInfos := makeAuthInfos("", "victim-token")

	result, err := executor.ExecuteCacheDeception(context.Background(), tmpl, "/api/account/statement", "victim", authInfos, "http://example.test")
	require.NoError(t, err)
	assert.True(t, result.Matched, "sanity check: this fixture is a genuine cache-HIT body-equality leak")

	require.Len(t, client.requests, 3, "expected exactly 2 authenticated prime requests followed by 1 anonymous replay")
	primeReqs := client.requests[:2]
	replayReq := client.requests[2]

	for i, req := range primeReqs {
		assert.Equal(t, "secret", req.Header.Get("X-Operator"),
			"prime request %d must carry the operator's custom header (--header)", i)
		assert.Equal(t, "Bearer victim-token", req.Header.Get("Authorization"),
			"prime request %d must carry the victim's authentication", i)
	}

	assert.Empty(t, replayReq.Header.Get("X-Operator"),
		"the anonymous replay must NOT carry the operator's custom header — it must be structurally unauthenticated/unattributed")
	assert.Empty(t, replayReq.Header.Get("Authorization"),
		"the anonymous replay must NOT carry an Authorization header")
	assert.Empty(t, replayReq.Header.Get("Cookie"),
		"the anonymous replay must NOT carry a Cookie header")
}
