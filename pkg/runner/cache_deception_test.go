//go:build integration

package runner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Two-phase (self-priming) Web Cache Deception executor — integration tests
// (LAB-3470, PR #156)
// =============================================================================
//
// These tests exercise the ACTIVE `test_pattern: "cache-deception"` executor
// (pkg/orchestrator/cache_deception.go, dispatched from pkg/runner/execution.go)
// end-to-end via RunTest against the production example template
// (examples/cache-deception/12-api8-web-cache-deception-active.yaml), plus a
// canary-mode test fixture template for the dynamic-body case.
//
// Unlike the single-request observational template's fixture
// (web_cache_deception_test.go), the executor under test here is STATEFUL: it
// authenticates and primes a URL-keyed cache with `prime_repeat` GETs, then
// replays the same URL anonymously. So the mock servers below model a shared,
// URL-keyed cache that remembers what was served across requests, rather than
// a single static per-path response.

// -----------------------------------------------------------------------------
// Fixture A/B/C: genuine leak, correct auth-varying, and hidden (headerless) leak
// -----------------------------------------------------------------------------

// cacheDeceptionActiveHandler models three independent endpoints in front of a
// shared, URL-keyed cache:
//
//	/api/account/statement    — CASE A (genuine leak, MUST flag): the cache
//	                            ignores auth entirely. The body never changes,
//	                            so it also satisfies exact body-equality. The
//	                            2nd+ request (authenticated or not) reports an
//	                            explicit Cloudflare cache-HIT header.
//	/api/account/safe-varies  — CASE B (correct, MUST NOT flag): auth is
//	                            enforced on every request regardless of prior
//	                            cache hits — an anonymous replay always 401s.
//	/api/account/hidden-cache — CASE C (leak, but MUST NOT flag): the cache
//	                            silently serves the same authenticated body to
//	                            anonymous callers (a real leak) but never
//	                            exposes a cache-status header, so the
//	                            executor's header gate correctly withholds the
//	                            finding.
func cacheDeceptionActiveHandler() http.Handler {
	mux := http.NewServeMux()

	var muStatement sync.Mutex
	hitsStatement := 0
	mux.HandleFunc("/api/account/statement", func(w http.ResponseWriter, _ *http.Request) {
		muStatement.Lock()
		hitsStatement++
		n := hitsStatement
		muStatement.Unlock()

		if n >= 2 {
			w.Header().Set("CF-Cache-Status", "HIT")
		}
		fixtureJSON(w, http.StatusOK, map[string]interface{}{
			"account_id": 1, "holder": "Victim User", "balance": 10425.50,
		})
	})

	mux.HandleFunc("/api/account/safe-varies", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		fixtureJSON(w, http.StatusOK, map[string]interface{}{
			"account_id": 1, "email": "victim@example.com",
		})
	})

	mux.HandleFunc("/api/account/hidden-cache", func(w http.ResponseWriter, _ *http.Request) {
		// No auth check (models the cache serving everyone the same cached
		// body) and no cache-status header of any kind (models a CDN that
		// doesn't expose one), regardless of request count.
		fixtureJSON(w, http.StatusOK, map[string]interface{}{
			"account_id": 1, "holder": "Victim User", "notes": "silently-cached-no-status-header",
		})
	})

	return mux
}

const cacheDeceptionActiveSpec = `openapi: "3.0.0"
info:
  title: Cache Deception Active Test API
  version: "1.0.0"
servers:
  - url: "%s"
paths:
  /api/account/statement:
    get:
      summary: Cacheable authenticated statement (genuine WCD leak)
      security: [{bearerAuth: []}]
      responses: {"200": {description: OK}}
  /api/account/safe-varies:
    get:
      summary: Correctly varies on auth (anonymous replay 401s)
      security: [{bearerAuth: []}]
      responses: {"200": {description: OK}}
  /api/account/hidden-cache:
    get:
      summary: Leaked to anonymous callers but no explicit cache-HIT header
      security: [{bearerAuth: []}]
      responses: {"200": {description: OK}}
components:
  securitySchemes:
    bearerAuth: {type: http, scheme: bearer}
`

// -----------------------------------------------------------------------------
// Fixture D: canary containment vs exact body-equality on a dynamic body
// -----------------------------------------------------------------------------

// cacheDeceptionCanaryHandler models a single endpoint whose AUTHENTICATED
// responses always carry fresh, per-request dynamic content (`served_at`
// increments every authenticated hit — e.g. a live counter/timestamp field),
// while the shared cache actually serves a snapshot frozen from the very
// first-ever hit to any UNAUTHENTICATED caller. This reproduces a leak whose
// authenticated ("prime") body never matches the anonymous ("replay") body
// byte-for-byte, even though a stable field (`email`) is identical in both —
// exactly the scenario exact body-equality misses and canary containment
// catches.
func cacheDeceptionCanaryHandler() http.Handler {
	mux := http.NewServeMux()
	var mu sync.Mutex
	hits := 0
	snapshot := ""

	mux.HandleFunc("/api/account/canary-dynamic", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		hits++

		if r.Header.Get("Authorization") == "" {
			// Anonymous replay: serve the frozen first-hit snapshot, however
			// many authenticated hits have happened since.
			w.Header().Set("CF-Cache-Status", "HIT")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(snapshot))
			return
		}

		body := fmt.Sprintf(`{"email":"canary@self.test","served_at":%d}`, hits)
		if snapshot == "" {
			snapshot = body // freeze the very first authenticated response
		} else {
			w.Header().Set("CF-Cache-Status", "HIT") // reports HIT though content is freshly generated
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})

	return mux
}

const cacheDeceptionCanarySpec = `openapi: "3.0.0"
info:
  title: Cache Deception Canary Test API
  version: "1.0.0"
servers:
  - url: "%s"
paths:
  /api/account/canary-dynamic:
    get:
      summary: Dynamic-body endpoint (per-hit served_at field)
      security: [{bearerAuth: []}]
      responses: {"200": {description: OK}}
components:
  securitySchemes:
    bearerAuth: {type: http, scheme: bearer}
`

// cacheDeceptionCanaryTemplate is a test-only variant of the production active
// template with cache_deception.canary_field set. It is written to its own
// temporary template directory (never to examples/cache-deception/) so this
// test file is fully self-contained and never mutates production template
// content.
const cacheDeceptionCanaryTemplate = `id: cache-deception-canary-test

info:
  name: "Web Cache Deception - Canary Field Mode (Test Fixture)"
  category: "API8:2023"
  severity: "HIGH"
  author: "hadrian-tests"
  description: |
    Test-only variant of the active two-phase Web Cache Deception template with
    cache_deception.canary_field set, proving canary containment catches a leak
    that exact body-equality misses when the authenticated body carries a
    per-request dynamic field.
  tags: ["web-cache-deception", "cache-deception", "cwe-525", "owasp-api-top10", "api8"]
  requires_llm_triage: false
  test_pattern: "cache-deception"

endpoint_selector:
  requires_auth: true
  methods: ["GET"]

role_selector:
  attacker_permission_level: "none"
  victim_permission_level: "all"

cache_deception:
  prime_repeat: 2
  canary_field: "email"
`

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// writeCacheDeceptionConfigs writes the api/roles/auth fixture files for a
// running server into a fresh temp dir and returns their paths.
func writeCacheDeceptionConfigs(t *testing.T, specTemplate, serverURL string) (apiPath, rolesPath, authPath string) {
	t.Helper()
	dir := t.TempDir()

	apiPath = filepath.Join(dir, "api.yaml")
	require.NoError(t, os.WriteFile(apiPath, []byte(strings.Replace(specTemplate, "%s", serverURL, 1)), 0o644))

	rolesPath = filepath.Join(dir, "roles.yaml")
	require.NoError(t, os.WriteFile(rolesPath, []byte(fixtureRolesConfig), 0o644))

	authPath = filepath.Join(dir, "auth.yaml")
	require.NoError(t, os.WriteFile(authPath, []byte(fixtureAuthConfig), 0o644))

	return apiPath, rolesPath, authPath
}

// runCacheDeception runs RunTest against the given fixture files, template
// directory, and template ID filter, and returns the findings.
func runCacheDeception(t *testing.T, apiPath, rolesPath, authPath, templateDir string, templateIDs []string) []*model.Finding {
	t.Helper()
	config := Config{
		API: apiPath, Roles: rolesPath, Auth: authPath,
		TemplateDir: templateDir, Categories: []string{"all"},
		Templates: templateIDs, RateLimit: 50.0, Timeout: 30, Output: "json",
	}
	findings, err := RunTest(context.Background(), config)
	require.NoError(t, err, "RunTest should not error against the cache-deception fixture")
	return findings
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

// TestIntegration_CacheDeceptionActive_TwoPhase runs the production ACTIVE
// two-phase template (examples/cache-deception/12-api8-web-cache-deception-active.yaml)
// against Cases A, B, and C. Only the genuine, cache-HIT-header-carrying leak
// (Case A) must be flagged.
func TestIntegration_CacheDeceptionActive_TwoPhase(t *testing.T) {
	server := httptest.NewServer(cacheDeceptionActiveHandler())
	t.Cleanup(server.Close)

	apiPath, rolesPath, authPath := writeCacheDeceptionConfigs(t, cacheDeceptionActiveSpec, server.URL)

	findings := runCacheDeception(t, apiPath, rolesPath, authPath,
		"../../examples/cache-deception", []string{"12-api8-web-cache-deception-active"})

	byEndpoint := make(map[string]*model.Finding, len(findings))
	var endpoints []string
	for _, f := range findings {
		byEndpoint[f.Endpoint] = f
		endpoints = append(endpoints, f.Endpoint)
	}

	require.Len(t, findings, 1, "exactly the genuine cache-served leak must be flagged; got %v", endpoints)

	leak, ok := byEndpoint["/api/account/statement"]
	require.True(t, ok, "Case A (genuine leak, cache-HIT header, matching body) must be flagged; got %v", endpoints)
	assert.Equal(t, "API8:2023", leak.Category)
	assert.Equal(t, model.Severity("HIGH"), leak.Severity)
	assert.True(t, leak.IsVulnerability)
	assert.Equal(t, "anonymous", leak.AttackerRole, "the finding must attribute the leak to the anonymous replay")
	assert.NotEmpty(t, leak.VictimRole, "the finding must record which role primed the cache")
	require.NotNil(t, leak.Evidence.AttackResponse, "finding must carry the anonymous replay as attack evidence")
	assert.Equal(t, http.StatusOK, leak.Evidence.AttackResponse.StatusCode)
	assert.Equal(t, "HIT", leak.Evidence.AttackResponse.Headers["Cf-Cache-Status"],
		"the anonymous replay evidence must carry the explicit cache-HIT header that justified the finding")
	require.NotNil(t, leak.Evidence.SetupResponse, "finding must carry the authenticated prime response as setup evidence")
	assert.Equal(t, http.StatusOK, leak.Evidence.SetupResponse.StatusCode)
	assert.NotEmpty(t, leak.RequestIDs, "finding must record request IDs from both prime and replay phases")

	_, flaggedSafe := byEndpoint["/api/account/safe-varies"]
	assert.False(t, flaggedSafe,
		"Case B (auth correctly enforced, anonymous replay 401s) must NOT be flagged")

	_, flaggedHidden := byEndpoint["/api/account/hidden-cache"]
	assert.False(t, flaggedHidden,
		"Case C (real leak, but no explicit cache-HIT header) must NOT be flagged — the header gate must withhold it")
}

// TestIntegration_CacheDeceptionActive_CanaryVsBodyEquality proves canary
// containment is robust where exact body-equality is not, against the SAME
// dynamic-body endpoint: the default (body-equality) template must MISS the
// leak, while a canary_field-configured variant of the same test pattern must
// FLAG it.
func TestIntegration_CacheDeceptionActive_CanaryVsBodyEquality(t *testing.T) {
	server := httptest.NewServer(cacheDeceptionCanaryHandler())
	t.Cleanup(server.Close)

	apiPath, rolesPath, authPath := writeCacheDeceptionConfigs(t, cacheDeceptionCanarySpec, server.URL)

	// (1) Default active template (canary_field: "" -> exact body-equality)
	// must MISS: the authenticated prime body's `served_at` field never
	// matches the frozen anonymous snapshot byte-for-byte.
	equalityFindings := runCacheDeception(t, apiPath, rolesPath, authPath,
		"../../examples/cache-deception", []string{"12-api8-web-cache-deception-active"})
	assert.Empty(t, equalityFindings,
		"exact body-equality mode must MISS a leak whose authenticated body has a dynamic field; got %d findings", len(equalityFindings))

	// (2) A canary_field-configured variant of the same test pattern, against
	// the SAME endpoint, must FLAG it: the canary value is stable even though
	// the rest of the body (served_at) is dynamic.
	canaryTemplateDir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(canaryTemplateDir, "cache-deception-canary-test.yaml"),
		[]byte(cacheDeceptionCanaryTemplate), 0o644,
	))

	canaryFindings := runCacheDeception(t, apiPath, rolesPath, authPath,
		canaryTemplateDir, []string{"cache-deception-canary-test"})
	require.Len(t, canaryFindings, 1,
		"canary_field mode must FLAG the same dynamic-body leak that body-equality missed")
	assert.Equal(t, "/api/account/canary-dynamic", canaryFindings[0].Endpoint)
	assert.Equal(t, "API8:2023", canaryFindings[0].Category)
	assert.True(t, canaryFindings[0].IsVulnerability)
}
