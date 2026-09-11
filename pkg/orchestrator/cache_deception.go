package orchestrator

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/auth"
	"github.com/praetorian-inc/hadrian/pkg/log"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/templates"
)

// defaultPrimeRepeat is the number of authenticated GETs sent to warm the cache
// when the template does not override it. Two hits warm cache-on-second-hit CDNs
// (the first request is a MISS that populates the cache, the second a HIT).
const defaultPrimeRepeat = 2

// maxPrimeRepeat caps prime_repeat so a template (or a typo) cannot turn one
// operation into an unbounded burst of authenticated GETs against the target —
// a self-inflicted DoS / rate-limit exhaustion. A configured value above this is
// clamped down to it; a value < 1 falls back to defaultPrimeRepeat.
const maxPrimeRepeat = 20

// minBodyLen is the shortest anonymous body that body-equality mode (empty
// canary_field) will treat as a leak. Body-equality is a weak heuristic: a
// public, role-independent cached body (an empty object, a short status blob)
// matches between the authenticated prime and the anonymous replay without any
// authenticated content leaking. Requiring a non-trivial body of at least this
// length avoids that false positive; prefer canary_field for a real signal.
const minBodyLen = 16

// minCanaryLen is the shortest canary value bodyLeaked will trust as a leak
// signal. The canary is matched with strings.Contains (a substring test), so a
// short or low-entropy value — e.g. "1" extracted from an id field — substring-
// matches almost any response body and produces false positives. A canary whose
// trimmed length is below this threshold makes the detector fail safe (report
// not-leaked) and warn, rather than assert on it.
const minCanaryLen = 8

// defaultCacheHitPatterns are the two tightened cache-HIT arms carried by the
// observational template (templates/rest/12-api8-web-cache-deception.yaml),
// reused verbatim so both templates agree on what "explicit cache HIT" means.
var defaultCacheHitPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?im)^cf-cache-status:\s*hit`), // Cloudflare
	regexp.MustCompile(`(?im)^x-cache:.*hit\b`),        // CloudFront / Varnish / Fastly / Akamai
}

// canaryPlaceholderBlacklist are canary values that are structurally low-entropy
// or serialization artifacts rather than real, self-scoped identifiers. An
// extractField result equal to one of these (case-insensitive, trimmed) is not a
// trustworthy leak signal — e.g. a serialized `null`/`undefined`, an "anonymous"
// display name, or a "not_found" sentinel would substring-match unrelated bodies
// — so the detector treats it exactly like the short-canary guard: not-leaked,
// with a warning.
var canaryPlaceholderBlacklist = map[string]bool{
	"":            true,
	"undefined":   true,
	"null":        true,
	"none":        true,
	"nil":         true,
	"placeholder": true,
	"anonymous":   true,
	"not_found":   true,
	"n/a":         true,
	"unknown":     true,
}

// CacheDeceptionExecutor runs the two-phase self-priming Web Cache Deception
// test. It embeds *MutationExecutor to reuse executePhase/applyHeaders/tracker/
// trackedHTTPClient and the package-level helpers with ZERO changes to the
// mutation framework (mutation.go is untouched).
type CacheDeceptionExecutor struct {
	*MutationExecutor
}

// NewCacheDeceptionExecutor builds an executor that owns its own TrackedHTTPClient
// via the embedded MutationExecutor. In the runner the executor is instead
// constructed inline from the already-wired mutationExecutor (see
// pkg/runner/execution.go); this constructor exists for standalone use and tests.
func NewCacheDeceptionExecutor(client HTTPClient, customHeaders map[string]string) *CacheDeceptionExecutor {
	return &CacheDeceptionExecutor{MutationExecutor: NewMutationExecutor(client, customHeaders)}
}

// CacheDeceptionResult holds the outcome of one prime+replay run.
type CacheDeceptionResult struct {
	TemplateID    string
	Matched       bool
	PrimeResponse *model.HTTPResponse // last authenticated (victim) prime response
	AnonResponse  *model.HTTPResponse // anonymous replay response
	CanaryValue   string              // canary value asserted on (empty in body-equality mode)
	RequestIDs    *PhaseRequestIDs    // Setup = prime request IDs, Attack = replay request IDs
}

// ExecuteCacheDeception primes the cache as victimUser (default 2 authenticated
// GETs against concretePath), then replays the SAME URL anonymously and detects a
// leak. concretePath MUST be brace-free (OpenAPI path params already resolved) —
// executePhase errors on any remaining {placeholder}, so the dispatch layer
// resolves them before calling.
//
// Detection requires ALL of: the anonymous response is 2xx, it carries an
// explicit cache-HIT header, and its body proves it is the victim's cached
// content (canary containment when canary_field is set, else exact body
// equality). victimUser must be a key in authInfos and identifies the prime
// (canary) identity.
//
// The anonymous replay does NOT go through executePhase/applyHeaders. It is a
// dedicated request path (executeAnonymousReplay) that sends a bare GET with no
// Authorization, no Cookie, no api-key, and none of the operator custom headers
// (--header): the unauthenticated invariant is enforced structurally rather than
// by mutating and restoring the shared executor's customHeaders (concurrency-
// safe — no shared mutable state is touched). The prime phases keep using
// executePhase, so they legitimately carry auth and operator headers.
// Cache-key-parity caveat: suppressing a required non-auth custom header on the
// replay could change the CDN cache key and yield a false negative — that is the
// accepted trade-off to preserve the unauthenticated invariant.
func (e *CacheDeceptionExecutor) ExecuteCacheDeception(
	ctx context.Context,
	tmpl *templates.Template,
	concretePath string,
	victimUser string,
	authInfos map[string]*auth.AuthInfo,
	baseURL string,
) (*CacheDeceptionResult, error) {
	result := &CacheDeceptionResult{TemplateID: tmpl.ID, RequestIDs: &PhaseRequestIDs{}}

	cfg := tmpl.CacheDeception
	primeRepeat := defaultPrimeRepeat
	if cfg != nil && cfg.PrimeRepeat > 0 {
		primeRepeat = cfg.PrimeRepeat
	}
	if primeRepeat > maxPrimeRepeat {
		log.Warn("cache-deception: prime_repeat %d exceeds the cap of %d; clamping to %d to avoid a self-inflicted request burst",
			primeRepeat, maxPrimeRepeat, maxPrimeRepeat)
		primeRepeat = maxPrimeRepeat
	}

	// PRIME: authenticated GETs to warm the cache. Keep the last response as the
	// victim body to compare the anonymous replay against.
	for i := 0; i < primeRepeat; i++ {
		e.trackedHTTPClient.ClearRequestIDs()
		primePhase := &templates.Phase{Path: concretePath, Operation: "read"} // GET
		resp, err := e.executePhase(ctx, baseURL, primePhase, victimUser, authInfos)
		if err != nil {
			return result, err
		}
		result.PrimeResponse = resp
		result.RequestIDs.Setup = append(result.RequestIDs.Setup, e.trackedHTTPClient.GetRequestIDs()...)
	}

	// REPLAY: one fully anonymous GET to the SAME URL via a dedicated request
	// path — no Authorization, no Cookie, no api-key, no operator custom headers.
	// See executeAnonymousReplay for why this does not route through
	// executePhase/applyHeaders (no shared-state mutation).
	e.trackedHTTPClient.ClearRequestIDs()
	targetURL := strings.TrimSuffix(baseURL, "/") + concretePath
	anonResp, err := e.executeAnonymousReplay(ctx, targetURL)
	if err != nil {
		return result, err
	}
	result.AnonResponse = anonResp
	result.RequestIDs.Attack = e.trackedHTTPClient.GetRequestIDs()

	// DETECT: 2xx AND explicit cache-HIT header AND proof the anon body is the
	// victim's cached content.
	if result.PrimeResponse == nil || anonResp == nil {
		return result, nil
	}
	is2xx := anonResp.StatusCode >= 200 && anonResp.StatusCode < 300
	cacheHit := hasCacheHitHeader(anonResp.Headers, cfg)
	// Fail closed on truncation: executePhase caps prime bodies at
	// maxResponseBodySize with no truncation signal, so a prime body at the cap is
	// treated as possibly truncated. The anonymous replay reports truncation
	// precisely. A truncated body on either side means we would be comparing
	// prefixes, which can spuriously match — never assert a leak on it.
	truncated := anonResp.Truncated || len(result.PrimeResponse.Body) >= maxResponseBodySize
	leaked, canary := bodyLeaked(result.PrimeResponse.Body, anonResp.Body, cfg)
	if truncated {
		log.Warn("cache-deception: prime or anonymous body was truncated at the %d-byte cap; "+
			"treating as not-leaked to avoid asserting on a truncated prefix", maxResponseBodySize)
		leaked = false
	}
	result.CanaryValue = canary
	result.Matched = is2xx && cacheHit && leaked
	return result, nil
}

// executeAnonymousReplay performs the second-phase anonymous GET replay. It
// deliberately bypasses executePhase/applyHeaders: it builds a bare GET carrying
// only the tracked-client request-id header, so it sends NO Authorization, NO
// Cookie, NO api-key, and NONE of the operator custom headers (--header). The
// unauthenticated invariant is therefore a property of the request that is
// built, not of save/restoring the shared executor's customHeaders — which keeps
// it correct even if executions ever run concurrently.
//
// It reads one byte past maxResponseBodySize so it can DETECT truncation (rather
// than silently comparing a truncated prefix) and reports it via
// HTTPResponse.Truncated; the returned body is trimmed back to the cap.
func (e *CacheDeceptionExecutor) executeAnonymousReplay(ctx context.Context, targetURL string) (*model.HTTPResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.trackedHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize+1))
	if err != nil {
		return nil, err
	}
	truncated := len(body) > maxResponseBodySize
	if truncated {
		body = body[:maxResponseBodySize]
	}

	return &model.HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    headerMapFromResponse(resp),
		Body:       string(body),
		Size:       len(body),
		Truncated:  truncated,
	}, nil
}

// hasCacheHitHeader renders each response header as "Key: Value" and matches it
// against the template's cache_hit_headers (or the built-in defaults when none
// are configured). An invalid author-supplied regex is skipped rather than
// silently reinstating the defaults.
func hasCacheHitHeader(headers map[string]string, cfg *templates.CacheDeception) bool {
	patterns := defaultCacheHitPatterns
	if cfg != nil && len(cfg.CacheHitHeaders) > 0 {
		patterns = make([]*regexp.Regexp, 0, len(cfg.CacheHitHeaders))
		for _, p := range cfg.CacheHitHeaders {
			re, err := regexp.Compile(p)
			if err != nil {
				log.Warn("cache-deception: ignoring invalid cache_hit_headers regex %q: %v", p, err)
				continue // skip invalid author regex
			}
			patterns = append(patterns, re)
		}
		if len(patterns) == 0 {
			log.Warn("cache-deception: all %d cache_hit_headers pattern(s) failed to compile; "+
				"cache-HIT detection is effectively disabled and no replay can match — fix the patterns or omit cache_hit_headers to use the built-in defaults", len(cfg.CacheHitHeaders))
		}
	}
	for k, v := range headers {
		line := k + ": " + v
		for _, re := range patterns {
			if re.MatchString(line) {
				return true
			}
		}
	}
	return false
}

// bodyLeaked reports whether the anonymous body proves the victim's cached
// content leaked, and the canary value used. Primary mode (canary_field set):
// the stored authenticated field value must appear in the anonymous body — robust
// to per-request dynamic fields (timestamps, request IDs) that would break exact
// equality. Fallback mode (empty canary_field): exact body equality, which is the
// strongest proof when it holds but is subject to dynamic-body false negatives.
//
// Truncation is handled by the caller (ExecuteCacheDeception), which fails closed
// before trusting this result: a body capped at maxResponseBodySize on either
// side would make both modes compare prefixes and can spuriously match.
func bodyLeaked(primeBody, anonBody string, cfg *templates.CacheDeception) (bool, string) {
	if cfg != nil && cfg.CanaryField != "" {
		canary := extractField(primeBody, cfg.CanaryField)
		if canary == "" {
			return false, ""
		}
		trimmed := strings.TrimSpace(canary)
		// Fail safe on structural/low-entropy placeholder canaries (a serialized
		// null/undefined, an "anonymous" display name, a "not_found" sentinel):
		// these substring-match unrelated bodies and fire false positives.
		if canaryPlaceholderBlacklist[strings.ToLower(trimmed)] {
			log.Warn("cache-deception: canary_field %q value %q is a low-entropy placeholder/sentinel, not a reliable leak signal; "+
				"treating as not-leaked — configure a field carrying a unique, self-scoped value (e.g. email or an account token)", cfg.CanaryField, trimmed)
			return false, ""
		}
		// Fail safe on short/low-entropy canaries: strings.Contains would let a
		// value like "1" substring-match almost any body and fire a false
		// positive. Below minCanaryLen, report not-leaked and warn.
		if len(trimmed) < minCanaryLen {
			log.Warn("cache-deception: canary_field %q value is too short/low-entropy (%d chars) to be a reliable leak signal; "+
				"treating as not-leaked — configure a longer, unique field (e.g. email or an account token)", cfg.CanaryField, len(trimmed))
			return false, ""
		}
		return strings.Contains(anonBody, canary), canary
	}
	// Body-equality fallback. Reject trivial/structural bodies: an empty object,
	// an empty array, whitespace, or any very short body can match between the
	// authenticated prime and the anonymous replay without any authenticated
	// content leaking (a public, role-independent response). Require a
	// non-trivial body before declaring a leak.
	if isTrivialBody(anonBody) {
		return false, ""
	}
	return anonBody == primeBody, ""
}

// isTrivialBody reports whether body is too small or structurally empty to carry
// authenticated content — used to reject body-equality false positives.
func isTrivialBody(body string) bool {
	t := strings.TrimSpace(body)
	// Trivial structural bodies ("", "{}", "[]", "null") are all shorter than
	// minBodyLen, so the length check alone rejects them — no separate literal
	// switch is needed.
	return len(t) < minBodyLen
}
