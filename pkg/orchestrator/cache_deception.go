package orchestrator

import (
	"context"
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
// equality). victimUser must be a key in authInfos; the replay deliberately uses
// the key "anonymous", which is absent from authInfos, so applyHeaders sends no
// Authorization/Cookie/api-key on the replay.
//
// Operator custom headers (from --header, applied to every request by
// applyHeaders) are intentionally NOT applied to the anonymous replay: an
// auth-bearing custom header would otherwise authenticate the "anonymous" replay
// and fake a leak. They ARE kept on the prime phases. Cache-key-parity caveat:
// suppressing a required non-auth custom header on the replay could change the
// CDN cache key and yield a false negative — that is the accepted trade-off to
// preserve the unauthenticated invariant.
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

	// REPLAY: one fully anonymous GET (authUser "anonymous" is absent from
	// authInfos, so no auth header is applied — see mutation.go applyHeaders).
	// Suppress operator custom headers (--header) for this request ONLY:
	// applyHeaders applies e.customHeaders to every request, so an auth-bearing
	// custom header would authenticate the "anonymous" replay and fake a leak.
	// Save and restore around this single call — execution is sequential, so this
	// is safe, and the prime phases above keep the custom headers.
	savedHeaders := e.customHeaders
	e.customHeaders = nil
	e.trackedHTTPClient.ClearRequestIDs()
	anonPhase := &templates.Phase{Path: concretePath, Operation: "read"}
	anonResp, err := e.executePhase(ctx, baseURL, anonPhase, "anonymous", authInfos)
	e.customHeaders = savedHeaders // restore immediately, before any early return
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
	leaked, canary := bodyLeaked(result.PrimeResponse.Body, anonResp.Body, cfg)
	result.CanaryValue = canary
	result.Matched = is2xx && cacheHit && leaked
	return result, nil
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
func bodyLeaked(primeBody, anonBody string, cfg *templates.CacheDeception) (bool, string) {
	if cfg != nil && cfg.CanaryField != "" {
		canary := extractField(primeBody, cfg.CanaryField)
		if canary == "" {
			return false, ""
		}
		// Fail safe on short/low-entropy canaries: strings.Contains would let a
		// value like "1" substring-match almost any body and fire a false
		// positive. Below minCanaryLen, report not-leaked and warn.
		if len(strings.TrimSpace(canary)) < minCanaryLen {
			log.Warn("cache-deception: canary_field %q value is too short/low-entropy (%d chars) to be a reliable leak signal; "+
				"treating as not-leaked — configure a longer, unique field (e.g. email or an account token)", cfg.CanaryField, len(strings.TrimSpace(canary)))
			return false, ""
		}
		return strings.Contains(anonBody, canary), canary
	}
	return anonBody != "" && anonBody == primeBody, ""
}
