package runner

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/auth"
	"github.com/praetorian-inc/hadrian/pkg/log"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/orchestrator"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/praetorian-inc/hadrian/pkg/templates"
)

// executeTemplate runs template against operation with role combinations
func executeTemplate(
	ctx context.Context,
	executor *templates.Executor,
	mutationExecutor *orchestrator.MutationExecutor,
	tmpl *templates.CompiledTemplate,
	op *model.Operation,
	rolesCfg *roles.RoleConfig,
	authCfg *auth.AuthConfig,
	baseURL string,
) ([]*model.Finding, error) {
	// Check if this is a mutation template - route to MutationExecutor
	if tmpl.Template != nil && tmpl.Template.Info.TestPattern == "mutation" {
		return executeMutationTemplate(ctx, mutationExecutor, tmpl, op, rolesCfg, authCfg, baseURL)
	}

	// Check if this is a cache-deception template - route to CacheDeceptionExecutor.
	// The executor is constructed inline by embedding the already-wired
	// mutationExecutor (its MutationExecutor field is exported), so no new
	// parameter is threaded through the call chain and no test call site changes.
	if tmpl.Template != nil && tmpl.Template.Info.TestPattern == "cache-deception" {
		cacheExecutor := &orchestrator.CacheDeceptionExecutor{MutationExecutor: mutationExecutor}
		return executeCacheDeceptionTemplate(ctx, cacheExecutor, tmpl, op, rolesCfg, authCfg, baseURL)
	}

	var findings []*model.Finding

	// For unauthenticated endpoints, run test only once without roles
	if !tmpl.EndpointSelector.RequiresAuth {
		variables := buildVariables(op, baseURL)

		result, err := executor.Execute(ctx, tmpl, op, nil, variables)
		if err != nil {
			return nil, err
		}

		if result.Matched {
			finding := &model.Finding{
				ID:              fmt.Sprintf("%s-%s-%s-%s-%s", tmpl.ID, op.Method, strings.ReplaceAll(op.Path, "/", "-"), "anonymous", "no-victim"),
				TemplateID:      tmpl.ID,
				Category:        tmpl.Info.Category,
				Name:            tmpl.Info.Name,
				Severity:        model.Severity(tmpl.Info.Severity),
				Endpoint:        op.Path,
				Method:          op.Method,
				AttackerRole:    "anonymous",
				IsVulnerability: true,
				Evidence: model.Evidence{
					Response: result.Response,
				},
				RequestIDs: result.RequestIDs,
				Timestamp:  time.Now(),
			}
			findings = append(findings, finding)
		}
		return findings, nil
	}

	// For "none" attacker permission level: test authenticated endpoints without any auth
	// This tests that endpoints properly reject unauthenticated access
	// Send a single unauthenticated request per endpoint (no per-victim duplication)
	if tmpl.RoleSelector.AttackerPermissionLevel == "none" {
		variables := buildVariables(op, baseURL)

		// Execute with nil auth (no authentication header)
		result, err := executor.Execute(ctx, tmpl, op, nil, variables)
		if err != nil {
			if ctx.Err() != nil {
				return findings, ctx.Err()
			}
			log.Warn("request failed for %s on %s %s (anonymous): %v", tmpl.ID, op.Method, op.Path, err)
			return findings, nil
		}

		if result.Matched {
			// Warn if response body is empty — may indicate proxy interception or dropped request
			if result.Response.Body == "" {
				log.Warn("matched with empty response body for %s on %s %s — response may be from proxy, not target API",
					tmpl.ID, op.Method, op.Path)
			}
			finding := &model.Finding{
				ID:              fmt.Sprintf("%s-%s-%s-%s-%s", tmpl.ID, op.Method, strings.ReplaceAll(op.Path, "/", "-"), "anonymous", "no-victim"),
				TemplateID:      tmpl.ID,
				Category:        tmpl.Info.Category,
				Name:            tmpl.Info.Name,
				Severity:        model.Severity(tmpl.Info.Severity),
				Endpoint:        op.Path,
				Method:          op.Method,
				AttackerRole:    "anonymous",
				IsVulnerability: true,
				Evidence: model.Evidence{
					Response: result.Response,
				},
				RequestIDs: result.RequestIDs,
				Timestamp:  time.Now(),
			}
			findings = append(findings, finding)
		}
		return findings, nil
	}

	// Get roles based on selector
	attackerRoles := rolesCfg.GetRolesByPermissionLevel(tmpl.RoleSelector.AttackerPermissionLevel)
	var victimRoles []*roles.Role
	if tmpl.RoleSelector.VictimPermissionLevel == "" {
		victimRoles = []*roles.Role{nil}
	} else {
		victimRoles = rolesCfg.GetRolesByPermissionLevel(tmpl.RoleSelector.VictimPermissionLevel)
	}

	for _, attackerRole := range attackerRoles {
		// Skip unauthenticated (level 0) attacker roles — these are tested
		// separately via attacker_permission_level: "none" templates (API2).
		// BOLA (API1) requires authenticated attackers accessing other users' objects.
		if attackerRole.Level == 0 {
			continue
		}

		for _, victimRole := range victimRoles {
			// Skip same-role if testing cross-role
			if victimRole != nil && attackerRole.Name == victimRole.Name {
				continue
			}

			// Skip if attacker has equal or higher privilege than victim
			if victimRole != nil && attackerRole.Level >= victimRole.Level {
				continue
			}

			// Build auth info for attacker
			var authInfo *templates.AuthInfo
			if authCfg != nil {
				info, err := authCfg.GetAuthInfo(attackerRole.Name)
				if err != nil {
					log.Warn("skipping attacker role '%s': %v", attackerRole.Name, err)
					continue
				}
				// info is nil when the role has no_auth: true — send request without auth header
				if info != nil {
					authInfo = &templates.AuthInfo{
						Method:   info.Method,
						Location: info.Location,
						KeyName:  info.KeyName,
						Value:    info.Value,
					}
				}
			}

			// Build variables for template substitution
			variables := buildVariables(op, baseURL)

			// Execute template
			result, err := executor.Execute(ctx, tmpl, op, authInfo, variables)
			if err != nil {
				if ctx.Err() != nil {
					return findings, ctx.Err()
				}
				log.Warn("request failed for %s on %s %s (attacker=%s): %v", tmpl.ID, op.Method, op.Path, attackerRole.Name, err)
				continue
			}

			// Check if vulnerability detected
			if result.Matched {
				victimName := "no-victim"
				if victimRole != nil {
					victimName = victimRole.Name
				}
				finding := &model.Finding{
					ID:              fmt.Sprintf("%s-%s-%s-%s-%s", tmpl.ID, op.Method, strings.ReplaceAll(op.Path, "/", "-"), attackerRole.Name, victimName),
					TemplateID:      tmpl.ID,
					Category:        tmpl.Info.Category,
					Name:            tmpl.Info.Name,
					Severity:        model.Severity(tmpl.Info.Severity),
					Endpoint:        op.Path,
					Method:          op.Method,
					AttackerRole:    attackerRole.Name,
					IsVulnerability: true,
					Evidence: model.Evidence{
						Response: result.Response,
					},
					RequestIDs: result.RequestIDs,
					Timestamp:  time.Now(),
				}

				if victimRole != nil {
					finding.VictimRole = victimRole.Name
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// executeMutationTemplate runs a three-phase mutation test
func executeMutationTemplate(
	ctx context.Context,
	executor *orchestrator.MutationExecutor,
	tmpl *templates.CompiledTemplate,
	op *model.Operation,
	rolesCfg *roles.RoleConfig,
	authCfg *auth.AuthConfig,
	baseURL string,
) ([]*model.Finding, error) {
	var findings []*model.Finding

	// Warn if "none" attacker is used with mutation tests — setup/verify phases need auth
	if tmpl.RoleSelector.AttackerPermissionLevel == "none" {
		log.Warn("template %s uses attacker_permission_level=\"none\" with mutation test pattern — "+
			"setup/verify phases require authentication; skipping (set attacker_permission_level to \"lower\" or \"all\" for mutation tests)", tmpl.ID)
		return findings, nil
	}

	attackerRoles := rolesCfg.GetRolesByPermissionLevel(tmpl.RoleSelector.AttackerPermissionLevel)
	victimRoles := rolesCfg.GetRolesByPermissionLevel(tmpl.RoleSelector.VictimPermissionLevel)

	for _, attackerRole := range attackerRoles {
		// Skip unauthenticated (level 0) attacker roles in mutation tests
		if attackerRole.Level == 0 {
			continue
		}

		for _, victimRole := range victimRoles {
			if victimRole == nil || attackerRole.Name == victimRole.Name {
				continue
			}

			// Skip if attacker has equal or higher privilege than victim
			if attackerRole.Level >= victimRole.Level {
				continue
			}

			// Build auth info map for both roles
			authInfos := make(map[string]*auth.AuthInfo)
			if authCfg != nil {
				attackerInfo, err := authCfg.GetAuthInfo(attackerRole.Name)
				if err != nil {
					log.Warn("skipping mutation attacker role '%s': %v", attackerRole.Name, err)
					continue
				}
				// Skip no_auth attacker roles in mutation tests — setup/verify phases require auth
				if attackerInfo == nil {
					log.Debug("skipping no_auth attacker role '%s' in mutation test %s — setup/verify phases require authentication", attackerRole.Name, tmpl.ID)
					continue
				}
				authInfos["attacker"] = attackerInfo

				victimInfo, err := authCfg.GetAuthInfo(victimRole.Name)
				if err != nil {
					log.Warn("skipping mutation victim role '%s': %v", victimRole.Name, err)
					continue
				}
				// Skip no_auth victim roles — verifying against unauthenticated victims is meaningless
				if victimInfo == nil {
					log.Debug("skipping no_auth victim role '%s' in mutation test %s", victimRole.Name, tmpl.ID)
					continue
				}
				authInfos["victim"] = victimInfo
			}

			// Clear tracker between tests
			executor.ClearTracker()

			// Execute three-phase mutation test
			result, err := executor.ExecuteMutation(
				ctx,
				tmpl.Template,
				op.Method,
				attackerRole.Name,
				victimRole.Name,
				authInfos,
				baseURL,
			)
			if err != nil {
				log.Warn("Mutation test failed [template=%s, attacker=%s, victim=%s, endpoint=%s %s]: %v",
					tmpl.ID, attackerRole.Name, victimRole.Name, op.Method, op.Path, err)
				continue
			}

			if result.Matched {
				finding := &model.Finding{
					ID:              fmt.Sprintf("%s-%s-%s-%s-%s", tmpl.ID, op.Method, strings.ReplaceAll(op.Path, "/", "-"), attackerRole.Name, victimRole.Name),
					TemplateID:      tmpl.ID,
					Category:        tmpl.Info.Category,
					Name:            tmpl.Info.Name,
					Severity:        model.Severity(tmpl.Info.Severity),
					Endpoint:        op.Path,
					Method:          op.Method,
					AttackerRole:    attackerRole.Name,
					VictimRole:      victimRole.Name,
					IsVulnerability: true,
					Timestamp:       time.Now(),
				}
				if result.AttackResponse != nil {
					finding.Evidence = model.Evidence{
						Response: *result.AttackResponse,
					}
				}

				// Collect all request IDs from all phases
				if result.RequestIDs != nil {
					var allRequestIDs []string
					allRequestIDs = append(allRequestIDs, result.RequestIDs.Setup...)
					allRequestIDs = append(allRequestIDs, result.RequestIDs.Attack...)
					allRequestIDs = append(allRequestIDs, result.RequestIDs.Verify...)
					finding.RequestIDs = allRequestIDs
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// executeCacheDeceptionTemplate runs the two-phase self-priming Web Cache
// Deception test for one operation. The replay attacker is always anonymous; the
// priming identity is the EXPLICIT cache_deception.prime_role — a self-scoped
// canary account named by the template. The role is never guessed: if prime_role
// is unset or not authenticatable the operation is skipped, so a privileged
// account is never used to write privileged data into a shared cache.
func executeCacheDeceptionTemplate(
	ctx context.Context,
	cacheExecutor *orchestrator.CacheDeceptionExecutor,
	tmpl *templates.CompiledTemplate,
	op *model.Operation,
	rolesCfg *roles.RoleConfig,
	authCfg *auth.AuthConfig,
	baseURL string,
) ([]*model.Finding, error) {
	var findings []*model.Finding

	if authCfg == nil {
		log.Warn("template %s (cache-deception) requires auth config for priming; skipping", tmpl.ID)
		return findings, nil
	}

	// Only GET responses are keyed and cached by CDNs. endpoint_selector should
	// already restrict to GET, but enforce it here so a non-GET is never primed or
	// recorded as a cache-deception finding.
	if !strings.EqualFold(op.Method, "GET") {
		log.Warn("template %s (cache-deception): operation %s %s is not a GET; skipping (only GET responses are CDN-cacheable)",
			tmpl.ID, op.Method, op.Path)
		return findings, nil
	}

	// Resolve the explicit prime_role. Never guess a role: without a named,
	// authenticatable self-scoped canary account there is nothing safe to prime
	// with, so skip.
	cfg := tmpl.Template.CacheDeception
	if cfg == nil || strings.TrimSpace(cfg.PrimeRole) == "" {
		log.Warn("template %s (cache-deception): cache_deception.prime_role is not set; skipping — "+
			"priming requires an explicitly named self-scoped canary role and is never guessed", tmpl.ID)
		return findings, nil
	}
	primeRoleName := cfg.PrimeRole
	victimInfo, err := authCfg.GetAuthInfo(primeRoleName)
	if err != nil || victimInfo == nil {
		log.Warn("template %s (cache-deception): prime_role %q is not authenticatable (absent from auth config or a no-auth role); skipping",
			tmpl.ID, primeRoleName)
		return findings, nil
	}

	// Resolve a concrete, brace-free path: URL-escape path params and append the
	// operation's required query params so both phases hit the same cache key.
	// victimInfo is passed so a QUERY-located auth api-key is NOT copied onto the
	// shared probe path — the anonymous replay must carry no auth key (see
	// buildCacheDeceptionPath).
	concretePath := buildCacheDeceptionPath(op, victimInfo)

	authInfos := map[string]*auth.AuthInfo{"victim": victimInfo}
	cacheExecutor.ClearTracker()

	result, err := cacheExecutor.ExecuteCacheDeception(ctx, tmpl.Template, concretePath, "victim", authInfos, baseURL)
	if err != nil {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}
		log.Warn("cache-deception test failed [template=%s, prime_role=%s, endpoint=%s %s]: %v",
			tmpl.ID, primeRoleName, op.Method, op.Path, err)
		return findings, nil
	}

	if result.Matched {
		// Distinguish the two proof modes the detector can match on. A
		// canary-confirmed match (non-empty CanaryValue) found the self-scoped
		// canary value in the anonymous body — identity-specific proof, so keep
		// the template's severity (HIGH). A body-equality-only match (empty
		// CanaryValue) proved only that the authenticated and anonymous bodies are
		// byte-for-byte equal; a long PUBLIC, role-independent response also
		// satisfies equality, so it does not by itself prove identity-specific
		// disclosure. Downgrade that to MEDIUM and describe it as a CANDIDATE to
		// confirm with canary_field. The detection gate (2xx + cache-HIT + leak
		// proof) is unchanged; only the emitted severity/description differ.
		severity := model.Severity(tmpl.Info.Severity)
		if tmpl.Info.Severity == "" {
			// Defensive fallback, mirroring buildGRPCFinding: our cache-deception
			// templates always set info.severity, so an empty value should never
			// reach here — default to MEDIUM rather than emitting an empty severity.
			severity = model.SeverityMedium
		}
		// A canary-confirmed match (non-empty CanaryValue) is identity-specific
		// proof — a confirmed vulnerability. A body-equality-only match (empty
		// CanaryValue) is an unconfirmed CANDIDATE (a long PUBLIC, role-independent
		// response satisfies byte-equality too), so it must NOT surface as a
		// confirmed finding in report counts / exit-code gating.
		isVulnerability := result.CanaryValue != ""
		description := tmpl.Info.Description
		if result.CanaryValue == "" {
			severity = model.SeverityMedium
			description = "CANDIDATE (unconfirmed) Web Cache Deception: the authenticated (prime) and " +
				"anonymous replay bodies are byte-for-byte equal and the anonymous response was a 2xx cache HIT. " +
				"Byte-equality alone does not prove the body is identity-specific — a long PUBLIC, role-independent " +
				"cached response would match too — so this is a candidate, not confirmed disclosure. Set " +
				"cache_deception.canary_field to a unique, self-scoped value (e.g. the canary account's email or an " +
				"account token) and re-run to confirm identity-specific disclosure."
		}
		finding := &model.Finding{
			ID:              fmt.Sprintf("%s-%s-%s-%s-%s", tmpl.ID, op.Method, strings.ReplaceAll(op.Path, "/", "-"), "anonymous", primeRoleName),
			TemplateID:      tmpl.ID,
			Category:        tmpl.Info.Category,
			Name:            tmpl.Info.Name,
			Description:     description,
			Severity:        severity,
			Endpoint:        op.Path,
			Method:          op.Method,
			AttackerRole:    "anonymous",
			VictimRole:      primeRoleName,
			IsVulnerability: isVulnerability,
			Timestamp:       time.Now(),
		}
		if result.AnonResponse != nil {
			finding.Evidence = model.Evidence{
				Response:       *result.AnonResponse,
				AttackResponse: result.AnonResponse,
			}
		}
		if result.PrimeResponse != nil {
			finding.Evidence.SetupResponse = result.PrimeResponse
		}
		// Represent the anonymous replay request: a GET to the same URL with no
		// auth and no operator custom headers (both suppressed on the replay).
		finding.Evidence.Request = model.HTTPRequest{
			Method:  op.Method,
			URL:     strings.TrimSuffix(baseURL, "/") + concretePath,
			Headers: map[string]string{},
		}
		if result.RequestIDs != nil {
			var ids []string
			ids = append(ids, result.RequestIDs.Setup...)
			ids = append(ids, result.RequestIDs.Attack...)
			finding.RequestIDs = ids
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// buildVariables creates the template substitution variables map from an operation and base URL.
func buildVariables(op *model.Operation, baseURL string) map[string]string {
	variables := map[string]string{
		"baseURL": baseURL,
	}
	for _, p := range op.PathParams {
		if p.Example != nil {
			variables[p.Name] = fmt.Sprintf("%v", p.Example)
		} else {
			variables[p.Name] = "1"
		}
	}
	return variables
}

// buildCacheDeceptionPath resolves op.Path into a concrete, brace-free URL path
// for the cache-deception probe (both phases use it, so both hit the same cache
// key). Path-parameter values are URL-path-escaped — a raw '/', '?', or space
// would otherwise split the path or start a query string — and every REQUIRED
// query parameter declared on the operation is appended (URL-query-escaped) so a
// query-driven endpoint is actually reached rather than 400ing or resolving a
// different resource. Values use the spec example when present, else "1".
//
// primeAuth is the prime role's resolved auth. When it authenticates via a
// QUERY-located api-key, that key's parameter is EXCLUDED from the probe path:
// copying it here would (a) pollute the anonymous replay URL — which must carry
// no auth key at all — with the auth parameter name and its placeholder value,
// and (b) collide on the prime with the real key that executePhase/applyHeaders
// injects. The prime still receives its real query key via applyHeaders, so the
// prime is authenticated and the replay stays anonymous. Consequence: for
// query-key auth the prime and replay cache keys differ (the key rides in the
// prime's URL, absent from the replay's), so query-key-authenticated endpoints
// are a documented false negative for the two-phase check.
func buildCacheDeceptionPath(op *model.Operation, primeAuth *auth.AuthInfo) string {
	path := op.Path
	for _, p := range op.PathParams {
		val := "1"
		if p.Example != nil {
			val = fmt.Sprintf("%v", p.Example)
		}
		path = strings.ReplaceAll(path, "{"+p.Name+"}", url.PathEscape(val))
	}

	// Auth key to exclude when the prime authenticates via a query api-key.
	var authQueryKey string
	if primeAuth != nil && primeAuth.Location == "query" {
		authQueryKey = primeAuth.KeyName
	}

	q := url.Values{}
	for _, p := range op.QueryParams {
		if !p.Required {
			continue
		}
		if authQueryKey != "" && p.Name == authQueryKey {
			continue // never leak the auth query key onto the anonymous replay
		}
		val := "1"
		if p.Example != nil {
			val = fmt.Sprintf("%v", p.Example)
		}
		q.Set(p.Name, val)
	}
	if enc := q.Encode(); enc != "" {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		path += sep + enc
	}
	return path
}
