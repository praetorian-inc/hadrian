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

	var findings []*model.Finding

	// For unauthenticated endpoints, run test only once without roles
	if !tmpl.EndpointSelector.RequiresAuth {
		variables := buildVariables(op, baseURL)

		result, err := executor.Execute(ctx, tmpl, op, nil, variables)
		if err != nil {
			return nil, err
		}

		if result.Matched {
			method, endpoint := observedEndpoint(op, result.Request)
			finding := &model.Finding{
				ID:              fmt.Sprintf("%s-%s-%s-%s-%s", tmpl.ID, method, strings.ReplaceAll(endpoint, "/", "-"), "anonymous", "no-victim"),
				Category:        tmpl.Info.Category,
				Name:            tmpl.Info.Name,
				Severity:        model.Severity(tmpl.Info.Severity),
				Endpoint:        endpoint,
				Method:          method,
				AttackerRole:    "anonymous",
				IsVulnerability: true,
				Evidence: model.Evidence{
					Request:  result.Request,
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
			method, endpoint := observedEndpoint(op, result.Request)
			// Warn if response body is empty — may indicate proxy interception or dropped request
			if result.Response.Body == "" {
				log.Warn("matched with empty response body for %s on %s %s — response may be from proxy, not target API",
					tmpl.ID, method, endpoint)
			}
			finding := &model.Finding{
				ID:              fmt.Sprintf("%s-%s-%s-%s-%s", tmpl.ID, method, strings.ReplaceAll(endpoint, "/", "-"), "anonymous", "no-victim"),
				Category:        tmpl.Info.Category,
				Name:            tmpl.Info.Name,
				Severity:        model.Severity(tmpl.Info.Severity),
				Endpoint:        endpoint,
				Method:          method,
				AttackerRole:    "anonymous",
				IsVulnerability: true,
				Evidence: model.Evidence{
					Request:  result.Request,
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
				method, endpoint := observedEndpoint(op, result.Request)
				victimName := "no-victim"
				if victimRole != nil {
					victimName = victimRole.Name
				}
				finding := &model.Finding{
					ID:              fmt.Sprintf("%s-%s-%s-%s-%s", tmpl.ID, method, strings.ReplaceAll(endpoint, "/", "-"), attackerRole.Name, victimName),
					Category:        tmpl.Info.Category,
					Name:            tmpl.Info.Name,
					Severity:        model.Severity(tmpl.Info.Severity),
					Endpoint:        endpoint,
					Method:          method,
					AttackerRole:    attackerRole.Name,
					IsVulnerability: true,
					Evidence: model.Evidence{
						Request:  result.Request,
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

func observedEndpoint(op *model.Operation, req model.HTTPRequest) (method, endpoint string) {
	method = op.Method
	endpoint = op.Path

	if req.Method != "" {
		method = req.Method
	}

	if req.URL != "" {
		if parsed, err := url.Parse(req.URL); err == nil && parsed.Path != "" {
			endpoint = parsed.Path
		}
	}

	return method, endpoint
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
