package runner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/auth"
	"github.com/praetorian-inc/hadrian/pkg/log"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/owasp"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/praetorian-inc/hadrian/pkg/templates"
)

// executeTemplate runs template against operation with role combinations
func executeTemplate(
	ctx context.Context,
	executor *templates.Executor,
	mutationExecutor *owasp.MutationExecutor,
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

		result, err := executor.Execute(ctx, tmpl, op, nil, variables)
		if err != nil {
			return nil, err
		}

		if result.Matched {
			finding := &model.Finding{
				ID:              fmt.Sprintf("%s-%s-%s", tmpl.ID, op.Method, strings.ReplaceAll(op.Path, "/", "-")),
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
	victimRoles := rolesCfg.GetRolesByPermissionLevel(tmpl.RoleSelector.VictimPermissionLevel)

	// If no victim roles needed, use single-role tests
	if tmpl.RoleSelector.VictimPermissionLevel == "" {
		victimRoles = []*roles.Role{nil}
	}

	for _, attackerRole := range attackerRoles {
		for _, victimRole := range victimRoles {
			// Skip same-role if testing cross-role
			if victimRole != nil && attackerRole.Name == victimRole.Name {
				continue
			}

			// Build auth info for attacker
			var authInfo *templates.AuthInfo
			if authCfg != nil {
				authValue, err := authCfg.GetAuth(attackerRole.Name)
				if err != nil {
					// Role may not have auth configured
					continue
				}

				// Create AuthInfo from auth config
				authInfo = &templates.AuthInfo{
					Method:   authCfg.Method,
					Location: authCfg.Location,
					KeyName:  authCfg.KeyName,
					Value:    authValue,
				}
			}

			// Build variables for template substitution
			variables := map[string]string{
				"baseURL": baseURL,
			}

			// Add path parameter values
			for _, p := range op.PathParams {
				if p.Example != nil {
					variables[p.Name] = fmt.Sprintf("%v", p.Example)
				} else {
					variables[p.Name] = "1" // Default value
				}
			}

			// Execute template
			result, err := executor.Execute(ctx, tmpl, op, authInfo, variables)
			if err != nil {
				return nil, err
			}

			// Check if vulnerability detected
			if result.Matched {
				finding := &model.Finding{
					ID:              fmt.Sprintf("%s-%s-%s", tmpl.ID, op.Method, strings.ReplaceAll(op.Path, "/", "-")),
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
	executor *owasp.MutationExecutor,
	tmpl *templates.CompiledTemplate,
	op *model.Operation,
	rolesCfg *roles.RoleConfig,
	authCfg *auth.AuthConfig,
	baseURL string,
) ([]*model.Finding, error) {
	var findings []*model.Finding

	attackerRoles := rolesCfg.GetRolesByPermissionLevel(tmpl.RoleSelector.AttackerPermissionLevel)
	victimRoles := rolesCfg.GetRolesByPermissionLevel(tmpl.RoleSelector.VictimPermissionLevel)

	for _, attackerRole := range attackerRoles {
		for _, victimRole := range victimRoles {
			if victimRole == nil || attackerRole.Name == victimRole.Name {
				continue
			}

			// Build auth info map for both roles
			authInfos := make(map[string]*auth.AuthInfo)
			if authCfg != nil {
				if info, err := authCfg.GetAuthInfo(attackerRole.Name); err == nil {
					authInfos["attacker"] = info
				}
				if info, err := authCfg.GetAuthInfo(victimRole.Name); err == nil {
					authInfos["victim"] = info
				}
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
				log.Warn("Mutation test failed: %v", err)
				continue
			}

			if result.Matched {
				finding := &model.Finding{
					ID:              fmt.Sprintf("%s-%s-%s", tmpl.ID, op.Method, strings.ReplaceAll(op.Path, "/", "-")),
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
