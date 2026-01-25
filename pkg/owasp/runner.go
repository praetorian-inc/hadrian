package owasp

import (
	"context"
	"fmt"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/praetorian-inc/hadrian/pkg/templates"
)

// =============================================================================
// PUBLIC API
// =============================================================================

// Runner orchestrates OWASP security tests using templates.
type Runner struct {
	executor    *templates.Executor
	templateDir string
}

// NewRunner creates a Runner with the given template executor and template directory.
func NewRunner(executor *templates.Executor, templateDir string) *Runner {
	return &Runner{
		executor:    executor,
		templateDir: templateDir,
	}
}

// RunCategory executes all templates for a given OWASP category against the API spec.
// It iterates through templates -> operations -> role combinations and returns findings.
func (r *Runner) RunCategory(
	ctx context.Context,
	spec *model.APISpec,
	rolesCfg *roles.RoleConfig,
	category string,
) ([]*model.Finding, error) {
	// Load templates for the category
	categoryTemplates, err := LoadTemplatesByCategory(r.templateDir, category)
	if err != nil {
		return nil, fmt.Errorf("failed to load templates for category %s: %w", category, err)
	}

	if len(categoryTemplates) == 0 {
		return []*model.Finding{}, nil
	}

	findings := make([]*model.Finding, 0)

	// Iterate through each operation in the spec
	for _, operation := range spec.Operations {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		// Match templates to this operation
		for _, tmpl := range categoryTemplates {
			if !MatchesEndpointSelector(operation, tmpl.EndpointSelector) {
				continue
			}

			// Get role combinations based on template's role selector
			attackerRoles := rolesCfg.GetRolesByPermissionLevel(tmpl.RoleSelector.AttackerPermissionLevel)
			victimRoles := rolesCfg.GetRolesByPermissionLevel(tmpl.RoleSelector.VictimPermissionLevel)

			// Execute for each role combination where attacker != victim
			for _, attacker := range attackerRoles {
				for _, victim := range victimRoles {
					// Skip if attacker and victim are the same role
					if attacker.Name == victim.Name {
						continue
					}

					// Check context cancellation
					select {
					case <-ctx.Done():
						return findings, nil
					default:
					}

					// Execute the template test
					finding, err := r.executeTest(ctx, tmpl, operation, attacker, victim)
					if err != nil {
						// Log error but continue with other tests
						continue
					}

					if finding != nil {
						findings = append(findings, finding)
					}
				}
			}
		}
	}

	return findings, nil
}

// =============================================================================
// MAIN LOGIC
// =============================================================================

// executeTest runs a single template test for a specific operation and role combination.
func (r *Runner) executeTest(
	ctx context.Context,
	tmpl *templates.CompiledTemplate,
	operation *model.Operation,
	attacker *roles.Role,
	victim *roles.Role,
) (*model.Finding, error) {
	// Build variables for template execution
	variables := map[string]string{
		"attacker_role": attacker.Name,
		"victim_role":   victim.Name,
	}

	// Generate auth header for attacker (placeholder - in real impl would get actual token)
	authHeader := fmt.Sprintf("Bearer token_%s", attacker.Name)

	// Execute the template
	result, err := r.executor.Execute(ctx, tmpl, operation, authHeader, variables)
	if err != nil {
		return nil, fmt.Errorf("template execution failed: %w", err)
	}

	// If template matched (potential vulnerability detected), create finding
	if result.Matched {
		finding := createFinding(tmpl, operation, attacker, victim, result)
		return finding, nil
	}

	return nil, nil
}

// =============================================================================
// HELPERS
// =============================================================================

// createFinding constructs a Finding from test execution results.
func createFinding(
	tmpl *templates.CompiledTemplate,
	operation *model.Operation,
	attacker *roles.Role,
	victim *roles.Role,
	result *templates.ExecutionResult,
) *model.Finding {
	return &model.Finding{
		ID:              generateFindingID(tmpl.ID, operation, attacker.Name),
		Category:        tmpl.Info.Category,
		Name:            tmpl.Info.Name,
		Description:     fmt.Sprintf("Potential %s vulnerability detected", tmpl.Info.Category),
		Severity:        parseSeverity(tmpl.Info.Severity),
		Confidence:      0.7, // Default confidence, can be adjusted by LLM triage
		IsVulnerability: true,
		Endpoint:        fmt.Sprintf("%s %s", operation.Method, operation.Path),
		Method:          operation.Method,
		AttackerRole:    attacker.Name,
		VictimRole:      victim.Name,
		Evidence: model.Evidence{
			Request: model.HTTPRequest{
				Method: operation.Method,
				URL:    operation.Path,
			},
			Response: result.Response,
		},
		Timestamp: time.Now(),
	}
}

// generateFindingID creates a unique ID for a finding.
func generateFindingID(templateID string, operation *model.Operation, attackerRole string) string {
	return fmt.Sprintf("%s-%s-%s-%s-%d",
		templateID,
		operation.Method,
		sanitizePath(operation.Path),
		attackerRole,
		time.Now().UnixNano(),
	)
}

// sanitizePath converts a path to a safe string for use in IDs.
func sanitizePath(path string) string {
	// Simple sanitization - replace / and { } with -
	result := path
	for _, char := range []string{"/", "{", "}", " "} {
		result = replaceAll(result, char, "-")
	}
	return result
}

// replaceAll is a simple string replacement helper.
func replaceAll(s, old, new string) string {
	result := ""
	for i := 0; i < len(s); i++ {
		if string(s[i]) == old {
			result += new
		} else {
			result += string(s[i])
		}
	}
	return result
}

// parseSeverity converts severity string to model.Severity.
func parseSeverity(severity string) model.Severity {
	switch severity {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH":
		return model.SeverityHigh
	case "MEDIUM":
		return model.SeverityMedium
	case "LOW":
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}
