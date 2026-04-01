package planner

import (
	"fmt"
	"strings"
)

// buildPrompt constructs a structured prompt for the LLM from the planner input.
func buildPrompt(input *PlannerInput) string {
	var b strings.Builder

	b.WriteString(`You are a security expert planning API authorization tests.
You will be given an API specification, available security test templates, and role definitions.
Your job is to produce a focused attack plan: an ordered list of tests most likely to find real vulnerabilities.

RULES:
- Only reference template IDs from the AVAILABLE TEMPLATES list below.
- Only reference role names from the ROLES list below.
- Prioritize high-risk endpoints: those with path parameters, auth requirements, and sensitive operations (DELETE, PUT, POST).
- Prefer tests that chain together (e.g., read a resource ID, then use it to test access control).
- Do NOT generate payloads. Use the template's built-in test logic.
- Return valid JSON only. No markdown, no commentary outside the JSON.
- If no templates match what the user asked for, return an empty steps array with reasoning explaining why.

`)

	// Endpoints
	b.WriteString("## API ENDPOINTS\n\n")
	if input.Spec != nil {
		for _, op := range input.Spec.Operations {
			params := ""
			if len(op.PathParams) > 0 {
				names := make([]string, len(op.PathParams))
				for i, p := range op.PathParams {
					names[i] = p.Name
				}
				params = fmt.Sprintf(" params=[%s]", strings.Join(names, ", "))
			}
			authStr := "no-auth"
			if op.RequiresAuth {
				authStr = "requires-auth"
			}
			b.WriteString(fmt.Sprintf("- %s %s [%s]%s\n", op.Method, op.Path, authStr, params))
		}
	}
	b.WriteString("\n")

	// Templates
	b.WriteString("## AVAILABLE TEMPLATES\n\n")
	for _, t := range input.Templates {
		selector := ""
		if t.EndpointSelector.HasPathParameter {
			selector += " needs-path-param"
		}
		if t.EndpointSelector.RequiresAuth {
			selector += " needs-auth"
		}
		if len(t.EndpointSelector.Methods) > 0 {
			selector += fmt.Sprintf(" methods=%v", t.EndpointSelector.Methods)
		}
		b.WriteString(fmt.Sprintf("- id=%q category=%q name=%q severity=%q%s\n",
			t.ID, t.Info.Category, t.Info.Name, t.Info.Severity, selector))
	}
	b.WriteString("\n")

	// Roles
	b.WriteString("## ROLES\n\n")
	if input.Roles != nil {
		for _, r := range input.Roles.Roles {
			perms := make([]string, len(r.Permissions))
			for i, p := range r.Permissions {
				perms[i] = p.Raw
			}
			b.WriteString(fmt.Sprintf("- name=%q level=%d permissions=[%s]\n",
				r.Name, r.Level, strings.Join(perms, ", ")))
		}
	}
	b.WriteString("\n")

	// Prior results
	if len(input.PriorResults) > 0 {
		b.WriteString("## PRIOR FINDINGS (from previous run)\n\n")
		for _, f := range input.PriorResults {
			b.WriteString(fmt.Sprintf("- %s %s category=%s attacker=%s victim=%s vuln=%v\n",
				f.Method, f.Endpoint, f.Category, f.AttackerRole, f.VictimRole, f.IsVulnerability))
		}
		b.WriteString("\nAvoid re-testing endpoints that already have confirmed findings. Focus on untested areas.\n\n")
	}

	// Options
	if input.Options.MaxSteps > 0 {
		b.WriteString(fmt.Sprintf("Return at most %d steps.\n\n", input.Options.MaxSteps))
	}
	if len(input.Options.FocusCategories) > 0 {
		b.WriteString(fmt.Sprintf("Focus on these OWASP categories: %s\n\n",
			strings.Join(input.Options.FocusCategories, ", ")))
	}
	if len(input.Options.FocusEndpoints) > 0 {
		b.WriteString(fmt.Sprintf("Focus on these endpoints: %s\n\n",
			strings.Join(input.Options.FocusEndpoints, ", ")))
	}

	// Custom context
	if input.Options.CustomContext != "" {
		b.WriteString("## ADDITIONAL CONTEXT\n\n")
		b.WriteString(input.Options.CustomContext)
		b.WriteString("\n\n")
	}

	// Output format
	b.WriteString(`## OUTPUT FORMAT

Return a JSON object with this exact structure:
{
  "reasoning": "Brief explanation of your attack strategy",
  "steps": [
    {
      "id": "step-1",
      "method": "GET",
      "path": "/api/users/{id}",
      "template_id": "api1-bola-read",
      "attacker_role": "user2",
      "victim_role": "user",
      "rationale": "Why this test matters"
    }
  ]
}

Optional step fields: "parameter", "oob", "depends_on", "extract", "detection_method".
`)

	return b.String()
}
