package runner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/auth"
	"github.com/praetorian-inc/hadrian/pkg/log"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/orchestrator"
	"github.com/praetorian-inc/hadrian/pkg/planner"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/praetorian-inc/hadrian/pkg/templates"
)

// RunTest executes security tests against an API and returns findings directly.
// It is the library entry point for programmatic usage (e.g. from Chariot),
// performing the same core work as the CLI minus reporter output and LLM triage.
func RunTest(ctx context.Context, config Config) ([]*model.Finding, error) {
	log.SetVerbose(config.Verbose)

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration error: %w", err)
	}

	// Parse custom headers
	customHeaders, err := ParseCustomHeaders(config.Headers)
	if err != nil {
		return nil, fmt.Errorf("invalid custom header: %w", err)
	}

	spec, err := parseAPISpec(config.API)
	if err != nil {
		return nil, fmt.Errorf("failed to parse API spec: %w", err)
	}

	rolesCfg, err := roles.Load(config.Roles)
	if err != nil {
		return nil, fmt.Errorf("failed to load roles: %w", err)
	}

	var authCfg *auth.AuthConfig
	if config.Auth != "" {
		authCfg, err = auth.Load(config.Auth)
		if err != nil {
			return nil, fmt.Errorf("failed to load auth config: %w", err)
		}
	}

	httpClient, err := createHTTPClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	rateLimitConfig := &RateLimitConfig{
		Rate:           config.RateLimit,
		Enabled:        true,
		BackoffType:    config.RateLimitBackoff,
		BackoffInitial: 1 * time.Second,
		BackoffMax:     config.RateLimitMaxWait,
		MaxRetries:     config.RateLimitMaxRetries,
		StatusCodes:    config.RateLimitStatusCodes,
		BodyPatterns:   []string{},
	}
	rateLimiter := NewRateLimiter(config.RateLimit, config.RateLimit)
	rateLimitingClient := NewRateLimitingClient(httpClient, rateLimiter, rateLimitConfig)

	templateDir := config.TemplateDir
	if templateDir == "" {
		templateDir = getTemplateDir("./templates/rest")
	}

	tmplFiles, err := loadTemplateFiles(templateDir, config.Categories)
	if err != nil {
		return nil, fmt.Errorf("failed to load templates from %s: %w", templateDir, err)
	}

	if len(config.Templates) > 0 {
		tmplFiles = filterByTemplates(tmplFiles, config.Templates)
		if len(tmplFiles) == 0 {
			return nil, fmt.Errorf("no templates matched the specified filters: %v", config.Templates)
		}
	}

	executor := templates.NewExecutor(rateLimitingClient, customHeaders)
	mutationExecutor := orchestrator.NewMutationExecutor(rateLimitingClient, customHeaders)

	// LLM-assisted attack planning (experimental)
	var attackPlan *planner.AttackPlan
	if config.PlannerEnabled {
		var llmClient planner.LLMClient
		var planErr error
		if config.PlannerLLMClient != nil {
			llmClient = config.PlannerLLMClient
		} else {
			llmClient, planErr = newPlannerLLMClient(config.PlannerProvider, config.PlannerModel, time.Duration(config.PlannerTimeout)*time.Second)
		}
		if planErr != nil {
			if config.PlannerOnly {
				log.Warn("Planner: %v", planErr)
			} else {
				log.Warn("Planner: %v — falling back to brute-force execution", planErr)
			}
		} else {
			p := planner.NewPlanner(llmClient)
			planInput := &planner.PlannerInput{
				Spec:      spec,
				Roles:     rolesCfg,
				Templates: tmplFiles,
				Options: planner.PlannerOptions{
					CustomContext: config.PlannerContext,
				},
			}
			attackPlan, planErr = p.Plan(ctx, planInput)
			if planErr != nil {
				if config.PlannerOnly {
					log.Warn("Planner failed: %v", planErr)
				} else {
					log.Warn("Planner failed: %v — falling back to brute-force execution", planErr)
				}
				attackPlan = nil
			} else {
				if len(attackPlan.Steps) == 0 {
					log.Info("LLM Attack Plan: 0 steps")
					if attackPlan.Reasoning != "" {
						log.Info("Reason: %s", attackPlan.Reasoning)
					}
				} else {
					log.Info("LLM Attack Plan (%d steps)", len(attackPlan.Steps))
					if attackPlan.Reasoning != "" {
						log.Info("Strategy: %s", attackPlan.Reasoning)
					}
					for i, step := range attackPlan.Steps {
						log.Info("[%d] %s %s -> template=%s attacker=%s victim=%s",
							i+1, step.Method, step.Path, step.TemplateID, step.AttackerRole, step.VictimRole)
						if step.Rationale != "" {
							log.Debug("    %s", step.Rationale)
						}
					}
				}
			}
		}
	}

	var allFindings []*model.Finding

	// Execute planned steps first
	covered := make(map[string]bool) // tracks "templateID|method|path" combos already run
	if attackPlan != nil && len(attackPlan.Steps) > 0 {
		// Build lookup maps
		tmplMap := make(map[string]*templates.CompiledTemplate)
		for _, t := range tmplFiles {
			tmplMap[t.ID] = t
		}
		opMap := make(map[string]*model.Operation) // "METHOD /path" → operation
		for _, o := range spec.Operations {
			opMap[normalizeOpKey(o.Method, o.Path)] = o
		}

		log.Info("Executing %d planned steps...", len(attackPlan.Steps))
		for i, step := range attackPlan.Steps {
			tmpl, ok := tmplMap[step.TemplateID]
			if !ok {
				log.Warn("Plan step %d: template %q not found, skipping", i+1, step.TemplateID)
				continue
			}
			op, ok := opMap[normalizeOpKey(step.Method, step.Path)]
			if !ok {
				log.Warn("Plan step %d: operation %s %s not found, skipping", i+1, step.Method, step.Path)
				continue
			}

			findings, err := executeTemplate(ctx, executor, mutationExecutor, tmpl, op, rolesCfg, authCfg, spec.BaseURL)
			if err != nil {
				log.Warn("Plan step %d: %s failed on %s %s: %v", i+1, tmpl.ID, op.Method, op.Path, err)
				continue
			}
			allFindings = append(allFindings, findings...)
			covered[tmpl.ID+"|"+op.Method+"|"+op.Path] = true
		}
	}

	// If --planner-only, never run brute-force — even if the planner failed.
	// The user explicitly opted into planner-only execution.
	if config.PlannerOnly {
		if attackPlan == nil {
			return nil, fmt.Errorf("planner failed and --planner-only is set — cannot continue without a plan")
		}
		if len(allFindings) == 0 && len(attackPlan.Steps) > 0 {
			log.Warn("All %d planned steps were dropped or failed — 0 valid tests executed", len(attackPlan.Steps))
		}
		return allFindings, nil
	}

	// Brute-force remaining combos
	{
		for _, op := range spec.Operations {
			for _, tmpl := range tmplFiles {
				if !templateApplies(tmpl, op) {
					continue
				}
				// Skip combos already covered by the plan
				if covered[tmpl.ID+"|"+op.Method+"|"+op.Path] {
					continue
				}

				findings, err := executeTemplate(ctx, executor, mutationExecutor, tmpl, op, rolesCfg, authCfg, spec.BaseURL)
				if err != nil {
					log.Warn("Template %s failed on %s %s: %v", tmpl.ID, op.Method, op.Path, err)
					continue
				}
				allFindings = append(allFindings, findings...)
			}
		}
	}

	return allFindings, nil
}

// normalizeOpKey produces a stable key for matching operations,
// tolerant of LLM output variance (case, trailing slashes).
func normalizeOpKey(method, path string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	path = strings.TrimSpace(path)
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		path = strings.TrimRight(path, "/")
	}
	return method + " " + path
}

// newPlannerLLMClient creates the appropriate LLM client based on provider name.
func newPlannerLLMClient(provider, model string, timeout time.Duration) (planner.LLMClient, error) {
	switch provider {
	case "anthropic":
		return planner.NewAnthropicClient("", model, timeout)
	case "ollama":
		return planner.NewOllamaClient("", model, timeout), nil
	case "openai", "":
		return planner.NewOpenAIClient("", model, timeout)
	default:
		return nil, fmt.Errorf("unknown planner provider %q (use openai, anthropic, or ollama)", provider)
	}
}
