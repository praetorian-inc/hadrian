package runner

import (
	"context"
	"fmt"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/auth"
	"github.com/praetorian-inc/hadrian/pkg/log"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/orchestrator"
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

	var allFindings []*model.Finding
	for _, op := range spec.Operations {
		for _, tmpl := range tmplFiles {
			if !templateApplies(tmpl, op) {
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

	return allFindings, nil
}
