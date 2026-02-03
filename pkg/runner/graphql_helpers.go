// pkg/runner/graphql_helpers.go
package runner

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	internalhttp "github.com/praetorian-inc/hadrian/internal/http"
	"github.com/praetorian-inc/hadrian/pkg/graphql"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/templates"
)

// loadConfigs loads authentication and roles configuration files
func loadConfigs(authPath, rolesPath string) (*AuthConfig, *RolesConfig, error) {
	var authConfig *AuthConfig
	var rolesConfig *RolesConfig
	var err error

	// Load auth config if provided
	if authPath != "" {
		authConfig, err = LoadAuthConfig(authPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load auth config: %w", err)
		}
	}

	// Load roles config if provided
	if rolesPath != "" {
		rolesConfig, err = LoadRolesConfig(rolesPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load roles config: %w", err)
		}
	}

	return authConfig, rolesConfig, nil
}

// fetchSchema retrieves GraphQL schema via introspection or SDL file
func fetchSchema(ctx context.Context, config GraphQLConfig, httpClient templates.HTTPClient) (*graphql.Schema, error) {
	if config.Schema != "" {
		// Load schema from SDL file
		schema, err := graphql.LoadSchemaFromFile(config.Schema)
		if err != nil {
			return nil, fmt.Errorf("failed to load schema from file: %w", err)
		}
		return schema, nil
	}

	// Introspect endpoint
	endpoint := config.Target + config.Endpoint
	client := graphql.NewIntrospectionClient(httpClient, endpoint)
	schema, err := client.FetchSchema(ctx)
	if err != nil {
		return nil, fmt.Errorf("introspection failed: %w", err)
	}

	return schema, nil
}

// createGraphQLHTTPClient creates HTTP client with proxy, TLS, and timeout settings
func createGraphQLHTTPClient(config GraphQLConfig) (templates.HTTPClient, error) {
	httpConfig := &internalhttp.Config{
		Proxy:    config.Proxy,
		CACert:   config.CACert,
		Insecure: config.Insecure,
		Timeout:  time.Duration(config.Timeout) * time.Second,
	}
	return internalhttp.New(httpConfig)
}

// wrapWithRateLimiting wraps HTTP client with rate limiting
func wrapWithRateLimiting(httpClient templates.HTTPClient, config GraphQLConfig) templates.HTTPClient {
	// Create rate limiter
	limiter := NewRateLimiter(config.RateLimit, config.RateLimit)

	// Create rate limit config
	rateLimitConfig := &RateLimitConfig{
		Rate:           config.RateLimit,
		Enabled:        config.RateLimit > 0,
		BackoffType:    config.RateLimitBackoff,
		BackoffInitial: 1 * time.Second,
		BackoffMax:     config.RateLimitMaxWait,
		MaxRetries:     config.RateLimitMaxRetries,
		StatusCodes:    config.RateLimitStatusCodes,
	}

	// Wrap with rate limiting
	return NewRateLimitingClient(httpClient, limiter, rateLimitConfig)
}

// graphqlVerboseLog prints message if verbose mode is enabled (GraphQL-specific version)
func graphqlVerboseLog(verbose bool, format string, args ...interface{}) {
	if verbose {
		fmt.Printf(format+"\n", args...)
	}
}

// graphqlDryRunLog prints message if dry run mode is enabled (GraphQL-specific version)
func graphqlDryRunLog(dryRun bool, format string, args ...interface{}) {
	if dryRun {
		fmt.Printf("[DRY RUN] "+format+"\n", args...)
	}
}

// reportSchemaInfo prints discovered schema statistics
func reportSchemaInfo(schema *graphql.Schema, verbose bool) {
	graphqlVerboseLog(verbose, "Schema loaded successfully")
	graphqlVerboseLog(verbose, "  Queries: %d", len(schema.Queries))
	graphqlVerboseLog(verbose, "  Mutations: %d", len(schema.Mutations))
	graphqlVerboseLog(verbose, "  Types: %d", len(schema.Types))
}

// reportAuthConfigsLoaded prints auth configs status
func reportAuthConfigsLoaded(authPath string, rolesPath string, authConfig *AuthConfig, rolesConfig *RolesConfig, authConfigs map[string]*graphql.AuthInfo, verbose bool) {
	if authConfig != nil {
		graphqlVerboseLog(verbose, "Auth config loaded: %s", authPath)
	}
	if rolesConfig != nil {
		graphqlVerboseLog(verbose, "Roles config loaded: %s (%d roles)", rolesPath, len(rolesConfig.Roles))
	}
	if authConfigs != nil {
		graphqlVerboseLog(verbose, "Auth configs loaded: %d roles available for BOLA/BFLA testing", len(authConfigs))
	}
}

// buildAuthConfigs converts AuthConfig to the format needed by the GraphQL scanner
func buildAuthConfigs(authConfig *AuthConfig) (map[string]*graphql.AuthInfo, error) {
	// Return nil if no auth config or no roles
	if authConfig == nil || authConfig.Roles == nil || len(authConfig.Roles) == 0 {
		return nil, nil
	}

	authConfigs := make(map[string]*graphql.AuthInfo)

	for role, roleAuth := range authConfig.Roles {
		// Determine auth value based on method and validate required fields
		var authValue string
		switch authConfig.Method {
		case "bearer":
			if roleAuth.Token == "" {
				return nil, fmt.Errorf("role %s: bearer auth requires 'token' field", role)
			}
			authValue = roleAuth.Token

		case "api_key":
			if roleAuth.APIKey == "" {
				return nil, fmt.Errorf("role %s: api_key auth requires 'api_key' field", role)
			}
			authValue = roleAuth.APIKey

		case "basic":
			if roleAuth.Username == "" || roleAuth.Password == "" {
				return nil, fmt.Errorf("role %s: basic auth requires 'username' and 'password' fields", role)
			}
			// Encode username:password for Basic auth
			authValue = base64.StdEncoding.EncodeToString([]byte(roleAuth.Username + ":" + roleAuth.Password))

		default:
			return nil, fmt.Errorf("role %s: unsupported auth method: %s", role, authConfig.Method)
		}

		authConfigs[role] = &graphql.AuthInfo{
			Method:   authConfig.Method,
			Value:    authValue,
			Location: authConfig.Location,
			KeyName:  authConfig.KeyName,
		}
	}

	return authConfigs, nil
}

// convertGraphQLFinding converts a graphql.Finding to model.Finding for consistent reporting
func convertGraphQLFinding(gqlFinding *graphql.Finding) *model.Finding {
	// Map graphql severity to model severity (they use the same string values)
	severity := model.Severity(gqlFinding.Severity)

	// Create model.Finding with mapped fields
	finding := &model.Finding{
		ID:              gqlFinding.ID,
		Category:        string(gqlFinding.Type), // Use finding type as category
		Name:            string(gqlFinding.Type), // Use finding type as name
		Description:     gqlFinding.Evidence,     // GraphQL evidence becomes description
		Severity:        severity,
		Confidence:      1.0, // GraphQL findings have full confidence (not LLM-triaged)
		IsVulnerability: true,

		// Endpoint info - GraphQL always uses POST /graphql (or configured endpoint)
		Endpoint: "GraphQL Endpoint",
		Method:   "POST",

		// Evidence structure
		Evidence: model.Evidence{
			// Note: GraphQL findings don't have full HTTP request/response details yet
			// This can be enhanced in future when GraphQL scanner tracks full evidence
			Request: model.HTTPRequest{
				Method: "POST",
			},
			Response: model.HTTPResponse{},
		},

		Timestamp: time.Now(),
	}

	// Add GraphQL-specific details if present
	if len(gqlFinding.Details) > 0 {
		// Details could include attack parameters, etc.
		// For now, we can add them to the description
		finding.Description = fmt.Sprintf("%s (Details: %v)", gqlFinding.Evidence, gqlFinding.Details)
	}

	if gqlFinding.Remediation != "" {
		// Add remediation to description for now
		finding.Description = fmt.Sprintf("%s\nRemediation: %s", finding.Description, gqlFinding.Remediation)
	}

	return finding
}

// reportFindings prints security findings to stdout with color-coded severity
// DEPRECATED: Use Reporter pattern (createReporter) for consistent output
func reportFindings(findings []*graphql.Finding) {
	if len(findings) == 0 {
		fmt.Println("\nNo security issues found.")
		return
	}

	fmt.Printf("\n=== Security Findings (%d) ===\n\n", len(findings))
	for _, f := range findings {
		// Color-coded output based on severity
		switch f.Severity {
		case graphql.SeverityCritical, graphql.SeverityHigh:
			fmt.Printf("🔴 %s\n", f.Format())
		case graphql.SeverityMedium:
			fmt.Printf("🟡 %s\n", f.Format())
		default:
			fmt.Printf("🟢 %s\n", f.Format())
		}
		if f.Remediation != "" {
			fmt.Printf("   Remediation: %s\n", f.Remediation)
		}
		fmt.Println()
	}
}

// runSecurityChecks executes scanner checks and template tests, returning all findings and template count
func runSecurityChecks(ctx context.Context, schema *graphql.Schema, httpClient templates.HTTPClient, endpoint string, config GraphQLConfig, authConfigs map[string]*graphql.AuthInfo) ([]*graphql.Finding, int) {
	var findings []*graphql.Finding

	// Run built-in security checks unless skip flag is set
	if !config.SkipBuiltinChecks {
		// Create executor and scanner
		executor := graphql.NewExecutor(httpClient, endpoint)
		scanner := graphql.NewSecurityScanner(schema, executor, graphql.ScanConfig{
			DepthLimit:      config.DepthLimit,
			ComplexityLimit: config.ComplexityLimit,
			BatchSize:       config.BatchSize,
			Verbose:         config.Verbose,
		})

		// Run scanner checks with timeout
		graphqlVerboseLog(config.Verbose, "\n=== Running Security Checks ===")
		checkCtx, cancel := context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
		defer cancel()

		findings = scanner.RunAllChecks(checkCtx, authConfigs)
	} else {
		graphqlVerboseLog(config.Verbose, "\n=== Skipping Built-in Security Checks ===")
		findings = []*graphql.Finding{}
	}

	templateCount := 0
	// Execute GraphQL templates if provided
	if config.Templates != "" {
		templateFindings, count := runTemplateTests(ctx, config, endpoint, httpClient, authConfigs)
		findings = append(findings, templateFindings...)
		templateCount = count
	}

	return findings, templateCount
}

// filterGraphQLTemplatesByID filters GraphQL templates by ID patterns
func filterGraphQLTemplatesByID(tmpls []*templates.Template, filters []string) []*templates.Template {
	if len(filters) == 0 {
		return tmpls
	}

	var filtered []*templates.Template
	for _, tmpl := range tmpls {
		for _, filter := range filters {
			if tmpl.ID == filter {
				filtered = append(filtered, tmpl)
				break
			}
		}
	}
	return filtered
}

// filterGraphQLTemplatesByOWASP filters GraphQL templates by OWASP API Security categories
func filterGraphQLTemplatesByOWASP(tmpls []*templates.Template, categories []string) []*templates.Template {
	if len(categories) == 0 {
		return tmpls
	}

	// Build category lookup map
	categoryMap := make(map[string]bool)
	for _, cat := range categories {
		categoryMap[cat] = true
	}

	var filtered []*templates.Template
	for _, tmpl := range tmpls {
		// Check if template's category matches any filter
		if categoryMap[tmpl.Info.Category] {
			filtered = append(filtered, tmpl)
		}
	}
	return filtered
}

// runTemplateTests executes GraphQL templates and returns findings and template count
func runTemplateTests(ctx context.Context, config GraphQLConfig, endpoint string, httpClient templates.HTTPClient, authConfigs map[string]*graphql.AuthInfo) ([]*graphql.Finding, int) {
	graphqlVerboseLog(config.Verbose, "\n=== Running GraphQL Templates ===")

	// Load templates
	tmplFiles, err := loadGraphQLTemplates(config.Templates)
	if err != nil {
		fmt.Printf("Error loading templates: %v\n", err)
		return nil, 0
	}

	// Apply filters
	tmplFiles = filterGraphQLTemplatesByID(tmplFiles, config.TemplateFilters)
	tmplFiles = filterGraphQLTemplatesByOWASP(tmplFiles, config.OWASPCategories)

	templateCount := len(tmplFiles)
	graphqlVerboseLog(config.Verbose, "Loaded %d template(s) from: %s", templateCount, config.Templates)

	if len(config.TemplateFilters) > 0 {
		graphqlVerboseLog(config.Verbose, "Filtered by templates: %v", config.TemplateFilters)
	}
	if len(config.OWASPCategories) > 0 {
		graphqlVerboseLog(config.Verbose, "Filtered by OWASP categories: %v", config.OWASPCategories)
	}

	// Create template executor
	tmplExecutor := templates.NewExecutor(httpClient)

	var findings []*graphql.Finding

	// Execute each template
	for _, tmpl := range tmplFiles {
		// Compile template
		compiled, err := templates.Compile(tmpl)
		if err != nil {
			fmt.Printf("Error compiling template %s: %v\n", tmpl.ID, err)
			continue
		}

		// Convert authConfigs to templates.AuthInfo map
		var tmplAuthInfos map[string]*templates.AuthInfo
		if authConfigs != nil {
			tmplAuthInfos = make(map[string]*templates.AuthInfo)
			for role, info := range authConfigs {
				tmplAuthInfos[role] = &templates.AuthInfo{
					Method:   info.Method,
					Value:    info.Value,
					Location: info.Location,
					KeyName:  info.KeyName,
				}
			}
		}

		// Execute template
		result, err := tmplExecutor.ExecuteGraphQL(ctx, compiled, endpoint, tmplAuthInfos, nil)
		if err != nil {
			fmt.Printf("Error executing template %s: %v\n", tmpl.ID, err)
			continue
		}

		// Convert matched template results to graphql.Finding
		if result.Matched {
			// Map template severity string to graphql.Severity
			severity := mapTemplateSeverity(tmpl.Info.Severity)

			// Build evidence string
			evidence := tmpl.Info.Name
			if len(result.Response.Body) > 0 {
				evidence = fmt.Sprintf("%s - %s", tmpl.Info.Name, string(result.Response.Body))
			}

			// Create finding using template ID as the type
			finding := graphql.NewFinding(
				graphql.FindingType(tmpl.ID),
				severity,
				evidence,
			)

			// Add template details
			finding.WithDetails(map[string]interface{}{
				"template_name": tmpl.Info.Name,
				"category":      tmpl.Info.Category,
				"description":   tmpl.Info.Description,
				"endpoint":      endpoint,
			})

			findings = append(findings, finding)

			// Verbose per-template status removed - findings are reported in summary
		}
	}

	return findings, templateCount
}

// mapTemplateSeverity converts template severity string to graphql.Severity
func mapTemplateSeverity(severity string) graphql.Severity {
	switch severity {
	case "CRITICAL":
		return graphql.SeverityCritical
	case "HIGH":
		return graphql.SeverityHigh
	case "MEDIUM":
		return graphql.SeverityMedium
	case "LOW":
		return graphql.SeverityLow
	case "INFO":
		return graphql.SeverityInfo
	default:
		return graphql.SeverityMedium // Default to medium if unknown
	}
}
