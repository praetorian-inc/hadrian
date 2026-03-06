// pkg/runner/graphql_helpers.go
package runner

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	internalhttp "github.com/praetorian-inc/hadrian/internal/http"
	"github.com/praetorian-inc/hadrian/pkg/graphql"
	"github.com/praetorian-inc/hadrian/pkg/log"
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
func fetchSchema(ctx context.Context, config GraphQLConfig, httpClient templates.HTTPClient, customHeaders map[string]string) (*graphql.Schema, error) {
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
	for k, v := range customHeaders {
		client.SetHeader(k, v)
	}
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
			authValue = "Bearer " + roleAuth.Token

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

		case "cookie":
			if roleAuth.Cookie == "" {
				return nil, fmt.Errorf("role %s: cookie auth requires 'cookie' field", role)
			}
			cookieName := authConfig.CookieName
			if cookieName == "" {
				cookieName = "session"
			}
			authValue = cookieName + "=" + roleAuth.Cookie

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

// reportFindings prints security findings to stdout with color-coded severity.
// NOTE: This function is deprecated and kept for backward compatibility only.
//
// Deprecated: Use Reporter pattern (createReporter) for consistent output.
func reportFindings(findings []*model.Finding) {
	if len(findings) == 0 {
		fmt.Println("\nNo security issues found.")
		return
	}

	fmt.Printf("\n=== Security Findings (%d) ===\n\n", len(findings))
	for _, f := range findings {
		// Color-coded output based on severity
		switch f.Severity {
		case model.SeverityCritical, model.SeverityHigh:
			fmt.Printf("🔴 [%s] %s - %s\n  Description: %s\n", f.Severity, f.Category, f.Name, f.Description)
		case model.SeverityMedium:
			fmt.Printf("🟡 [%s] %s - %s\n  Description: %s\n", f.Severity, f.Category, f.Name, f.Description)
		default:
			fmt.Printf("🟢 [%s] %s - %s\n  Description: %s\n", f.Severity, f.Category, f.Name, f.Description)
		}
		fmt.Println()
	}
}

// runSecurityChecks executes scanner checks and template tests, returning all findings and template count
func runSecurityChecks(ctx context.Context, schema *graphql.Schema, httpClient templates.HTTPClient, endpoint string, config GraphQLConfig, authConfigs map[string]*graphql.AuthInfo, reporter Reporter, customHeaders map[string]string) ([]*model.Finding, int) {
	var findings []*model.Finding

	// Run built-in security checks unless skip flag is set
	if !config.SkipBuiltinChecks {
		// Create executor and scanner
		executor := graphql.NewExecutor(httpClient, endpoint, customHeaders)
		scanner := graphql.NewSecurityScanner(schema, executor, graphql.ScanConfig{
			DepthLimit:      config.DepthLimit,
			ComplexityLimit: config.ComplexityLimit,
			BatchSize:       config.BatchSize,
			Verbose:         config.Verbose,
			Endpoint:        endpoint,
		})

		// Create callback that uses reporter for real-time output
		var onFinding graphql.FindingCallback
		if config.Verbose && reporter != nil {
			onFinding = func(f *model.Finding) {
				reporter.ReportFinding(f)
			}
		}

		// Run scanner checks with timeout
		graphqlVerboseLog(config.Verbose, "\n=== Running Security Checks ===")
		checkCtx, cancel := context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
		defer cancel()

		findings = scanner.RunAllChecks(checkCtx, authConfigs, onFinding)
	} else {
		graphqlVerboseLog(config.Verbose, "\n=== Skipping Built-in Security Checks ===")
		findings = []*model.Finding{}
	}

	templateCount := 0
	// Execute GraphQL templates if provided
	if config.TemplateDir != "" {
		templateFindings, count := runTemplateTests(ctx, config, endpoint, httpClient, authConfigs, reporter, customHeaders)
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

// runTemplateTests executes GraphQL templates and returns findings and template count
func runTemplateTests(ctx context.Context, config GraphQLConfig, endpoint string, httpClient templates.HTTPClient, authConfigs map[string]*graphql.AuthInfo, reporter Reporter, customHeaders map[string]string) ([]*model.Finding, int) {
	graphqlVerboseLog(config.Verbose, "\n=== Running GraphQL Templates ===")

	// Load templates
	tmplFiles, err := loadGraphQLTemplates(config.TemplateDir)
	if err != nil {
		fmt.Printf("Error loading templates: %v\n", err)
		return nil, 0
	}

	// Apply filters
	tmplFiles = filterGraphQLTemplatesByID(tmplFiles, config.Templates)

	templateCount := len(tmplFiles)
	graphqlVerboseLog(config.Verbose, "Loaded %d template(s) from: %s", templateCount, config.TemplateDir)

	if len(config.Templates) > 0 {
		graphqlVerboseLog(config.Verbose, "Filtered by templates: %v", config.Templates)
	}

	// Create template executor
	tmplExecutor := templates.NewExecutor(httpClient, customHeaders)

	var findings []*model.Finding

	// Execute each template
	for _, tmpl := range tmplFiles {
		// Compile template
		compiled, err := templates.Compile(tmpl)
		if err != nil {
			// Use log.Warn for consistent warning output
			log.Warn("Failed to compile GraphQL template %s: %v", tmpl.ID, err)
			continue
		}

		// Convert authConfigs to templates.AuthInfo map
		var tmplAuthInfos map[string]*templates.AuthInfo
		var attackerRole, victimRole string
		if authConfigs != nil {
			tmplAuthInfos = make(map[string]*templates.AuthInfo)
			for role, info := range authConfigs {
				tmplAuthInfos[role] = &templates.AuthInfo{
					Method:   info.Method,
					Value:    info.Value,
					Location: info.Location,
					KeyName:  info.KeyName,
				}
				// Track roles for reporting
				if role == "attacker" {
					attackerRole = role
				} else if role == "victim" {
					victimRole = role
				}
			}
		}

		// Execute template
		result, err := tmplExecutor.ExecuteGraphQL(ctx, compiled, endpoint, tmplAuthInfos, nil)
		if err != nil {
			// Use log.Warn for consistent warning output
			log.Warn("GraphQL template execution failed [template=%s, endpoint=%s]: %v", tmpl.ID, endpoint, err)
			continue
		}

		// Convert matched template results to model.Finding
		if result.Matched {
			// Map template severity string to model.Severity
			severity := mapTemplateSeverity(tmpl.Info.Severity)

			// Build evidence string
			description := tmpl.Info.Name
			if len(result.Response.Body) > 0 {
				description = fmt.Sprintf("%s - %s", tmpl.Info.Name, string(result.Response.Body))
			}
			if tmpl.Info.Description != "" {
				description = fmt.Sprintf("%s\n%s", description, tmpl.Info.Description)
			}

			// Create model.Finding using template ID as the name
			finding := &model.Finding{
				ID:              generateGraphQLID(),
				Category:        tmpl.Info.Category,
				Name:            tmpl.ID,
				Description:     description,
				Severity:        severity,
				Confidence:      1.0,
				IsVulnerability: true,
				Endpoint:        endpoint,
				Method:          "POST",
				RequestIDs:      result.RequestIDs,
				Timestamp:       time.Now(),
			}

			// Populate roles if they were used in the template
			if attackerRole != "" {
				finding.AttackerRole = attackerRole
			}
			if victimRole != "" {
				finding.VictimRole = victimRole
			}

			findings = append(findings, finding)

			// Report finding in verbose mode via reporter
			if config.Verbose && reporter != nil {
				reporter.ReportFinding(finding)
			}
		}
	}

	return findings, templateCount
}

// generateGraphQLID generates a unique hexadecimal ID for GraphQL findings
func generateGraphQLID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		panic(fmt.Sprintf("failed to generate random ID: %v", err))
	}
	return hex.EncodeToString(b)
}

// mapTemplateSeverity converts template severity string to model.Severity
func mapTemplateSeverity(severity string) model.Severity {
	switch severity {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH":
		return model.SeverityHigh
	case "MEDIUM":
		return model.SeverityMedium
	case "LOW":
		return model.SeverityLow
	case "INFO":
		return model.SeverityInfo
	default:
		return model.SeverityMedium // Default to medium if unknown
	}
}
