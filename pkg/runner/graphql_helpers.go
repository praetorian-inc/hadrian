// pkg/runner/graphql_helpers.go
package runner

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/graphql"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/oob"
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
func fetchSchema(ctx context.Context, config GraphQLConfig, httpClient *http.Client) (*graphql.Schema, error) {
	if config.Schema != "" {
		// SDL file loading requested but not yet implemented
		return nil, fmt.Errorf("SDL file loading not yet implemented - use introspection for now")
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

// reportSchemaInfo prints discovered schema statistics
func reportSchemaInfo(schema *graphql.Schema) {
	fmt.Println("Schema loaded successfully")
	fmt.Printf("  Queries: %d\n", len(schema.Queries))
	fmt.Printf("  Mutations: %d\n", len(schema.Mutations))
	fmt.Printf("  Types: %d\n", len(schema.Types))
}

// reportAuthConfigsLoaded prints auth configs status
func reportAuthConfigsLoaded(authPath string, rolesPath string, authConfig *AuthConfig, rolesConfig *RolesConfig, authConfigs map[string]*graphql.AuthInfo) {
	if authConfig != nil {
		fmt.Printf("Auth config loaded: %s\n", authPath)
	}
	if rolesConfig != nil {
		fmt.Printf("Roles config loaded: %s (%d roles)\n", rolesPath, len(rolesConfig.Roles))
	}
	if authConfigs != nil {
		fmt.Printf("Auth configs loaded: %d roles available for BOLA/BFLA testing\n", len(authConfigs))
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

// runSecurityChecks executes scanner checks and template tests, returning all findings
func runSecurityChecks(ctx context.Context, schema *graphql.Schema, httpClient *http.Client, endpoint string, config GraphQLConfig, authConfigs map[string]*graphql.AuthInfo) []*graphql.Finding {
	// Create executor and scanner
	executor := graphql.NewExecutor(httpClient, endpoint)
	scanner := graphql.NewSecurityScanner(schema, executor, graphql.ScanConfig{
		DepthLimit:      config.DepthLimit,
		ComplexityLimit: config.ComplexityLimit,
		BatchSize:       config.BatchSize,
		Verbose:         config.Verbose,
	})

	// Run scanner checks with timeout
	fmt.Println("\n=== Running Security Checks ===")
	checkCtx, cancel := context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
	defer cancel()

	findings := scanner.RunAllChecks(checkCtx, authConfigs)

	// Execute GraphQL templates if provided
	if config.Templates != "" {
		templateFindings := runTemplateTests(ctx, config, endpoint, httpClient, authConfigs)
		findings = append(findings, templateFindings...)
	}

	return findings
}

// runTemplateTests executes GraphQL templates and returns findings (converted from template results)
func runTemplateTests(ctx context.Context, config GraphQLConfig, endpoint string, httpClient *http.Client, authConfigs map[string]*graphql.AuthInfo) []*graphql.Finding {
	fmt.Println("\n=== Running GraphQL Templates ===")

	// Load templates
	tmplFiles, err := loadGraphQLTemplates(config.Templates)
	if err != nil {
		fmt.Printf("Error loading templates: %v\n", err)
		return nil
	}

	fmt.Printf("Loaded %d template(s) from: %s\n", len(tmplFiles), config.Templates)

	// Initialize OOB detection based on user configuration
	var tmplExecutor *templates.Executor
	if config.EnableOOB {
		if config.OOBURL != "" {
			// User provided their own OOB callback URL - no interactsh client needed
			if config.Verbose {
				fmt.Printf("OOB detection enabled with user-provided URL: %s\n", config.OOBURL)
			}
			tmplExecutor = templates.NewExecutor(httpClient, templates.WithUserOOBURL(config.OOBURL))
		} else {
			// Legacy mode: auto-generate interactsh URL
			var oobClient *oob.Client
			oobCfg := oob.Config{
				ServerURL:   config.OOBServerURL,
				PollTimeout: time.Duration(config.OOBTimeout) * time.Second,
			}
			oobClient, err = oob.NewClient(oobCfg)
			if err != nil {
				fmt.Printf("Failed to create OOB client: %v\n", err)
				return nil
			}
			defer oobClient.Close()
			if config.Verbose {
				fmt.Printf("OOB detection enabled (interactsh): %s\n", oobClient.GenerateURL())
			}
			tmplExecutor = templates.NewExecutor(httpClient, templates.WithOOBClient(oobClient))
		}
	} else {
		// OOB detection disabled
		tmplExecutor = templates.NewExecutor(httpClient)
	}

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

		// Report findings from template
		if result.Matched {
			fmt.Printf("🔴 [%s] %s\n", tmpl.Info.Severity, tmpl.Info.Name)
			if len(result.Response.Body) > 0 {
				fmt.Printf("   Evidence: %s\n", result.Response.Body)
			}
			// Note: Template results are printed directly but not converted to graphql.Finding
			// This maintains existing behavior where template findings are separate from scanner findings
		} else if config.Verbose {
			fmt.Printf("✅ [%s] %s - No vulnerability detected\n", tmpl.Info.Severity, tmpl.Info.Name)
		}
	}

	return findings
}
