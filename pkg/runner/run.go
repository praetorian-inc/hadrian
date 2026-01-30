package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/auth"
	"github.com/praetorian-inc/hadrian/pkg/log"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/owasp"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/praetorian-inc/hadrian/pkg/templates"
	"github.com/spf13/cobra"
)

// Config holds the test command configuration
type Config struct {
	API              string
	Roles            string
	Auth             string
	Proxy            string
	CACert           string
	Insecure         bool
	Concurrency      int
	RateLimit        float64
	Timeout          int
	AllowProduction  bool
	AllowInternal    bool
	Output           string
	OutputFile       string
	Categories       []string
	TemplateDir      string   // Directory containing templates
	Templates        []string // Filter templates by ID or name
	AuditLog         string
	OWASPCategories  []string
	Verbose          bool
	DryRun           bool
	RequestIDsLimit  int      // Number of request IDs to display per finding (0 = all)
}

// Run is the main entry point for the Hadrian CLI
func Run() error {
	rootCmd := &cobra.Command{
		Use:   "hadrian",
		Short: "Hadrian - API Security Testing Framework",
		Long:  `Hadrian is a security testing framework for REST APIs that tests for OWASP vulnerabilities and custom security issues.`,
	}

	rootCmd.AddCommand(newTestCmd())
	rootCmd.AddCommand(newParseCmd())
	rootCmd.AddCommand(newVersionCmd())

	return rootCmd.Execute()
}

// newTestCmd creates the test command
func newTestCmd() *cobra.Command {
	var config Config

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Run security tests against an API",
		Long:  `Run security tests against an API using the provided specification and roles configuration.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTest(cmd.Context(), config)
		},
	}

	// Required flags
	cmd.Flags().StringVar(&config.API, "api", "", "API specification (OpenAPI, Swagger, Postman)")
	cmd.Flags().StringVar(&config.Roles, "roles", "", "Roles and permissions YAML file")
	cmd.MarkFlagRequired("api")
	cmd.MarkFlagRequired("roles")

	// Optional flags
	cmd.Flags().StringVar(&config.Auth, "auth", "", "Authentication configuration YAML file")
	cmd.Flags().StringVar(&config.Proxy, "proxy", "", "HTTP/HTTPS proxy URL (e.g., http://localhost:8080)")
	cmd.Flags().StringVar(&config.CACert, "ca-cert", "", "CA certificate for proxy (Burp Suite)")
	cmd.Flags().BoolVar(&config.Insecure, "insecure", false, "Skip TLS verification (use with proxies)")
	cmd.Flags().IntVar(&config.Concurrency, "concurrency", 1, "Concurrent requests (max: 10)")
	cmd.Flags().Float64Var(&config.RateLimit, "rate-limit", 5.0, "Global rate limit (req/s)")
	cmd.Flags().IntVar(&config.Timeout, "timeout", 30, "Request timeout (seconds)")
	cmd.Flags().BoolVar(&config.AllowProduction, "allow-production", false, "Allow testing production URLs")
	cmd.Flags().BoolVar(&config.AllowInternal, "allow-internal", false, "Allow testing internal/private IP addresses")
	cmd.Flags().StringVar(&config.Output, "output", "terminal", "Output format: terminal, json, markdown")
	cmd.Flags().StringVar(&config.OutputFile, "output-file", "", "Write findings to file")
	cmd.Flags().StringSliceVar(&config.Categories, "category", []string{"owasp"}, "Test categories (owasp, custom)")
	cmd.Flags().StringVar(&config.TemplateDir, "template-dir", "", "Directory containing test templates (default: $HADRIAN_TEMPLATES or ./templates/owasp)")
	cmd.Flags().StringSliceVar(&config.Templates, "template", []string{}, "Filter templates by ID or name (can specify multiple)")
	cmd.Flags().StringVar(&config.AuditLog, "audit-log", ".hadrian/audit.log", "Audit log file")
	cmd.Flags().StringSliceVar(&config.OWASPCategories, "owasp", []string{}, "OWASP API categories to test (e.g., API1,API2,API5,API9)")
	cmd.Flags().BoolVarP(&config.Verbose, "verbose", "v", false, "Enable verbose logging output")
	cmd.Flags().BoolVar(&config.DryRun, "dry-run", false, "Show what would be tested without making requests")
	cmd.Flags().IntVar(&config.RequestIDsLimit, "request-ids", 1, "Number of request IDs to display per finding (0 = all)")

	return cmd
}

// newParseCmd creates the parse command
func newParseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "parse <api-spec-file>",
		Short: "Parse API specification and show operations",
		Long:  `Parse an API specification file (OpenAPI, Swagger, Postman) and display all operations.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return parseCmdHandler(args[0])
		},
	}

	return cmd
}

// newVersionCmd creates the version command
func newVersionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show Hadrian version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Hadrian v1.0.0")
		},
	}

	return cmd
}

// runTest executes security tests against an API (Batch 18 implementation)
func runTest(ctx context.Context, config Config) error {
	startTime := time.Now()

	// Enable verbose logging if requested
	log.SetVerbose(config.Verbose)

	// 1. Validate configuration
	if err := config.Validate(); err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	// 2. Parse API specification
	spec, err := parseAPISpec(config.API)
	if err != nil {
		return fmt.Errorf("failed to parse API spec: %w", err)
	}

	// 3. Production safety checks (HR-1, CR-4)
	if err := ConfirmProductionTesting(spec.BaseURL, config.AllowProduction); err != nil {
		return err
	}
	if err := BlockInternalIPs(spec.BaseURL, config.AllowInternal); err != nil {
		return err
	}

	// 4. Load role configuration
	rolesCfg, err := roles.Load(config.Roles)
	if err != nil {
		return fmt.Errorf("failed to load roles: %w", err)
	}

	// 5. Load auth configuration (optional)
	var authCfg *auth.AuthConfig
	if config.Auth != "" {
		authCfg, err = auth.Load(config.Auth)
		if err != nil {
			return fmt.Errorf("failed to load auth config: %w", err)
		}
	}

	// 6. Create HTTP client with proxy support
	httpClient, err := createHTTPClient(config)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// 7. Create reporter based on output format
	rep, err := createReporter(config.Output, config.OutputFile, config.RequestIDsLimit)
	if err != nil {
		return fmt.Errorf("failed to create reporter: %w", err)
	}
	defer rep.Close()

	// 8. Load templates
	templateDir := config.TemplateDir
	if templateDir == "" {
		templateDir = getTemplateDir()
	}

	tmplFiles, err := loadTemplateFiles(templateDir, config.Categories)
	if err != nil {
		return fmt.Errorf("failed to load templates from %s: %w", templateDir, err)
	}

	// Apply template filters if specified
	if len(config.Templates) > 0 {
		tmplFiles = filterByTemplates(tmplFiles, config.Templates)
		if len(tmplFiles) == 0 {
			return fmt.Errorf("no templates matched the specified filters: %v", config.Templates)
		}
	}

	// Filter by OWASP categories if specified
	if len(config.OWASPCategories) > 0 {
		tmplFiles = filterTemplatesByOWASP(tmplFiles, config.OWASPCategories)
		fmt.Printf("[INFO] Filtered to %d templates matching OWASP categories: %v\n", len(tmplFiles), config.OWASPCategories)
	}

	fmt.Printf("[INFO] Loaded %d templates\n", len(tmplFiles))
	fmt.Printf("[INFO] Testing %d operations against %d roles\n", len(spec.Operations), len(rolesCfg.Roles))

	// 9. Create template executor
	executor := templates.NewExecutor(httpClient)

	// 10. Create mutation executor for mutation templates
	mutationExecutor := owasp.NewMutationExecutor(httpClient)

	// 11. Run tests for each operation
	var allFindings []*model.Finding
	for _, op := range spec.Operations {
		for _, tmpl := range tmplFiles {
			// Check if template applies to this operation
			if !templateApplies(tmpl, op) {
				continue
			}

			// Execute template for each role combination
			findings, err := executeTemplate(ctx, executor, mutationExecutor, tmpl, op, rolesCfg, authCfg, spec.BaseURL)
			if err != nil {
				log.Warn("Template %s failed on %s %s: %v", tmpl.ID, op.Method, op.Path, err)
				continue
			}

			// Real-time reporting
			for _, f := range findings {
				rep.ReportFinding(f)
			}

			allFindings = append(allFindings, findings...)
		}
	}

	// 11. Optional LLM triage
	if hasLLMConfig() {
		allFindings, _ = triageWithLLM(ctx, allFindings, rolesCfg)
	}

	// 12. Generate final report
	stats := calculateStats(allFindings, startTime)
	stats.OperationCount = len(spec.Operations)
	stats.RoleCount = len(rolesCfg.Roles)
	stats.TemplatesLoaded = len(tmplFiles)

	return rep.GenerateReport(allFindings, stats)
}

// parseCmdHandler parses and displays API specification details
func parseCmdHandler(apiSpecFile string) error {
	spec, err := parseAPISpec(apiSpecFile)
	if err != nil {
		return err
	}

	fmt.Printf("API: %s (v%s)\n", spec.Info.Title, spec.Info.Version)
	fmt.Printf("Base URL: %s\n", spec.BaseURL)
	fmt.Printf("Operations: %d\n\n", len(spec.Operations))

	for _, op := range spec.Operations {
		fmt.Printf("  %s %s\n", op.Method, op.Path)
		if op.RequiresAuth {
			fmt.Printf("    [Auth Required]\n")
		}
		if len(op.PathParams) > 0 {
			fmt.Printf("    Path params: ")
			for i, p := range op.PathParams {
				if i > 0 {
					fmt.Printf(", ")
				}
				fmt.Printf("{%s}", p.Name)
			}
			fmt.Println()
		}
	}

	return nil
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// getTemplateDir returns the template directory path
func getTemplateDir() string {
	// Check for environment variable override
	if dir := os.Getenv("HADRIAN_TEMPLATES"); dir != "" {
		return dir
	}

	// Default to ./templates/owasp/ relative to current directory
	return "./templates/owasp"
}

// loadTemplateFiles loads and compiles templates from directory
func loadTemplateFiles(dir string, categories []string) ([]*templates.CompiledTemplate, error) {
	var result []*templates.CompiledTemplate

	// Walk template directory
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-YAML files
		if info.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		// Check if template matches requested categories
		for _, cat := range categories {
			if strings.Contains(path, cat) || cat == "all" {
				tmpl, err := templates.Parse(path)
				if err != nil {
					log.Warn("Failed to parse template %s: %v", path, err)
					return nil
				}

				compiled, err := templates.Compile(tmpl)
				if err != nil {
					log.Warn("Failed to compile template %s: %v", path, err)
					return nil
				}

				compiled.FilePath = path
				result = append(result, compiled)
				break
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Sort templates by file path for deterministic execution order
	sort.Slice(result, func(i, j int) bool {
		return result[i].FilePath < result[j].FilePath
	})

	return result, nil
}

// templateApplies checks if template selector matches operation
func templateApplies(tmpl *templates.CompiledTemplate, op *model.Operation) bool {
	sel := tmpl.EndpointSelector

	// Check method filter
	if len(sel.Methods) > 0 {
		methodMatch := false
		for _, m := range sel.Methods {
			if strings.EqualFold(m, op.Method) {
				methodMatch = true
				break
			}
		}
		if !methodMatch {
			return false
		}
	}

	// Check path parameter requirement
	if sel.HasPathParameter && len(op.PathParams) == 0 {
		return false
	}

	// Check auth requirement
	if sel.RequiresAuth && !op.RequiresAuth {
		return false
	}

	// Check path pattern (regex match)
	if sel.PathPattern != "" {
		matched, err := regexp.MatchString(sel.PathPattern, op.Path)
		if err != nil || !matched {
			return false
		}
	}

	return true
}

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

// hasLLMConfig checks if LLM provider is configured
func hasLLMConfig() bool {
	return os.Getenv("ANTHROPIC_API_KEY") != "" ||
		os.Getenv("OPENAI_API_KEY") != "" ||
		os.Getenv("OLLAMA_HOST") != ""
}

// filterByTemplates filters templates by ID, filename, or path suffix.
// Matching is case-insensitive. Supports:
//   - Template ID (e.g., "bola-idor-basic")
//   - Filename with or without extension (e.g., "bola-idor-basic.yaml" or "bola-idor-basic")
//   - Path suffix (e.g., "templates/owasp/bola-idor-basic.yaml")
//
// If templateFilters is empty, returns all templates unchanged.
func filterByTemplates(tmpls []*templates.CompiledTemplate, templateFilters []string) []*templates.CompiledTemplate {
	if len(templateFilters) == 0 {
		return tmpls
	}

	var result []*templates.CompiledTemplate
	for _, tmpl := range tmpls {
		if templateMatchesAnyFilter(tmpl, templateFilters) {
			result = append(result, tmpl)
		}
	}
	return result
}


// filterTemplatesByOWASP filters templates by OWASP category prefix.
// If owaspCategories is empty, returns all templates unchanged.
func filterTemplatesByOWASP(tmpls []*templates.CompiledTemplate, owaspCategories []string) []*templates.CompiledTemplate {
	if len(owaspCategories) == 0 {
		return tmpls
	}

	var result []*templates.CompiledTemplate
	for _, tmpl := range tmpls {
		for _, cat := range owaspCategories {
			if strings.HasPrefix(strings.ToUpper(tmpl.Info.Category), strings.ToUpper(cat)) {
				result = append(result, tmpl)
				break
			}
		}
	}
	return result
}

// verboseLog writes a formatted message to w only if verbose mode is enabled.
func verboseLog(w io.Writer, verbose bool, format string, args ...interface{}) {
	if verbose {
		fmt.Fprintf(w, "[VERBOSE] "+format+"\n", args...)
	}
}

// dryRunLog writes a formatted message to w only if dry-run mode is enabled.
func dryRunLog(w io.Writer, dryRun bool, format string, args ...interface{}) {
	if dryRun {
		fmt.Fprintf(w, "[DRY-RUN] "+format+"\n", args...)
	}
}
