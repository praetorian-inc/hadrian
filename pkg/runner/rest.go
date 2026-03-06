package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/auth"
	"github.com/praetorian-inc/hadrian/pkg/log"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/orchestrator"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/praetorian-inc/hadrian/pkg/templates"
	"github.com/spf13/cobra"
)

// Config holds the test command configuration
type Config struct {
	API                  string
	Roles                string
	Auth                 string
	Proxy                string
	CACert               string
	Insecure             bool
	Concurrency          int
	RateLimit            float64
	RateLimitBackoff     string        // Backoff type: exponential or fixed
	RateLimitMaxWait     time.Duration // Maximum backoff wait time
	RateLimitMaxRetries  int           // Maximum retry attempts on rate limit
	RateLimitStatusCodes []int         // Status codes that trigger rate limit retry
	Timeout              int
	Output               string
	OutputFile           string
	Categories           []string
	TemplateDir          string   // Directory containing templates
	Templates            []string // Filter templates by ID or name
	AuditLog             string
	Verbose              bool
	DryRun               bool
	RequestIDsLimit      int      // Number of request IDs to display per finding (0 = all)
	LLMHost              string   // LLM provider host (e.g., http://localhost:11434 for Ollama)
	LLMModel             string   // LLM model name (e.g., llama3.2:latest)
	LLMTimeout           int      // LLM request timeout in seconds
	LLMContext           string   // Additional context for LLM prompts
	Headers              []string // Custom HTTP headers (format: "Key: Value")
}

// newTestRestCmd creates the "test rest" subcommand (was previously the main test command)
func newTestRestCmd() *cobra.Command {
	var config Config

	cmd := &cobra.Command{
		Use:   "rest",
		Short: "Run security tests against a REST API",
		Long:  `Run security tests against a REST API using OpenAPI/Swagger specification.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTest(cmd.Context(), config)
		},
	}

	// Required flags
	cmd.Flags().StringVar(&config.API, "api", "", "API specification (OpenAPI, Swagger, Postman)")
	cmd.Flags().StringVar(&config.Roles, "roles", "", "Roles and permissions YAML file")
	_ = cmd.MarkFlagRequired("api")
	_ = cmd.MarkFlagRequired("roles")

	// Optional flags
	cmd.Flags().StringVar(&config.Auth, "auth", "", "Authentication configuration YAML file")
	cmd.Flags().StringVar(&config.Proxy, "proxy", "", "HTTP/HTTPS proxy URL (e.g., http://localhost:8080)")
	cmd.Flags().StringVar(&config.CACert, "ca-cert", "", "CA certificate for proxy (Burp Suite)")
	cmd.Flags().BoolVar(&config.Insecure, "insecure", false, "Skip TLS verification (use with proxies)")
	cmd.Flags().IntVar(&config.Concurrency, "concurrency", 1, "Concurrent requests (max: 10)")
	cmd.Flags().Float64Var(&config.RateLimit, "rate-limit", 5.0, "Global rate limit (req/s)")
	cmd.Flags().StringVar(&config.RateLimitBackoff, "rate-limit-backoff", "exponential", "Backoff type for rate limit retries: exponential, fixed")
	cmd.Flags().DurationVar(&config.RateLimitMaxWait, "rate-limit-max-wait", 60*time.Second, "Maximum backoff wait time on rate limit")
	cmd.Flags().IntVar(&config.RateLimitMaxRetries, "rate-limit-max-retries", 5, "Maximum retry attempts on rate limit response")
	cmd.Flags().IntSliceVar(&config.RateLimitStatusCodes, "rate-limit-status-codes", []int{429, 503}, "Status codes that trigger rate limit retry")
	cmd.Flags().IntVar(&config.Timeout, "timeout", 30, "Request timeout (seconds)")
	cmd.Flags().StringVar(&config.Output, "output", "terminal", "Output format: terminal, json, markdown")
	cmd.Flags().StringVar(&config.OutputFile, "output-file", "", "Write findings to file")
	cmd.Flags().StringSliceVar(&config.Categories, "category", []string{"owasp"}, "Test categories (owasp, custom)")
	cmd.Flags().StringVar(&config.TemplateDir, "template-dir", "", "Directory containing test templates (default: $HADRIAN_TEMPLATES or ./templates/rest)")
	cmd.Flags().StringSliceVar(&config.Templates, "template", []string{}, "Filter templates by ID or name (can specify multiple)")
	cmd.Flags().StringVar(&config.AuditLog, "audit-log", ".hadrian/audit.log", "Audit log file")
	cmd.Flags().BoolVarP(&config.Verbose, "verbose", "v", false, "Enable verbose logging output")
	cmd.Flags().BoolVar(&config.DryRun, "dry-run", false, "Show what would be tested without making requests")
	cmd.Flags().IntVar(&config.RequestIDsLimit, "request-ids", 1, "Number of request IDs to display per finding (0 = all)")

	// LLM configuration
	cmd.Flags().StringVar(&config.LLMHost, "llm-host", "", "LLM provider host URL (e.g., http://localhost:11434 for Ollama)")
	cmd.Flags().StringVar(&config.LLMModel, "llm-model", "", "LLM model name (e.g., llama3.2:latest)")
	cmd.Flags().IntVar(&config.LLMTimeout, "llm-timeout", 180, "LLM request timeout in seconds")
	cmd.Flags().StringVar(&config.LLMContext, "llm-context", "", "Additional context for LLM analysis (e.g., 'This API handles financial data')")

	// Custom headers
	cmd.Flags().StringArrayVarP(&config.Headers, "header", "H", []string{}, "Custom HTTP header (format: 'Key: Value', can specify multiple)")

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

	// Parse custom headers
	customHeaders, err := ParseCustomHeaders(config.Headers)
	if err != nil {
		return fmt.Errorf("invalid custom header: %w", err)
	}

	// 2. Parse API specification
	spec, err := parseAPISpec(config.API)
	if err != nil {
		return fmt.Errorf("failed to parse API spec: %w", err)
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

	// 6a. Wrap HTTP client with rate limiting
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

	// 7. Create reporter based on output format
	rep, err := createReporter(config.Output, config.OutputFile, config.RequestIDsLimit)
	if err != nil {
		return fmt.Errorf("failed to create reporter: %w", err)
	}
	defer func() { _ = rep.Close() }()

	// 7a. Set LLM mode on terminal reporter if LLM is enabled
	llmEnabled := hasLLMConfig() || config.LLMHost != ""
	if terminalReporter, ok := rep.(*TerminalReporter); ok && llmEnabled {
		terminalReporter.SetLLMMode(true)
		log.Debug("LLM mode enabled on terminal reporter")
	}

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

	fmt.Printf("[INFO] Loaded %d templates\n", len(tmplFiles))
	fmt.Printf("[INFO] Testing %d operations against %d roles\n", len(spec.Operations), len(rolesCfg.Roles))

	// Dry-run: print what would be tested and exit before any HTTP execution
	if config.DryRun {
		testCount := 0
		opCount := 0
		for _, op := range spec.Operations {
			opMatched := false
			for _, tmpl := range tmplFiles {
				if !templateApplies(tmpl, op) {
					continue
				}
				fmt.Printf("[DRY-RUN] Would test %s %s with %s\n", op.Method, op.Path, tmpl.ID)
				testCount++
				opMatched = true
			}
			if opMatched {
				opCount++
			}
		}
		fmt.Printf("[DRY-RUN] Total: %d tests across %d operations and %d templates\n", testCount, opCount, len(tmplFiles))
		fmt.Println("[DRY-RUN] Dry run complete - no requests were sent")
		return nil
	}

	// 9. Create template executor with rate-limiting client
	executor := templates.NewExecutor(rateLimitingClient, customHeaders)

	// 10. Create mutation executor for mutation templates with rate-limiting client
	mutationExecutor := orchestrator.NewMutationExecutor(rateLimitingClient, customHeaders)

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

			// Real-time reporting (skip if LLM triage will run - show in final report instead)
			llmEnabled := hasLLMConfig() || config.LLMHost != ""
			if !llmEnabled {
				for _, f := range findings {
					rep.ReportFinding(f)
				}
			}

			allFindings = append(allFindings, findings...)
		}
	}

	// 12. Optional LLM triage
	if hasLLMConfig() || config.LLMHost != "" {
		allFindings, _ = triageWithLLM(ctx, allFindings, rolesCfg, config.LLMHost, config.LLMModel, config.LLMTimeout, config.LLMContext, rep)
	}

	// 13. Generate final report
	log.Debug("Generating final report with %d findings", len(allFindings))
	stats := calculateStats(allFindings, startTime)
	stats.OperationCount = len(spec.Operations)
	stats.RoleCount = len(rolesCfg.Roles)
	stats.TemplatesLoaded = len(tmplFiles)

	return rep.GenerateReport(allFindings, stats)
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

	// Default to ./templates/rest/ relative to current directory
	return "./templates/rest"
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

// filterByTemplates filters templates by ID, filename, or path suffix.
// Matching is case-insensitive. Supports:
//   - Template ID (e.g., "bola-idor-basic")
//   - Filename with or without extension (e.g., "bola-idor-basic.yaml" or "bola-idor-basic")
//   - Path suffix (e.g., "templates/rest/bola-idor-basic.yaml")
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

// =============================================================================
// TEMPLATE MATCHING
// =============================================================================

// templateMatchesAnyFilter checks if template matches any of the filters
func templateMatchesAnyFilter(tmpl *templates.CompiledTemplate, filters []string) bool {
	for _, filter := range filters {
		if templateMatchesFilter(tmpl, filter) {
			return true
		}
	}
	return false
}

// templateMatchesFilter checks if template matches a single filter
// Matches by: template ID (exact, case-insensitive), filename with/without extension, path suffix
func templateMatchesFilter(tmpl *templates.CompiledTemplate, filter string) bool {
	// 1. Match by template ID (case-insensitive)
	if strings.EqualFold(tmpl.ID, filter) {
		return true
	}

	// 2. Match by filename (with or without .yaml/.yml extension)
	filename := filepath.Base(tmpl.FilePath)
	filenameNoExt := strings.TrimSuffix(strings.TrimSuffix(filename, ".yaml"), ".yml")
	if strings.EqualFold(filename, filter) || strings.EqualFold(filenameNoExt, filter) {
		return true
	}

	// 3. Match by path suffix
	if strings.HasSuffix(tmpl.FilePath, filter) {
		return true
	}

	return false
}
