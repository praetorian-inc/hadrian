// pkg/runner/graphql.go
package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/auth"
	"github.com/praetorian-inc/hadrian/pkg/log"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/praetorian-inc/hadrian/pkg/templates"
	"github.com/spf13/cobra"
)

// AuthConfig wraps pkg/auth.AuthConfig for compatibility
type AuthConfig = auth.AuthConfig

// RolesConfig wraps pkg/roles.RoleConfig for compatibility
type RolesConfig = roles.RoleConfig

// LoadAuthConfig loads authentication configuration
func LoadAuthConfig(path string) (*AuthConfig, error) {
	return auth.Load(path)
}

// LoadRolesConfig loads roles configuration
func LoadRolesConfig(path string) (*RolesConfig, error) {
	return roles.Load(path)
}

// GraphQLConfig holds GraphQL-specific test configuration
type GraphQLConfig struct {
	// Common config (shared with REST)
	Target          string
	Endpoint        string // GraphQL endpoint path (default: /graphql)
	Roles           string
	Auth            string
	Proxy           string
	CACert          string
	Insecure        bool
	RateLimit       float64
	Timeout         int
	Output          string
	OutputFile      string
	RequestIDsLimit int // Limit request IDs in output (default 1)
	Verbose         bool
	DryRun          bool

	// Rate limiting config (shared with REST)
	RateLimitBackoff     string        // "exponential" or "fixed" (default: "exponential")
	RateLimitMaxRetries  int           // Max retry attempts (default: 5)
	RateLimitMaxWait     time.Duration // Max backoff wait time (default: 1m)
	RateLimitStatusCodes []int         // Status codes that trigger rate limiting (default: [429, 503])

	// GraphQL-specific
	Schema            string   // SDL file path (optional, uses introspection if not provided)
	DepthLimit        int      // Max query depth for DoS testing
	ComplexityLimit   int      // Max complexity score for DoS testing
	BatchSize         int      // Number of queries in batch attack tests
	TemplateDir       string   // GraphQL templates directory path
	Templates         []string // Filter templates by ID
	SkipBuiltinChecks bool     // Skip built-in security checks (introspection, depth limit, batching)

	// LLM triage (optional)
	LLMHost    string   // LLM service host
	LLMModel   string   // LLM model name
	LLMTimeout int      // LLM request timeout (seconds)
	LLMContext string   // Additional context for LLM
	Headers    []string // Custom HTTP headers (format: "Key: Value")
}

// newTestGraphQLCmd creates the "test graphql" subcommand
func newTestGraphQLCmd() *cobra.Command {
	var config GraphQLConfig

	cmd := &cobra.Command{
		Use:   "graphql",
		Short: "Run security tests against a GraphQL API",
		Long:  `Run security tests against a GraphQL API using introspection or SDL schema.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGraphQLTest(cmd.Context(), config)
		},
	}

	// Required flags
	cmd.Flags().StringVar(&config.Target, "target", "", "Target base URL (e.g., https://api.example.com)")
	_ = cmd.MarkFlagRequired("target")

	// Schema source
	cmd.Flags().StringVar(&config.Schema, "schema", "", "GraphQL SDL schema file (uses introspection if not provided)")
	cmd.Flags().StringVar(&config.Endpoint, "endpoint", "/graphql", "GraphQL endpoint path")

	// Role configuration
	cmd.Flags().StringVar(&config.Roles, "roles", "", "Roles and permissions YAML file")
	cmd.Flags().StringVar(&config.Auth, "auth", "", "Authentication configuration YAML file")

	// Template configuration
	cmd.Flags().StringVar(&config.TemplateDir, "template-dir", "", "GraphQL templates directory (default: $HADRIAN_TEMPLATES or ./templates/graphql)")
	cmd.Flags().BoolVar(&config.SkipBuiltinChecks, "skip-builtin-checks", false, "Skip built-in security checks (introspection, depth limit, batching)")

	// Security limits
	cmd.Flags().IntVar(&config.DepthLimit, "depth-limit", 10, "Maximum query depth for DoS testing")
	cmd.Flags().IntVar(&config.ComplexityLimit, "complexity-limit", 1000, "Maximum complexity score for DoS testing")
	cmd.Flags().IntVar(&config.BatchSize, "batch-size", 100, "Number of queries in batch attack tests")

	// Network options
	cmd.Flags().StringVar(&config.Proxy, "proxy", "", "HTTP/HTTPS proxy URL")
	cmd.Flags().StringVar(&config.CACert, "ca-cert", "", "CA certificate for proxy")
	cmd.Flags().BoolVar(&config.Insecure, "insecure", false, "Skip TLS verification")
	cmd.Flags().Float64Var(&config.RateLimit, "rate-limit", 5.0, "Rate limit (req/s)")
	cmd.Flags().IntVar(&config.Timeout, "timeout", 30, "Request timeout in seconds")

	// Output options
	cmd.Flags().StringVar(&config.Output, "output", "terminal", "Output format: terminal, json, markdown")
	cmd.Flags().StringVar(&config.OutputFile, "output-file", "", "Output file path")
	cmd.Flags().IntVar(&config.RequestIDsLimit, "request-ids-limit", 1, "Limit request IDs in output (0 = show all)")
	cmd.Flags().BoolVar(&config.Verbose, "verbose", false, "Verbose output")
	cmd.Flags().BoolVar(&config.DryRun, "dry-run", false, "Dry run (don't execute tests)")

	// Template filtering
	cmd.Flags().StringSliceVar(&config.Templates, "template", []string{}, "Filter templates by ID (can specify multiple)")

	// Rate limiting (advanced)
	cmd.Flags().StringVar(&config.RateLimitBackoff, "rate-limit-backoff", "exponential", "Rate limit backoff strategy: exponential, fixed")
	cmd.Flags().IntVar(&config.RateLimitMaxRetries, "rate-limit-max-retries", 5, "Maximum retry attempts on rate limit")
	cmd.Flags().DurationVar(&config.RateLimitMaxWait, "rate-limit-max-wait", 1*time.Minute, "Maximum backoff wait time")
	cmd.Flags().IntSliceVar(&config.RateLimitStatusCodes, "rate-limit-status-codes", []int{429, 503}, "HTTP status codes that trigger rate limiting")

	// LLM triage (optional)
	cmd.Flags().StringVar(&config.LLMHost, "llm-host", "", "LLM service host for finding triage")
	cmd.Flags().StringVar(&config.LLMModel, "llm-model", "", "LLM model name for triage")
	cmd.Flags().IntVar(&config.LLMTimeout, "llm-timeout", 30, "LLM request timeout (seconds)")
	cmd.Flags().StringVar(&config.LLMContext, "llm-context", "", "Additional context for LLM triage")

	// Custom headers
	cmd.Flags().StringArrayVarP(&config.Headers, "header", "H", []string{}, "Custom HTTP header (format: 'Key: Value', can specify multiple)")

	return cmd
}

// loadGraphQLTemplates loads GraphQL templates from the specified directory
func loadGraphQLTemplates(dir string) ([]*templates.Template, error) {
	if dir == "" {
		return nil, fmt.Errorf("templates directory not specified")
	}

	// Read YAML files from directory
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read templates directory: %w", err)
	}

	var tmplList []*templates.Template
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		// Only load .yaml and .yml files
		name := file.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}

		// Parse template file
		filePath := filepath.Join(dir, name)
		tmpl, err := templates.Parse(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse template %s: %w", name, err)
		}

		tmplList = append(tmplList, tmpl)
	}

	return tmplList, nil
}

// runGraphQLTest executes GraphQL security tests
func runGraphQLTest(ctx context.Context, config GraphQLConfig) error {
	startTime := time.Now()

	// Enable verbose logging if requested
	log.SetVerbose(config.Verbose)

	graphqlVerboseLog(config.Verbose, "Starting GraphQL security test")
	graphqlVerboseLog(config.Verbose, "Target: %s%s", config.Target, config.Endpoint)

	// Load configs
	authConfig, rolesConfig, err := loadConfigs(config.Auth, config.Roles)
	if err != nil {
		return err
	}

	// Parse custom headers
	customHeaders, err := ParseCustomHeaders(config.Headers)
	if err != nil {
		return fmt.Errorf("invalid custom header: %w", err)
	}

	// Create HTTP client with proxy, TLS, timeout (shared infrastructure)
	httpClient, err := createGraphQLHTTPClient(config)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Wrap HTTP client with rate limiting
	rateLimitedClient := wrapWithRateLimiting(httpClient, config)

	// Get schema
	schema, err := fetchSchema(ctx, config, rateLimitedClient, customHeaders)
	if err != nil {
		return err
	}

	reportSchemaInfo(schema, config.Verbose)

	graphqlDryRunLog(config.DryRun, "Would run security checks against %d queries, %d mutations",
		len(schema.Queries), len(schema.Mutations))

	if config.DryRun {
		graphqlDryRunLog(config.DryRun, "Dry run - skipping test execution")
		return nil
	}

	// Build auth configs for scanner
	authConfigs, err := buildAuthConfigs(authConfig)
	if err != nil {
		return err
	}

	reportAuthConfigsLoaded(config.Auth, config.Roles, authConfig, rolesConfig, authConfigs, config.Verbose)

	// Create reporter based on output format (using REST reporter pattern)
	reporter, err := createReporter(config.Output, config.OutputFile, config.RequestIDsLimit)
	if err != nil {
		return fmt.Errorf("failed to create reporter: %w", err)
	}
	defer func() { _ = reporter.Close() }()

	// Run security checks with rate-limited client
	endpoint := config.Target + config.Endpoint
	modelFindings, templatesLoaded := runSecurityChecks(ctx, schema, rateLimitedClient, endpoint, config, authConfigs, reporter, customHeaders)

	// Only report findings if not already reported via callback (non-verbose mode)
	if config.Output == "terminal" && config.LLMHost == "" && !config.Verbose {
		for _, finding := range modelFindings {
			reporter.ReportFinding(finding)
		}
	}

	// LLM triage if configured
	if config.LLMHost != "" || config.LLMModel != "" {
		if rolesConfig != nil {
			graphqlVerboseLog(config.Verbose, "Running LLM triage on %d findings", len(modelFindings))
			modelFindings, err = triageWithLLM(ctx, modelFindings, rolesConfig,
				config.LLMHost, config.LLMModel, config.LLMTimeout, config.LLMContext, reporter)
			if err != nil {
				// LLM is optional - continue without it
				graphqlVerboseLog(config.Verbose, "LLM triage failed: %v", err)
			}
		} else {
			graphqlVerboseLog(config.Verbose, "Skipping LLM triage: no roles config provided")
		}
	}

	// Calculate stats using shared function
	stats := calculateStats(modelFindings, startTime)
	stats.OperationCount = len(schema.Queries) + len(schema.Mutations)
	stats.RoleCount = len(authConfigs)
	stats.TemplatesLoaded = templatesLoaded

	// Generate final report
	if err := reporter.GenerateReport(modelFindings, stats); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	return nil
}
