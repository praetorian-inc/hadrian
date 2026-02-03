// pkg/runner/graphql.go
package runner

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/auth"
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
	Target        string
	Endpoint      string // GraphQL endpoint path (default: /graphql)
	Roles         string
	Auth          string
	Proxy         string
	CACert        string
	Insecure      bool
	RateLimit     float64
	Timeout       int
	AllowInternal bool
	Output        string
	OutputFile    string
	Verbose       bool
	DryRun        bool

	// GraphQL-specific
	Schema          string // SDL file path (optional, uses introspection if not provided)
	DepthLimit      int    // Max query depth for DoS testing
	ComplexityLimit int    // Max complexity score for DoS testing
	BatchSize       int    // Number of queries in batch attack tests
	Templates       string // GraphQL templates directory path
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
	cmd.MarkFlagRequired("target")

	// Schema source
	cmd.Flags().StringVar(&config.Schema, "schema", "", "GraphQL SDL schema file (uses introspection if not provided)")
	cmd.Flags().StringVar(&config.Endpoint, "endpoint", "/graphql", "GraphQL endpoint path")

	// Role configuration
	cmd.Flags().StringVar(&config.Roles, "roles", "", "Roles and permissions YAML file")
	cmd.Flags().StringVar(&config.Auth, "auth", "", "Authentication configuration YAML file")

	// Template configuration
	cmd.Flags().StringVar(&config.Templates, "templates", "", "GraphQL templates directory (e.g., templates/graphql)")

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
	cmd.Flags().BoolVar(&config.AllowInternal, "allow-internal", false, "Allow internal IP addresses")

	// Output options
	cmd.Flags().StringVar(&config.Output, "output", "terminal", "Output format: terminal, json, markdown")
	cmd.Flags().StringVar(&config.OutputFile, "output-file", "", "Output file path")
	cmd.Flags().BoolVar(&config.Verbose, "verbose", false, "Verbose output")
	cmd.Flags().BoolVar(&config.DryRun, "dry-run", false, "Dry run (don't execute tests)")

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
		filePath := dir + "/" + name
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
	fmt.Println("Starting GraphQL security test")
	fmt.Printf("Target: %s%s\n", config.Target, config.Endpoint)

	// Load configs
	authConfig, rolesConfig, err := loadConfigs(config.Auth, config.Roles)
	if err != nil {
		return err
	}

	// Create HTTP client
	httpClient := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
	}

	// Get schema
	schema, err := fetchSchema(ctx, config, httpClient)
	if err != nil {
		return err
	}

	reportSchemaInfo(schema)

	if config.DryRun {
		fmt.Println("Dry run - skipping test execution")
		return nil
	}

	// Build auth configs for scanner
	authConfigs, err := buildAuthConfigs(authConfig)
	if err != nil {
		return err
	}

	reportAuthConfigsLoaded(config.Auth, config.Roles, authConfig, rolesConfig, authConfigs)

	// Run security checks
	endpoint := config.Target + config.Endpoint
	findings := runSecurityChecks(ctx, schema, httpClient, endpoint, config, authConfigs)

	// Report findings
	reportFindings(findings)

	// Suppress unused variable warnings (roles will be used for authorization testing in future phases)
	_ = rolesConfig

	return nil
}
