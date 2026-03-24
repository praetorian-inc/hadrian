// pkg/runner/grpc.go
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
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/praetorian-inc/hadrian/pkg/templates"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// GRPCConfig holds gRPC-specific test configuration
type GRPCConfig struct {
	// Common config (shared with REST/GraphQL)
	Target     string
	Roles      string
	Auth       string
	Proxy      string
	Insecure   bool
	RateLimit  float64
	Timeout    int
	Output     string
	OutputFile string
	Verbose    bool
	DryRun     bool

	// gRPC-specific flags
	Proto       string   // Proto file path
	Reflection  bool     // Use server reflection
	Plaintext   bool     // Use plaintext (no TLS)
	TLSCACert   string   // Custom CA certificate
	TemplateDir string   // gRPC templates directory
	Templates   []string // Filter templates by ID or name
	Headers     []string // Custom HTTP headers (format: "Key: Value")
}

// setDefaults fills zero-valued fields with sensible defaults for library usage.
// When hadrian is invoked via CLI, cobra flags provide these defaults; for
// direct library callers the fields may be unset.
func (c *GRPCConfig) setDefaults() {
	if c.Output == "" {
		c.Output = "json"
	}
	if c.RateLimit <= 0 {
		c.RateLimit = 5.0
	}
	if c.Timeout <= 0 {
		c.Timeout = 30
	}
	if c.TemplateDir == "" {
		c.TemplateDir = "./templates/grpc"
	}
}

// Validate checks the gRPC configuration for common errors before test execution.
// This mirrors the validation pattern used by REST and GraphQL runners.
func (c *GRPCConfig) Validate() error {
	c.setDefaults()

	if c.Target == "" {
		return fmt.Errorf("--target is required")
	}
	if c.Proto == "" && !c.Reflection {
		return fmt.Errorf("either --proto or --reflection must be provided")
	}
	if c.Plaintext && c.TLSCACert != "" {
		return fmt.Errorf("--plaintext and --tls-ca-cert are mutually exclusive")
	}
	if c.Insecure && c.TLSCACert != "" {
		return fmt.Errorf("--insecure and --tls-ca-cert are mutually exclusive")
	}
	if c.TLSCACert != "" {
		if _, err := os.Stat(c.TLSCACert); err != nil {
			return fmt.Errorf("TLS CA certificate file not found: %s", c.TLSCACert)
		}
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("--timeout must be positive (got %d)", c.Timeout)
	}
	if c.RateLimit <= 0 {
		return fmt.Errorf("--rate-limit must be positive (got %f)", c.RateLimit)
	}

	// Validate custom headers format
	if len(c.Headers) > 0 {
		if _, err := ParseCustomHeaders(c.Headers); err != nil {
			return err
		}
	}

	return nil
}

// newTestGRPCCmd creates the "test grpc" subcommand
func newTestGRPCCmd() *cobra.Command {
	var config GRPCConfig

	cmd := &cobra.Command{
		Use:   "grpc",
		Short: "Run security tests against a gRPC API",
		Long:  `Run security tests against a gRPC API using proto files or server reflection.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGRPCTest(cmd.Context(), config)
		},
	}

	// Required flags
	cmd.Flags().StringVar(&config.Target, "target", "", "Target gRPC server address (e.g., localhost:50051)")
	_ = cmd.MarkFlagRequired("target")

	// Schema source (proto file OR reflection)
	cmd.Flags().StringVar(&config.Proto, "proto", "", "Proto file path (uses reflection if not provided)")
	cmd.Flags().BoolVar(&config.Reflection, "reflection", false, "Use server reflection to discover service definition")

	// Role and authentication configuration
	cmd.Flags().StringVar(&config.Roles, "roles", "", "Roles and permissions YAML file")
	cmd.Flags().StringVar(&config.Auth, "auth", "", "Authentication configuration YAML file")

	// Template configuration
	cmd.Flags().StringVar(&config.TemplateDir, "template-dir", "", "gRPC templates directory (e.g., templates/grpc)")
	cmd.Flags().StringSliceVar(&config.Templates, "template", []string{}, "Filter templates by ID or name (can specify multiple)")

	// TLS options
	cmd.Flags().BoolVar(&config.Plaintext, "plaintext", false, "Use plaintext connection (no TLS)")
	cmd.Flags().StringVar(&config.TLSCACert, "tls-ca-cert", "", "Custom CA certificate for TLS")

	// Network options
	cmd.Flags().StringVar(&config.Proxy, "proxy", "", "HTTP/HTTPS proxy URL")
	cmd.Flags().BoolVar(&config.Insecure, "insecure", false, "Skip TLS verification")
	cmd.Flags().Float64Var(&config.RateLimit, "rate-limit", 5.0, "Rate limit (req/s)")
	cmd.Flags().IntVar(&config.Timeout, "timeout", 30, "Request timeout in seconds")

	// Output options
	cmd.Flags().StringVar(&config.Output, "output", "terminal", "Output format: terminal, json, markdown")
	cmd.Flags().StringVar(&config.OutputFile, "output-file", "", "Output file path")
	cmd.Flags().BoolVar(&config.Verbose, "verbose", false, "Verbose output")
	cmd.Flags().BoolVar(&config.DryRun, "dry-run", false, "Dry run (don't execute tests)")

	// Custom headers
	cmd.Flags().StringArrayVarP(&config.Headers, "header", "H", []string{}, "Custom HTTP header (format: 'Key: Value', can specify multiple)")

	return cmd
}

// countServices counts unique services from operations
func countServices(operations []*model.Operation) int {
	services := make(map[string]bool)
	for _, op := range operations {
		// Extract service from path like "/example.GreeterService/SayHello"
		parts := strings.Split(op.Path, "/")
		if len(parts) >= 2 {
			services[parts[1]] = true
		}
	}
	return len(services)
}

// runGRPCTest executes gRPC security tests (CLI entry point)
func runGRPCTest(ctx context.Context, config GRPCConfig) error {
	startTime := time.Now()

	log.SetVerbose(config.Verbose)

	if err := config.Validate(); err != nil {
		return err
	}

	// Header output
	fmt.Println("Starting gRPC security test")
	fmt.Printf("Target: %s\n", config.Target)

	if config.Proto != "" {
		fmt.Printf("Proto file: %s\n", config.Proto)
	}
	if config.Reflection {
		grpcVerboseLog(config.Verbose, "Using server reflection")
	}

	if config.Verbose {
		if config.Plaintext {
			grpcVerboseLog(config.Verbose, "Using plaintext connection (no TLS)")
		}
		if config.TLSCACert != "" {
			grpcVerboseLog(config.Verbose, "Custom CA certificate: %s", config.TLSCACert)
		}
	}

	// Dry run mode
	if config.DryRun {
		grpcDryRunLog(config.DryRun, "Dry run - skipping test execution")
		grpcDryRunLog(config.DryRun, "Would connect to: %s", config.Target)
		return nil
	}

	// Delegate core test execution to library function
	allFindings, err := RunGRPCTest(ctx, config)
	if err != nil {
		return err
	}

	// Create reporter and output results
	rep, err := createReporter(config.Output, config.OutputFile, 0)
	if err != nil {
		return fmt.Errorf("failed to create reporter: %w", err)
	}
	defer func() { _ = rep.Close() }()

	for _, f := range allFindings {
		rep.ReportFinding(f)
	}

	// Load roles count for stats
	rolesCount := 0
	if config.Roles != "" {
		if rolesCfg, err := roles.Load(config.Roles); err == nil {
			rolesCount = len(rolesCfg.Roles)
		}
	}

	stats := calculateStats(allFindings, startTime)
	stats.OperationCount = 0 // not tracked in delegated path
	stats.RoleCount = rolesCount

	if err := rep.GenerateReport(allFindings, stats); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	return nil
}

// buildGRPCFinding constructs a model.Finding from a matched template and operation
func buildGRPCFinding(tmpl *templates.CompiledTemplate, op *model.Operation, attackerRole, victimRole string) *model.Finding {
	severity := model.Severity("MEDIUM")
	if tmpl.Info.Severity != "" {
		severity = model.Severity(tmpl.Info.Severity)
	}

	category := tmpl.ID
	if tmpl.Info.Category != "" {
		category = tmpl.Info.Category
	}

	return &model.Finding{
		ID:              tmpl.ID,
		Category:        category,
		Name:            tmpl.ID,
		Severity:        severity,
		IsVulnerability: true,
		Endpoint:        op.Path,
		Method:          op.Method,
		AttackerRole:    attackerRole,
		VictimRole:      victimRole,
		Timestamp:       time.Now(),
	}
}

// buildTemplateVariablesWithRoles constructs the variable map for template substitution
// and returns the attacker and victim role names
func buildTemplateVariablesWithRoles(op *model.Operation, methodDesc protoreflect.MethodDescriptor, authCfg *auth.AuthConfig, rolesCfg *roles.RoleConfig) (map[string]string, string, string) {
	variables := map[string]string{
		// Operation context
		"operation.path":    op.Path,
		"operation.method":  string(methodDesc.Name()),
		"operation.service": string(methodDesc.Parent().Name()),
		"service.name":      string(methodDesc.Parent().Name()),
	}

	// Determine owner field with fallback
	ownerField := op.OwnerField
	if ownerField == "" && len(op.PathParams) > 0 {
		ownerField = op.PathParams[0].Name
	}
	if ownerField == "" {
		// Use first field from input type as fallback
		fields := methodDesc.Input().Fields()
		if fields.Len() > 0 {
			ownerField = string(fields.Get(0).Name())
		}
	}
	if ownerField == "" {
		ownerField = "id" // Final generic fallback
	}
	variables["operation.owner_field"] = ownerField

	// Default role names
	attackerRoleName := "user1"
	victimRoleName := "user2"

	// Populate auth variables from loaded configs
	// For BOLA tests: attacker = user1 (lower privilege), victim = user2 or admin (higher privilege)
	if authCfg != nil && rolesCfg != nil {
		// Get attacker role (lower privilege - typically user1)
		var attackerRole *roles.Role
		var victimRole *roles.Role

		// Find roles by name (user1 as attacker, user2 or admin as victim)
		for _, role := range rolesCfg.Roles {
			if role.Name == "user1" {
				attackerRole = role
			} else if role.Name == "user2" {
				victimRole = role
			}
		}

		// Fallback: use permission levels if specific names not found
		if attackerRole == nil {
			lowerRoles := rolesCfg.GetRolesByPermissionLevel("lower")
			if len(lowerRoles) > 0 {
				attackerRole = lowerRoles[0]
			}
		}

		if victimRole == nil {
			higherRoles := rolesCfg.GetRolesByPermissionLevel("higher")
			if len(higherRoles) > 0 {
				victimRole = higherRoles[0]
			} else if len(rolesCfg.Roles) > 1 {
				// Use second role as fallback
				victimRole = rolesCfg.Roles[1]
			}
		}

		// Get attacker token and name
		if attackerRole != nil {
			attackerRoleName = attackerRole.Name
			roleAuth, ok := authCfg.Roles[attackerRole.Name]
			if ok && roleAuth.Token != "" {
				variables["attacker_token"] = roleAuth.Token
			}
		}

		// Get victim ID and name
		if victimRole != nil {
			victimRoleName = victimRole.Name
			if victimRole.ID != "" {
				variables["victim_id"] = victimRole.ID
			}
		}
	}

	// Fallback to placeholders if configs not provided
	if _, exists := variables["victim_id"]; !exists {
		variables["victim_id"] = "test-victim-id"
	}
	if _, exists := variables["attacker_token"]; !exists {
		variables["attacker_token"] = "test-attacker-token"
	}

	return variables, attackerRoleName, victimRoleName
}

// matchesEndpointSelector checks if an operation matches the template's endpoint_selector criteria
func matchesEndpointSelector(op *model.Operation, tmpl *templates.CompiledTemplate) bool {
	selector := tmpl.EndpointSelector

	// Check service filter (exact match against service portion of path)
	if selector.Service != "" {
		// Extract service from path: "/package.Service/Method" -> "package.Service"
		parts := strings.Split(strings.TrimPrefix(op.Path, "/"), "/")
		if len(parts) >= 2 {
			serviceName := parts[0]
			if serviceName != selector.Service {
				return false
			}
		}
	}

	// Check method filter (exact match against method name)
	if selector.Method != "" {
		parts := strings.Split(op.Path, "/")
		methodName := parts[len(parts)-1]
		if methodName != selector.Method {
			return false
		}
	}

	// If no methods glob specified, match (already passed service/method filters above)
	if len(selector.Methods) == 0 {
		return true
	}

	// For gRPC, extract method name from path
	var methodName string
	parts := strings.Split(op.Path, "/")
	if len(parts) > 0 {
		methodName = parts[len(parts)-1]
	}
	if methodName == "" {
		methodName = op.Method
	}

	// Check if method matches any of the selector patterns
	for _, pattern := range selector.Methods {
		if matchMethodPattern(methodName, pattern) {
			return true
		}
	}

	return false
}

// matchMethodPattern checks if a method name matches a pattern (supports wildcards)
// Pattern examples: "Delete*", "*User", "GetProfile", "Remove*"
func matchMethodPattern(methodName, pattern string) bool {
	// Handle wildcard at end (e.g., "Delete*")
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(methodName, prefix)
	}

	// Handle wildcard at start (e.g., "*User")
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(methodName, suffix)
	}

	// Exact match
	return methodName == pattern
}

// loadGRPCTemplates loads templates from the gRPC template directory
func loadGRPCTemplates(dir string) ([]*templates.CompiledTemplate, error) {
	var result []*templates.CompiledTemplate

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

		// Parse and compile template
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

		return nil
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

// buildAuthInfoMap creates a map of role name to AuthInfo from auth and roles configs
func buildAuthInfoMap(authCfg *auth.AuthConfig, rolesCfg *roles.RoleConfig) map[string]*auth.AuthInfo {
	if authCfg == nil || rolesCfg == nil {
		return map[string]*auth.AuthInfo{}
	}

	authInfos := make(map[string]*auth.AuthInfo)
	for _, role := range rolesCfg.Roles {
		if info, err := authCfg.GetAuthInfo(role.Name); err == nil {
			authInfos[role.Name] = info
		}
	}
	return authInfos
}
