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
	"github.com/praetorian-inc/hadrian/pkg/orchestrator"
	"github.com/praetorian-inc/hadrian/pkg/plugins/grpc"
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

// Validate checks the gRPC configuration for common errors before test execution.
// This mirrors the validation pattern used by REST and GraphQL runners.
func (c *GRPCConfig) Validate() error {
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

// runGRPCTest executes gRPC security tests
func runGRPCTest(ctx context.Context, config GRPCConfig) error {
	startTime := time.Now()

	// Enable verbose logging if requested
	log.SetVerbose(config.Verbose)

	// Validate configuration early
	if err := config.Validate(); err != nil {
		return err
	}

	// Parse custom headers
	customHeaders, err := ParseCustomHeaders(config.Headers)
	if err != nil {
		return fmt.Errorf("invalid custom header: %w", err)
	}

	// Header output (no [DEBUG] prefix)
	fmt.Println("Starting gRPC security test")
	fmt.Printf("Target: %s\n", config.Target)

	// Log proto file if provided
	if config.Proto != "" {
		fmt.Printf("Proto file: %s\n", config.Proto)
	}
	if config.Reflection {
		grpcVerboseLog(config.Verbose, "Using server reflection")
	}

	// Verbose-only configuration details
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

	// 1. Parse proto file (if provided)
	var operations []*model.Operation
	var methodDescriptors map[string]protoreflect.MethodDescriptor
	if config.Proto != "" {
		data, err := os.ReadFile(config.Proto)
		if err != nil {
			return fmt.Errorf("failed to read proto file: %w", err)
		}

		plugin := &grpc.GRPCPlugin{}
		spec, descriptors, err := plugin.ParseWithDescriptors(data)
		if err != nil {
			return fmt.Errorf("failed to parse proto file: %w", err)
		}

		operations = spec.Operations
		methodDescriptors = descriptors

		// Output proto load success
		serviceCount := countServices(operations)
		fmt.Println("Proto loaded successfully")
		fmt.Printf("  Services: %d\n", serviceCount)
		fmt.Printf("  Methods: %d\n", len(operations))
	} else {
		// Server reflection will be implemented in future batches
		return fmt.Errorf("server reflection not yet implemented, use --proto flag")
	}

	// 2. Load auth and roles configuration (if provided)
	var authCfg *auth.AuthConfig
	var rolesCfg *roles.RoleConfig

	if config.Auth != "" {
		var err error
		authCfg, err = auth.Load(config.Auth)
		if err != nil {
			return fmt.Errorf("failed to load auth config: %w", err)
		}
		grpcVerboseLog(config.Verbose, "Loaded auth config from: %s", config.Auth)
	}

	if config.Roles != "" {
		var err error
		rolesCfg, err = roles.Load(config.Roles)
		if err != nil {
			return fmt.Errorf("failed to load roles config: %w", err)
		}
		grpcVerboseLog(config.Verbose, "Loaded roles config from: %s", config.Roles)
	}

	// 3. Load templates from template directory
	templateDir := config.TemplateDir
	if templateDir == "" {
		templateDir = "./templates/grpc"
	}

	var templateFiles []*templates.CompiledTemplate
	if _, err := os.Stat(templateDir); err == nil {
		// Directory exists, load templates
		tmpls, err := loadGRPCTemplates(templateDir)
		if err != nil {
			grpcVerboseLog(config.Verbose, "No templates loaded from %s: %v", templateDir, err)
		} else {
			templateFiles = tmpls
			grpcVerboseLog(config.Verbose, "Loaded %d templates from %s", len(templateFiles), templateDir)
		}
	} else {
		grpcVerboseLog(config.Verbose, "Template directory not found: %s", templateDir)
	}

	// 4. Create gRPC executor (skip if dry-run)
	var executor *templates.GRPCExecutor
	var mutationExecutor *orchestrator.GRPCMutationExecutor
	if !config.DryRun {
		var err error
		executor, err = templates.NewGRPCExecutor(templates.GRPCExecutorConfig{
			Target:    config.Target,
			Plaintext: config.Plaintext,
			Insecure:  config.Insecure,
			Timeout:   time.Duration(config.Timeout) * time.Second,
			TLSCACert: config.TLSCACert,
			RateLimit: config.RateLimit,
		})
		if err != nil {
			return fmt.Errorf("failed to create gRPC executor: %w", err)
		}
		defer func() { _ = executor.Close() }()
		executor.SetCustomHeaders(customHeaders)
		grpcVerboseLog(config.Verbose, "Created gRPC executor connection to %s", config.Target)

		// Validate connection before running tests
		if err := executor.CheckConnection(ctx); err != nil {
			return err
		}

		// Create mutation executor for three-phase tests with adapter
		adapter := &grpcExecutorAdapter{executor: executor}
		mutationExecutor = orchestrator.NewGRPCMutationExecutor(adapter)
	}

	// Create reporter based on output format
	rep, err := createReporter(config.Output, config.OutputFile, 0)
	if err != nil {
		return fmt.Errorf("failed to create reporter: %w", err)
	}
	defer func() { _ = rep.Close() }()

	// 5. Section header for template execution
	if len(templateFiles) > 0 {
		fmt.Println("")
		fmt.Println("=== Running gRPC Templates ===")
		fmt.Printf("Loaded %d template(s) from: %s\n", len(templateFiles), templateDir)
	}

	// 6. Execute test loop
	if config.Verbose {
		if config.DryRun {
			grpcVerboseLog(config.Verbose, "Test execution (dry-run - no actual gRPC calls):")
		} else {
			grpcVerboseLog(config.Verbose, "Test execution:")
		}
	}

	testCount := 0
	var allFindings []*model.Finding

	for _, op := range operations {
		if len(templateFiles) == 0 {
			// No templates, just log operation
			grpcVerboseLog(config.Verbose, "  Operation: %s", op.Path)
			testCount++
		} else {
			// Get method descriptor for this operation
			methodDesc := methodDescriptors[op.Path]
			if methodDesc == nil {
				grpcVerboseLog(config.Verbose, "  Skipping %s: no method descriptor found", op.Path)
				continue
			}

			// For each template
			for _, tmpl := range templateFiles {
				// Check if operation matches template's endpoint_selector
				if !matchesEndpointSelector(op, tmpl) {
					continue
				}

				if config.DryRun {
					grpcDryRunLog(config.DryRun, "Would test %s with %s", op.Path, tmpl.ID)
					testCount++
					continue
				}

				// Build variables for substitution and get role names
				variables, attackerRoleName, victimRoleName := buildTemplateVariablesWithRoles(op, methodDesc, authCfg, rolesCfg)

				// Verbose: log test execution start
				if config.Verbose {
					log.Debug("Testing %s with %s...", op.Path, tmpl.ID)
				}

				// Check if this is a mutation template requiring three-phase testing
				if tmpl.Template != nil && tmpl.Template.Info.TestPattern == "mutation" {
					// Clear tracker to prevent cross-test pollution of stored resource IDs
					mutationExecutor.ClearTracker()
					// Execute three-phase mutation test
					authInfoMap := buildAuthInfoMap(authCfg, rolesCfg)
					mutationResult, err := mutationExecutor.ExecuteGRPCMutation(ctx, tmpl.Template, methodDesc, authInfoMap)
					testCount++

					if err != nil {
						if config.Verbose {
							log.Warn("gRPC mutation test failed [template=%s, method=%s]: %v", tmpl.ID, op.Path, err)
						}
						continue
					}

					if mutationResult.Matched {
						finding := buildGRPCFinding(tmpl, op, attackerRoleName, victimRoleName)

						// Attach evidence from mutation phases
						finding.Evidence = model.Evidence{
							SetupResponse:  mutationResult.SetupResponse,
							AttackResponse: mutationResult.AttackResponse,
							VerifyResponse: mutationResult.VerifyResponse,
							ResourceID:     mutationResult.ResourceID,
						}
						if mutationResult.AttackResponse != nil {
							finding.Evidence.Response = *mutationResult.AttackResponse
						}

						// Collect request IDs from all phases
						if mutationResult.RequestIDs != nil {
							finding.RequestIDs = append(finding.RequestIDs, mutationResult.RequestIDs.Setup...)
							finding.RequestIDs = append(finding.RequestIDs, mutationResult.RequestIDs.Attack...)
							finding.RequestIDs = append(finding.RequestIDs, mutationResult.RequestIDs.Verify...)
						}

						allFindings = append(allFindings, finding)
						rep.ReportFinding(finding)
					} else if config.Verbose {
						fmt.Printf("  [PASS] %s (mutation test)\n", tmpl.ID)
					}
					continue
				}

				// Execute the test
				result, err := executor.ExecuteGRPC(ctx, tmpl, op, methodDesc, nil, variables)
				testCount++

				if err != nil {
					// Use WARN for template execution failures (matches GraphQL pattern)
					if config.Verbose {
						log.Warn("gRPC template execution failed [template=%s, method=%s]: %v", tmpl.ID, op.Path, err)
					}
					continue
				}

				if result.Matched {
					finding := buildGRPCFinding(tmpl, op, attackerRoleName, victimRoleName)
					finding.Evidence = model.Evidence{
						Response: result.Response,
					}
					finding.RequestIDs = result.RequestIDs

					allFindings = append(allFindings, finding)
					rep.ReportFinding(finding)
				} else if config.Verbose {
					fmt.Printf("  [PASS] %s (status: %d)\n", tmpl.ID, result.Response.StatusCode)
				}
			}
		}
	}

	// 7. Calculate stats and generate report
	elapsed := time.Since(startTime)
	grpcVerboseLog(config.Verbose, "Test completed in %v", elapsed)

	rolesCount := 0
	if rolesCfg != nil {
		rolesCount = len(rolesCfg.Roles)
	}

	stats := calculateStats(allFindings, startTime)
	stats.TotalTests = testCount
	stats.OperationCount = len(operations)
	stats.RoleCount = rolesCount
	stats.TemplatesLoaded = len(templateFiles)

	if err := rep.GenerateReport(allFindings, stats); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	if config.DryRun {
		fmt.Println("")
		fmt.Println("[NOTE] Dry-run mode - no actual tests were executed")
	} else if len(methodDescriptors) == 0 {
		fmt.Println("")
		fmt.Println("[NOTE] No method descriptors extracted. Ensure proto file defines services with methods.")
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
