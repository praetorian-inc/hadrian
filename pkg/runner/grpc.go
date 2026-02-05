// pkg/runner/grpc.go
package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jhump/protoreflect/desc"
	"github.com/praetorian-inc/hadrian/pkg/auth"
	"github.com/praetorian-inc/hadrian/pkg/log"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/owasp"
	"github.com/praetorian-inc/hadrian/pkg/plugins/grpc"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/praetorian-inc/hadrian/pkg/templates"
	"github.com/spf13/cobra"
)

// GRPCConfig holds gRPC-specific test configuration
type GRPCConfig struct {
	// Common config (shared with REST/GraphQL)
	Target          string
	Roles           string
	Auth            string
	Proxy           string
	Insecure        bool
	RateLimit       float64
	Timeout         int
	AllowInternal   bool
	AllowProduction bool
	Output          string
	OutputFile      string
	Verbose         bool
	DryRun          bool

	// gRPC-specific flags
	Proto       string // Proto file path
	Reflection  bool   // Use server reflection
	Plaintext   bool   // Use plaintext (no TLS)
	TLSCACert   string // Custom CA certificate
	TemplateDir string   // gRPC templates directory
	Templates   []string // Filter templates by ID or name
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
	cmd.MarkFlagRequired("target")

	// Schema source (proto file OR reflection)
	cmd.Flags().StringVar(&config.Proto, "proto", "", "Proto file path (uses reflection if not provided)")
	cmd.Flags().BoolVar(&config.Reflection, "reflection", false, "Use server reflection to discover service definition")

	// Role and authentication configuration
	cmd.Flags().StringVar(&config.Roles, "roles", "", "Roles and permissions YAML file")
	cmd.Flags().StringVar(&config.Auth, "auth", "", "Authentication configuration YAML file")

	// Template configuration
	cmd.Flags().StringVar(&config.TemplateDir, "template-dir", "", "gRPC templates directory (e.g., templates/grpc)")
	cmd.Flags().StringSliceVar(&config.Templates, "templates", []string{}, "Filter templates by ID or name (can specify multiple)")

	// TLS options
	cmd.Flags().BoolVar(&config.Plaintext, "plaintext", false, "Use plaintext connection (no TLS)")
	cmd.Flags().StringVar(&config.TLSCACert, "tls-ca-cert", "", "Custom CA certificate for TLS")

	// Network options
	cmd.Flags().StringVar(&config.Proxy, "proxy", "", "HTTP/HTTPS proxy URL")
	cmd.Flags().BoolVar(&config.Insecure, "insecure", false, "Skip TLS verification")
	cmd.Flags().Float64Var(&config.RateLimit, "rate-limit", 5.0, "Rate limit (req/s)")
	cmd.Flags().IntVar(&config.Timeout, "timeout", 30, "Request timeout in seconds")
	cmd.Flags().BoolVar(&config.AllowInternal, "allow-internal", false, "Allow internal IP addresses")
	cmd.Flags().BoolVar(&config.AllowProduction, "allow-production", false, "Allow testing production URLs")

	// Output options
	cmd.Flags().StringVar(&config.Output, "output", "terminal", "Output format: terminal, json, markdown")
	cmd.Flags().StringVar(&config.OutputFile, "output-file", "", "Output file path")
	cmd.Flags().BoolVar(&config.Verbose, "verbose", false, "Verbose output")
	cmd.Flags().BoolVar(&config.DryRun, "dry-run", false, "Dry run (don't execute tests)")

	return cmd
}


// findingSummary tracks findings by severity level
type findingSummary struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

// addFinding increments the count for the given severity
func (s *findingSummary) addFinding(severity string) {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		s.Critical++
	case "HIGH":
		s.High++
	case "MEDIUM":
		s.Medium++
	case "LOW":
		s.Low++
	case "INFO":
		s.Info++
	}
}

// total returns the total number of findings
func (s *findingSummary) total() int {
	return s.Critical + s.High + s.Medium + s.Low + s.Info
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

	// Header output (no [DEBUG] prefix)
	fmt.Println("Starting gRPC security test")
	fmt.Printf("Target: %s\n", config.Target)

	// Validation: require either --proto or --reflection
	if config.Proto == "" && !config.Reflection {
		return fmt.Errorf("either --proto or --reflection must be provided")
	}

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
	var methodDescriptors map[string]*desc.MethodDescriptor
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
	var mutationExecutor *owasp.GRPCMutationExecutor
	if !config.DryRun {
		var err error
		executor, err = templates.NewGRPCExecutor(templates.GRPCExecutorConfig{
			Target:    config.Target,
			Plaintext: config.Plaintext,
			Insecure:  config.Insecure,
			Timeout:   time.Duration(config.Timeout) * time.Second,
		})
		if err != nil {
			return fmt.Errorf("failed to create gRPC executor: %w", err)
		}
		defer executor.Close()
		grpcVerboseLog(config.Verbose, "Created gRPC executor connection to %s", config.Target)

		// Create mutation executor for three-phase tests with adapter
		adapter := &grpcExecutorAdapter{executor: executor}
		mutationExecutor = owasp.NewGRPCMutationExecutor(adapter)
	}

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
	summary := findingSummary{}

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
					if config.Verbose {
						log.Debug("Skipping %s for %s: doesn't match endpoint_selector", tmpl.ID, op.Path)
					}
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
						// Get severity and OWASP category from template
						severity := "MEDIUM"
						if tmpl.Info.Severity != "" {
							severity = tmpl.Info.Severity
						}

						owaspCategory := tmpl.ID
						if tmpl.Info.Category != "" {
							owaspCategory = tmpl.Info.Category
						}

						// Track finding by severity
						summary.addFinding(severity)

						// Get severity color
						color := getSeverityColor(model.Severity(severity))

						// Output finding with colored severity
						fmt.Printf("%s[%s]%s %s - %s %s %s\n",
							color,
							strings.ToUpper(severity),
							colorReset,
							owaspCategory,
							tmpl.ID,
							op.Method,
							op.Path)

						// Output roles line
						fmt.Printf("  Roles: attacker=%s, victim=%s\n", attackerRoleName, victimRoleName)

						// Output request IDs if available (collect from all phases)
						if mutationResult.RequestIDs != nil {
							var allRequestIDs []string
							allRequestIDs = append(allRequestIDs, mutationResult.RequestIDs.Setup...)
							allRequestIDs = append(allRequestIDs, mutationResult.RequestIDs.Attack...)
							allRequestIDs = append(allRequestIDs, mutationResult.RequestIDs.Verify...)
							if len(allRequestIDs) > 0 {
								fmt.Printf("  Request IDs: %s\n", strings.Join(allRequestIDs, ", "))
							}
						}
					} else {
						// Verbose: plain output for pass results
						if config.Verbose {
							fmt.Printf("  [PASS] %s (mutation test)\n", tmpl.ID)
						}
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
					// Get severity and OWASP category from template
					severity := "MEDIUM" // Default if not specified
					if tmpl.Info.Severity != "" {
						severity = tmpl.Info.Severity
					}

					owaspCategory := tmpl.ID // Fallback to ID if no category
					if tmpl.Info.Category != "" {
						owaspCategory = tmpl.Info.Category
					}

					// Track finding by severity
					summary.addFinding(severity)

					// Get severity color
					color := getSeverityColor(model.Severity(severity))

					// Output finding with colored severity (matches GraphQL format exactly)
					fmt.Printf("%s[%s]%s %s - %s %s %s\n",
						color,
						strings.ToUpper(severity),
						colorReset,
						owaspCategory,
						tmpl.ID,
						op.Method,
						op.Path)

					// Output roles line (matches GraphQL format exactly)
					fmt.Printf("  Roles: attacker=%s, victim=%s\n", attackerRoleName, victimRoleName)

					// Output request IDs if available
					if len(result.RequestIDs) > 0 {
						fmt.Printf("  Request IDs: %s\n", strings.Join(result.RequestIDs, ", "))
					}
				} else {
					// Verbose: plain output for pass results (no nested log levels)
					if config.Verbose {
						fmt.Printf("  [PASS] %s (status: %d)\n", tmpl.ID, result.Response.StatusCode)
					}
				}
			}
		}
	}

	// 6. Final summary (GraphQL style)
	elapsed := time.Since(startTime)
	grpcVerboseLog(config.Verbose, "Test completed in %v", elapsed)

	// Count roles tested
	rolesCount := 0
	if rolesCfg != nil {
		rolesCount = len(rolesCfg.Roles)
	}

	fmt.Println("")
	fmt.Println("=== Hadrian Security Test Results ===")
	fmt.Println("")
	fmt.Printf("Duration: %v\n", elapsed.Round(time.Second))
	fmt.Printf("Operations tested: %d\n", len(operations))
	fmt.Printf("Templates loaded: %d\n", len(templateFiles))
	if rolesCount > 0 {
		fmt.Printf("Roles tested: %d\n", rolesCount)
	}
	fmt.Println("")

	if summary.total() > 0 {
		fmt.Println("Findings Summary:")
		if summary.Critical > 0 {
			fmt.Printf("  %sCRITICAL%s: %d\n", colorRed, colorReset, summary.Critical)
		}
		if summary.High > 0 {
			fmt.Printf("  %sHIGH%s: %d\n", colorOrange, colorReset, summary.High)
		}
		if summary.Medium > 0 {
			fmt.Printf("  %sMEDIUM%s: %d\n", colorYellow, colorReset, summary.Medium)
		}
		if summary.Low > 0 {
			fmt.Printf("  %sLOW%s: %d\n", colorBlue, colorReset, summary.Low)
		}
		if summary.Info > 0 {
			fmt.Printf("  %sINFO%s: %d\n", colorGreen, colorReset, summary.Info)
		}
		fmt.Println("")
		fmt.Printf("Total findings: %d\n", summary.total())
	} else {
		fmt.Println("Total findings: 0")
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

// buildTemplateVariablesWithRoles constructs the variable map for template substitution
// and returns the attacker and victim role names
func buildTemplateVariablesWithRoles(op *model.Operation, methodDesc *desc.MethodDescriptor, authCfg *auth.AuthConfig, rolesCfg *roles.RoleConfig) (map[string]string, string, string) {
	variables := map[string]string{
		// Operation context
		"operation.path":    op.Path,
		"operation.method":  methodDesc.GetName(),
		"operation.service": methodDesc.GetService().GetName(),
		"service.name":      methodDesc.GetService().GetName(),
	}

	// Determine owner field with fallback
	ownerField := op.OwnerField
	if ownerField == "" && len(op.PathParams) > 0 {
		ownerField = op.PathParams[0].Name
	}
	if ownerField == "" {
		// Use first field from input type as fallback
		fields := methodDesc.GetInputType().GetFields()
		if len(fields) > 0 {
			ownerField = fields[0].GetName()
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

	// If no methods specified, match all operations
	if len(selector.Methods) == 0 {
		return true
	}

	// For gRPC, extract method name from path (e.g., "/package.Service/MethodName" -> "MethodName")
	// op.Method contains "GRPC" protocol type, not the actual method name
	var methodName string
	parts := strings.Split(op.Path, "/")
	if len(parts) > 0 {
		methodName = parts[len(parts)-1]
	}

	// Fallback if path extraction failed
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
