package runner

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/auth"
	"github.com/praetorian-inc/hadrian/pkg/log"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/orchestrator"
	"github.com/praetorian-inc/hadrian/pkg/plugins/grpc"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/praetorian-inc/hadrian/pkg/templates"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// RunGRPCTest executes gRPC security tests and returns findings directly.
// It is the library entry point for programmatic usage (e.g. from Chariot),
// performing the same core work as the CLI minus reporter output and verbose logging.
func RunGRPCTest(ctx context.Context, config GRPCConfig) ([]*model.Finding, error) {
	log.SetVerbose(config.Verbose)

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration error: %w", err)
	}

	// Parse custom headers
	customHeaders, err := ParseCustomHeaders(config.Headers)
	if err != nil {
		return nil, fmt.Errorf("invalid custom header: %w", err)
	}

	// Parse proto file
	var operations []*model.Operation
	var methodDescriptors map[string]protoreflect.MethodDescriptor
	if config.Proto != "" {
		data, err := os.ReadFile(config.Proto)
		if err != nil {
			return nil, fmt.Errorf("failed to read proto file: %w", err)
		}

		plugin := &grpc.GRPCPlugin{}
		spec, descriptors, err := plugin.ParseWithDescriptors(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse proto file: %w", err)
		}

		operations = spec.Operations
		methodDescriptors = descriptors
	} else {
		return nil, fmt.Errorf("server reflection not yet implemented, use --proto flag")
	}

	// Load auth and roles configuration
	var authCfg *auth.AuthConfig
	var rolesCfg *roles.RoleConfig

	if config.Auth != "" {
		authCfg, err = auth.Load(config.Auth)
		if err != nil {
			return nil, fmt.Errorf("failed to load auth config: %w", err)
		}
	}

	if config.Roles != "" {
		rolesCfg, err = roles.Load(config.Roles)
		if err != nil {
			return nil, fmt.Errorf("failed to load roles config: %w", err)
		}
	}

	// Load templates
	templateDir := config.TemplateDir
	var templateFiles []*templates.CompiledTemplate
	if _, err := os.Stat(templateDir); err == nil {
		tmpls, err := loadGRPCTemplates(templateDir)
		if err != nil {
			log.Warn("No templates loaded from %s: %v", templateDir, err)
		} else {
			templateFiles = tmpls
		}
	}

	// Filter templates if specified
	if len(config.Templates) > 0 && len(templateFiles) > 0 {
		templateFiles = filterByTemplates(templateFiles, config.Templates)
		if len(templateFiles) == 0 {
			return nil, fmt.Errorf("no templates matched the specified filters: %v", config.Templates)
		}
	}

	// Create gRPC executor
	executor, err := templates.NewGRPCExecutor(templates.GRPCExecutorConfig{
		Target:    config.Target,
		Plaintext: config.Plaintext,
		Insecure:  config.Insecure,
		Timeout:   time.Duration(config.Timeout) * time.Second,
		TLSCACert: config.TLSCACert,
		RateLimit: config.RateLimit,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC executor: %w", err)
	}
	defer func() { _ = executor.Close() }()
	executor.SetCustomHeaders(customHeaders)

	// Validate connection
	if err := executor.CheckConnection(ctx); err != nil {
		return nil, err
	}

	// Create mutation executor
	adapter := &grpcExecutorAdapter{executor: executor}
	mutationExecutor := orchestrator.NewGRPCMutationExecutor(adapter)

	// Execute test loop
	var allFindings []*model.Finding

	for _, op := range operations {
		if len(templateFiles) == 0 {
			continue
		}

		methodDesc := methodDescriptors[op.Path]
		if methodDesc == nil {
			continue
		}

		for _, tmpl := range templateFiles {
			if !matchesEndpointSelector(op, tmpl) {
				continue
			}

			variables, attackerRoleName, victimRoleName := buildTemplateVariablesWithRoles(op, methodDesc, authCfg, rolesCfg)

			// Mutation template: three-phase testing
			if tmpl.Template != nil && tmpl.Template.Info.TestPattern == "mutation" {
				mutationExecutor.ClearTracker()
				authInfoMap := buildAuthInfoMap(authCfg, rolesCfg)
				mutationResult, err := mutationExecutor.ExecuteGRPCMutation(ctx, tmpl.Template, methodDesc, authInfoMap)
				if err != nil {
					log.Warn("gRPC mutation test failed [template=%s, method=%s]: %v", tmpl.ID, op.Path, err)
					continue
				}

				if mutationResult.Matched {
					finding := buildGRPCFinding(tmpl, op, attackerRoleName, victimRoleName)
					finding.Evidence = model.Evidence{
						SetupResponse:  mutationResult.SetupResponse,
						AttackResponse: mutationResult.AttackResponse,
						VerifyResponse: mutationResult.VerifyResponse,
						ResourceID:     mutationResult.ResourceID,
					}
					if mutationResult.AttackResponse != nil {
						finding.Evidence.Response = *mutationResult.AttackResponse
					}
					if mutationResult.RequestIDs != nil {
						finding.RequestIDs = append(finding.RequestIDs, mutationResult.RequestIDs.Setup...)
						finding.RequestIDs = append(finding.RequestIDs, mutationResult.RequestIDs.Attack...)
						finding.RequestIDs = append(finding.RequestIDs, mutationResult.RequestIDs.Verify...)
					}
					allFindings = append(allFindings, finding)
				}
				continue
			}

			// Standard template execution
			result, err := executor.ExecuteGRPC(ctx, tmpl, op, methodDesc, nil, variables)
			if err != nil {
				log.Warn("gRPC template execution failed [template=%s, method=%s]: %v", tmpl.ID, op.Path, err)
				continue
			}

			if result.Matched {
				finding := buildGRPCFinding(tmpl, op, attackerRoleName, victimRoleName)
				finding.Evidence = model.Evidence{
					Response: result.Response,
				}
				finding.RequestIDs = result.RequestIDs
				allFindings = append(allFindings, finding)
			}
		}
	}

	return allFindings, nil
}
