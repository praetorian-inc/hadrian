package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/auth"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/templates"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// GRPCExecutor interface for making gRPC requests
type GRPCExecutor interface {
	ExecuteGRPC(
		ctx context.Context,
		tmpl *templates.CompiledTemplate,
		methodDesc protoreflect.MethodDescriptor,
		authInfo *auth.AuthInfo,
		variables map[string]string,
	) (*templates.ExecutionResult, error)
}

// GRPCMutationExecutor runs three-phase mutation tests for gRPC APIs
type GRPCMutationExecutor struct {
	grpcExecutor GRPCExecutor
	tracker      *Tracker
}

// GRPCMutationResult contains results from a three-phase gRPC mutation test
type GRPCMutationResult struct {
	TemplateID     string
	Matched        bool // true if vulnerability found (attack succeeded)
	SetupResponse  *model.HTTPResponse
	AttackResponse *model.HTTPResponse
	VerifyResponse *model.HTTPResponse
	ResourceID     string
	RequestIDs     *PhaseRequestIDs // tracks request IDs per phase
}

// NewGRPCMutationExecutor creates a new gRPC mutation executor
func NewGRPCMutationExecutor(executor GRPCExecutor) *GRPCMutationExecutor {
	return &GRPCMutationExecutor{
		grpcExecutor: executor,
		tracker:      NewTracker(),
	}
}

// ExecuteGRPCMutation runs a three-phase gRPC mutation test
func (e *GRPCMutationExecutor) ExecuteGRPCMutation(
	ctx context.Context,
	tmpl *templates.Template,
	methodDesc protoreflect.MethodDescriptor,
	authInfos map[string]*auth.AuthInfo,
) (*GRPCMutationResult, error) {
	result := &GRPCMutationResult{
		TemplateID: tmpl.ID,
		RequestIDs: &PhaseRequestIDs{},
	}

	if tmpl.TestPhases == nil {
		return result, fmt.Errorf("template has no test phases")
	}

	// Phase 1: Setup (create resource) - supports multiple setup phases
	for i, setupPhase := range tmpl.TestPhases.Setup {
		if setupPhase == nil {
			continue
		}

		setupResp, err := e.executePhase(ctx, tmpl, setupPhase, methodDesc, setupPhase.Auth, authInfos)
		if err != nil {
			return result, fmt.Errorf("setup phase %d failed: %w", i+1, err)
		}

		// For backwards compatibility, store last setup response
		result.SetupResponse = setupResp

		// Store resource ID if needed - store by field name for later lookup
		// Support both single field (backwards compat) and multiple fields
		if setupPhase.StoreResponseField != "" && setupResp != nil {
			resourceID := extractField(setupResp.Body, setupPhase.StoreResponseField)
			if resourceID != "" {
				// Store in result if first setup phase with resource ID
				if result.ResourceID == "" {
					result.ResourceID = resourceID
				}
				e.tracker.StoreResource(setupPhase.StoreResponseField, resourceID)
			}
		}

		// Store multiple fields if specified
		if len(setupPhase.StoreResponseFields) > 0 && setupResp != nil {
			for alias, jsonPath := range setupPhase.StoreResponseFields {
				fieldValue := extractField(setupResp.Body, jsonPath)
				if fieldValue != "" {
					e.tracker.StoreResource(alias, fieldValue)
					// If this is the first stored field and ResourceID is empty, use it
					if result.ResourceID == "" {
						result.ResourceID = fieldValue
					}
				}
			}
		}
	}

	// Phase 2: Attack (try to access with different role)
	if tmpl.TestPhases.Attack != nil {
		attackResp, err := e.executePhase(ctx, tmpl, tmpl.TestPhases.Attack, methodDesc, tmpl.TestPhases.Attack.Auth, authInfos)
		if err != nil {
			return result, fmt.Errorf("attack phase failed: %w", err)
		}
		result.AttackResponse = attackResp

		// Check if attack succeeded (vulnerability found)
		if matchesDetectionConditions(tmpl.TestPhases.Attack, attackResp.StatusCode, attackResp.Body) {
			result.Matched = true
		}
	}

	// Phase 3: Verify (confirm resource still accessible by victim)
	if tmpl.TestPhases.Verify != nil {
		verifyResp, err := e.executePhase(ctx, tmpl, tmpl.TestPhases.Verify, methodDesc, tmpl.TestPhases.Verify.Auth, authInfos)
		if err != nil {
			return result, fmt.Errorf("verify phase failed: %w", err)
		}
		result.VerifyResponse = verifyResp
	}

	return result, nil
}

// executePhase executes a single phase and returns the gRPC response
func (e *GRPCMutationExecutor) executePhase(
	ctx context.Context,
	tmpl *templates.Template,
	phase *templates.Phase,
	methodDesc protoreflect.MethodDescriptor,
	authUser string,
	authInfos map[string]*auth.AuthInfo,
) (*model.HTTPResponse, error) {
	if phase == nil {
		return nil, nil
	}

	// Build path with resource ID substitution
	path := phase.Path
	if path == "" {
		return nil, fmt.Errorf("phase path is required")
	}

	// Substitute stored values into path
	// Support backwards compatibility: if UseStoredField is set, use it
	if phase.UseStoredField != "" {
		storedValue := e.tracker.GetResource(phase.UseStoredField)
		if storedValue != "" {
			// Replace {fieldName} with stored value
			path = strings.ReplaceAll(path, "{"+phase.UseStoredField+"}", storedValue)
		}
	}

	// Also substitute ALL stored fields (supports multiple placeholders in path)
	// This allows paths like "/api/{video_id}/comments/{comment_id}"
	for _, alias := range e.tracker.GetAllKeys() {
		storedValue := e.tracker.GetResource(alias)
		if storedValue != "" {
			path = strings.ReplaceAll(path, "{"+alias+"}", storedValue)
		}
	}

	// Build variables map for gRPC executor
	variables := make(map[string]string)

	// Add stored resource IDs to variables
	for _, key := range e.tracker.GetAllKeys() {
		variables[key] = e.tracker.GetResource(key)
	}

	msg, err := buildGRPCMessage(phase, variables)
	if err != nil {
		return nil, err
	}

	// Create a minimal compiled template for execution
	grpcTest := templates.GRPCTest{
		Method:   path,
		Service:  "", // Will be extracted from methodDesc
		Message:  msg,
		Metadata: make(map[string]string),
	}

	phaseTemplate := &templates.Template{
		ID:   tmpl.ID,
		Info: tmpl.Info,
		GRPC: []templates.GRPCTest{grpcTest},
	}

	compiledTmpl := &templates.CompiledTemplate{
		Template: phaseTemplate,
	}

	// Get auth info for the role
	var authInfo *auth.AuthInfo
	if ai, ok := authInfos[authUser]; ok {
		authInfo = ai
	}

	// Execute the gRPC call
	execResult, err := e.grpcExecutor.ExecuteGRPC(ctx, compiledTmpl, methodDesc, authInfo, variables)
	if err != nil {
		return nil, err
	}

	return &execResult.Response, nil
}

// buildGRPCMessage constructs a gRPC message JSON from phase data and variables
func buildGRPCMessage(phase *templates.Phase, variables map[string]string) (string, error) {
	if len(phase.Data) == 0 && len(variables) == 0 {
		return "{}", nil
	}

	// Merge phase data and variables
	data := make(map[string]interface{})

	// Add phase data first
	for k, v := range phase.Data {
		data[k] = v
	}

	// Add variables (may override phase data)
	for k, v := range variables {
		data[k] = v
	}

	// Convert to JSON
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal gRPC message: %w", err)
	}

	return string(jsonBytes), nil
}

// ClearTracker clears all tracked resources
func (e *GRPCMutationExecutor) ClearTracker() {
	e.tracker.Clear()
}
