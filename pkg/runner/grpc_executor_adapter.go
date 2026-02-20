package runner

import (
	"context"

	"github.com/praetorian-inc/hadrian/pkg/auth"
	"github.com/praetorian-inc/hadrian/pkg/templates"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// grpcExecutorAdapter adapts templates.GRPCExecutor to orchestrator.GRPCExecutor interface
type grpcExecutorAdapter struct {
	executor *templates.GRPCExecutor
}

// ExecuteGRPC implements orchestrator.GRPCExecutor interface by calling templates.GRPCExecutor
// with the appropriate parameters
func (a *grpcExecutorAdapter) ExecuteGRPC(
	ctx context.Context,
	tmpl *templates.CompiledTemplate,
	methodDesc protoreflect.MethodDescriptor,
	authInfo *auth.AuthInfo,
	variables map[string]string,
) (*templates.ExecutionResult, error) {
	// Convert auth.AuthInfo to templates.AuthInfo if needed
	var templatesAuth *templates.AuthInfo
	if authInfo != nil {
		templatesAuth = &templates.AuthInfo{
			Method:   authInfo.Method,
			Location: authInfo.Location,
			KeyName:  authInfo.KeyName,
			Value:    authInfo.Value,
		}
	}

	// Call the actual GRPCExecutor with additional parameters
	// We pass nil for operation since mutation executor doesn't use it
	return a.executor.ExecuteGRPC(ctx, tmpl, nil, methodDesc, templatesAuth, variables)
}
