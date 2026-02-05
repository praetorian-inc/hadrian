package templates

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/dynamic"
	"github.com/jhump/protoreflect/dynamic/grpcdynamic"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/praetorian-inc/hadrian/pkg/model"
)

// GRPCExecutor handles gRPC test execution
type GRPCExecutor struct {
	conn       *grpc.ClientConn
	stub       grpcdynamic.Stub
	target     string
	plaintext  bool
	insecure   bool
	timeout    time.Duration
}

// GRPCExecutorConfig holds configuration for the gRPC executor
type GRPCExecutorConfig struct {
	Target    string
	Plaintext bool
	Insecure  bool
	Timeout   time.Duration
	TLSCACert string
}

// NewGRPCExecutor creates a new gRPC executor
func NewGRPCExecutor(config GRPCExecutorConfig) (*GRPCExecutor, error) {
	var opts []grpc.DialOption

	if config.Plaintext {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else if config.Insecure {
		// TLS but skip verification
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		// TODO: Add proper TLS with CA cert support
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.Dial(config.Target, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC server: %w", err)
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &GRPCExecutor{
		conn:      conn,
		stub:      grpcdynamic.NewStub(conn),
		target:    config.Target,
		plaintext: config.Plaintext,
		insecure:  config.Insecure,
		timeout:   timeout,
	}, nil
}

// Close closes the gRPC connection
func (e *GRPCExecutor) Close() error {
	if e.conn != nil {
		return e.conn.Close()
	}
	return nil
}

// ExecuteGRPC executes a gRPC test against an operation
func (e *GRPCExecutor) ExecuteGRPC(
	ctx context.Context,
	tmpl *CompiledTemplate,
	op *model.Operation,
	methodDesc *desc.MethodDescriptor,
	authInfo *AuthInfo,
	variables map[string]string,
) (*ExecutionResult, error) {
	if len(tmpl.GRPC) == 0 {
		return nil, fmt.Errorf("template has no gRPC tests defined")
	}

	result := &ExecutionResult{
		TemplateID: tmpl.ID,
		Operation:  op,
		RequestIDs: []string{},
	}

	// Execute each gRPC test in the template
	for _, grpcTest := range tmpl.GRPC {
		execResult, err := e.executeGRPCTest(ctx, &grpcTest, op, methodDesc, authInfo, variables)
		if err != nil {
			return nil, err
		}

		result.Response = execResult.Response
		result.RequestIDs = append(result.RequestIDs, execResult.RequestIDs...)

		// Check matchers
		if len(grpcTest.Matchers) > 0 {
			matched := e.evaluateMatchers(grpcTest.Matchers, execResult)
			result.Matched = matched
		}
	}

	// Evaluate Detection section if present (preferred method)
	if len(tmpl.Detection.SuccessIndicators) > 0 {
		result.Matched = e.evaluateDetection(&tmpl.Detection, result)
	}

	return result, nil
}

// executeGRPCTest executes a single gRPC test
func (e *GRPCExecutor) executeGRPCTest(
	ctx context.Context,
	test *GRPCTest,
	op *model.Operation,
	methodDesc *desc.MethodDescriptor,
	authInfo *AuthInfo,
	variables map[string]string,
) (*ExecutionResult, error) {
	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	// Build request metadata
	md := metadata.New(nil)

	// Add auth metadata
	if authInfo != nil {
		switch authInfo.Method {
		case "bearer":
			md.Set("authorization", "Bearer "+authInfo.Value)
		case "api_key":
			if authInfo.KeyName != "" {
				md.Set(strings.ToLower(authInfo.KeyName), authInfo.Value)
			} else {
				md.Set("authorization", authInfo.Value)
			}
		}
	}

	// Add template metadata with variable substitution
	for key, value := range test.Metadata {
		substituted := substituteVariables(value, variables)
		md.Set(strings.ToLower(key), substituted)
	}

	// Generate request ID
	requestID := generateRequestID()
	md.Set("x-hadrian-request-id", requestID)

	// Attach metadata to context
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Build the request message
	reqMsg := dynamic.NewMessage(methodDesc.GetInputType())

	// Parse message JSON and populate fields
	if test.Message != "" {
		msgJSON := substituteVariables(test.Message, variables)
		if err := reqMsg.UnmarshalJSON([]byte(msgJSON)); err != nil {
			return nil, fmt.Errorf("failed to parse request message: %w", err)
		}
	}

	// Execute the RPC call
	var respMD metadata.MD
	respMsg, err := e.stub.InvokeRpc(ctx, methodDesc, reqMsg, grpc.Header(&respMD))

	// Extract status code
	var statusCode int
	var statusMessage string
	if err != nil {
		st, ok := status.FromError(err)
		if ok {
			statusCode = int(st.Code())
			statusMessage = st.Message()
		} else {
			statusCode = int(codes.Unknown)
			statusMessage = err.Error()
		}
	} else {
		statusCode = int(codes.OK)
	}

	// Build response body
	var responseBody string
	if respMsg != nil {
		if dynMsg, ok := respMsg.(*dynamic.Message); ok {
			bodyBytes, _ := dynMsg.MarshalJSON()
			responseBody = string(bodyBytes)
		}
	}
	if statusMessage != "" && responseBody == "" {
		responseBody = fmt.Sprintf(`{"error": "%s"}`, statusMessage)
	}

	// Convert metadata to headers map
	headers := make(map[string]string)
	for k, v := range respMD {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return &ExecutionResult{
		RequestIDs: []string{requestID},
		Response: model.HTTPResponse{
			StatusCode: statusCode,
			Headers:    headers,
			Body:       responseBody,
		},
	}, nil
}

// evaluateMatchers checks if matchers match the response
func (e *GRPCExecutor) evaluateMatchers(matchers []Matcher, result *ExecutionResult) bool {
	for _, matcher := range matchers {
		matched := false

		switch matcher.Type {
		case "status", "grpc_status":
			// Check gRPC status code
			for _, code := range matcher.Code {
				if result.Response.StatusCode == code {
					matched = true
					break
				}
			}
			// Also check HTTP status field for backwards compatibility
			for _, status := range matcher.Status {
				if result.Response.StatusCode == status {
					matched = true
					break
				}
			}

		case "word":
			// Word match in body
			for _, word := range matcher.Words {
				if strings.Contains(result.Response.Body, word) {
					matched = true
					break
				}
			}

		case "regex":
			// Regex match in body
			for _, pattern := range matcher.Regex {
				if matchRegex(pattern, result.Response.Body) {
					matched = true
					break
				}
			}
		}

		// If matcher condition is "and" (default), all must match
		// If "or", any match is sufficient
		if matcher.Condition == "or" {
			if matched {
				return true
			}
		} else {
			// "and" condition - if any fails, return false
			if !matched {
				return false
			}
		}
	}

	return true
}

// substituteVariables replaces {{variable}} placeholders in a string
func substituteVariables(s string, variables map[string]string) string {
	result := s
	for key, value := range variables {
		result = strings.ReplaceAll(result, "{{"+key+"}}", value)
	}
	return result
}

// matchRegex checks if a pattern matches the input
func matchRegex(pattern, input string) bool {
	// Simple implementation - in production use pre-compiled regex
	return strings.Contains(input, pattern)
}

// evaluateDetection evaluates the Detection section to determine if a vulnerability was found
func (e *GRPCExecutor) evaluateDetection(detection *Detection, result *ExecutionResult) bool {
	// Check failure indicators first - if any match, NOT a vulnerability
	for _, indicator := range detection.FailureIndicators {
		if e.indicatorMatches(&indicator, result) {
			return false
		}
	}

	// Check success indicators - if any match, IS a vulnerability
	for _, indicator := range detection.SuccessIndicators {
		if e.indicatorMatches(&indicator, result) {
			return true
		}
	}

	return false
}

// indicatorMatches checks if a single indicator matches the response
func (e *GRPCExecutor) indicatorMatches(indicator *Indicator, result *ExecutionResult) bool {
	switch indicator.Type {
	case "grpc_status":
		// Handle code as int or []int
		switch code := indicator.Code.(type) {
		case int:
			return result.Response.StatusCode == code
		case float64:
			return result.Response.StatusCode == int(code)
		case []interface{}:
			for _, c := range code {
				switch cv := c.(type) {
				case int:
					if result.Response.StatusCode == cv {
						return true
					}
				case float64:
					if result.Response.StatusCode == int(cv) {
						return true
					}
				}
			}
		}
	case "status_code":
		// HTTP-style status code check
		switch code := indicator.StatusCode.(type) {
		case int:
			return result.Response.StatusCode == code
		case float64:
			return result.Response.StatusCode == int(code)
		case []interface{}:
			for _, c := range code {
				switch cv := c.(type) {
				case int:
					if result.Response.StatusCode == cv {
						return true
					}
				case float64:
					if result.Response.StatusCode == int(cv) {
						return true
					}
				}
			}
		}
	case "body_field":
		// Check if a field exists in body
		if indicator.Exists != nil {
			fieldExists := strings.Contains(result.Response.Body, indicator.BodyField)
			return fieldExists == *indicator.Exists
		}
		// Check field value if specified
		if indicator.Value != nil {
			// Simple contains check for now
			return strings.Contains(result.Response.Body, fmt.Sprintf("%v", indicator.Value))
		}
	case "word":
		// Check if any pattern exists in body
		for _, pattern := range indicator.Patterns {
			if strings.Contains(result.Response.Body, pattern) {
				return true
			}
		}
	}
	return false
}
