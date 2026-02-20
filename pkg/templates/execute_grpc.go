package templates

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	grpcinsecure "google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/praetorian-inc/hadrian/pkg/log"
	"github.com/praetorian-inc/hadrian/pkg/model"
)

// MaxGRPCResponseBodySize limits gRPC response body size to prevent memory exhaustion (10MB)
const MaxGRPCResponseBodySize = 10 * 1024 * 1024

// GRPCExecutor handles gRPC test execution
type GRPCExecutor struct {
	conn        *grpc.ClientConn
	target      string
	plaintext   bool
	insecure    bool
	timeout     time.Duration
	rateLimiter *rate.Limiter
}

// GRPCExecutorConfig holds configuration for the gRPC executor
type GRPCExecutorConfig struct {
	Target    string
	Plaintext bool
	Insecure  bool
	Timeout   time.Duration
	TLSCACert string
	RateLimit float64
}

// NewGRPCExecutor creates a new gRPC executor
func NewGRPCExecutor(config GRPCExecutorConfig) (*GRPCExecutor, error) {
	var opts []grpc.DialOption

	switch {
	case config.Plaintext:
		opts = append(opts, grpc.WithTransportCredentials(grpcinsecure.NewCredentials()))
	case config.TLSCACert != "":
		// TLSCACert takes priority over Insecure flag
		caCert, err := os.ReadFile(config.TLSCACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: certPool})))
	case config.Insecure:
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	default:
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})))
	}

	conn, err := grpc.NewClient(config.Target, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC server: %w", err)
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Initialize rate limiter if rate limit is positive
	var rateLimiter *rate.Limiter
	if config.RateLimit > 0 {
		burst := int(config.RateLimit) * 2
		if burst < 1 {
			burst = 1
		}
		rateLimiter = rate.NewLimiter(rate.Limit(config.RateLimit), burst)
	}

	return &GRPCExecutor{
		conn:        conn,
		target:      config.Target,
		plaintext:   config.Plaintext,
		insecure:    config.Insecure,
		timeout:     timeout,
		rateLimiter: rateLimiter,
	}, nil
}

// Close closes the gRPC connection
func (e *GRPCExecutor) Close() error {
	if e.conn != nil {
		return e.conn.Close()
	}
	return nil
}

// CheckConnection verifies the gRPC server is reachable by attempting a connection.
// grpc.NewClient creates lazy connections, so this ensures we fail fast with a clear
// error instead of getting UNAVAILABLE on every RPC call.
func (e *GRPCExecutor) CheckConnection(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	e.conn.Connect()
	for {
		state := e.conn.GetState()
		if state == connectivity.Ready {
			return nil
		}
		if state == connectivity.TransientFailure {
			return fmt.Errorf("cannot reach gRPC server at %s (connection state: %s). Is the server running?", e.target, state)
		}
		if !e.conn.WaitForStateChange(ctx, state) {
			return fmt.Errorf("timeout connecting to gRPC server at %s (last state: %s). Is the server running?", e.target, state)
		}
	}
}

// ExecuteGRPC executes a gRPC test against an operation
func (e *GRPCExecutor) ExecuteGRPC(
	ctx context.Context,
	tmpl *CompiledTemplate,
	op *model.Operation,
	methodDesc protoreflect.MethodDescriptor,
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
	methodDesc protoreflect.MethodDescriptor,
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
		default:
			log.Warn("unsupported gRPC auth method %q (supported: bearer, api_key)", authInfo.Method)
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

	// Build the request message using dynamicpb
	reqMsg := dynamicpb.NewMessage(methodDesc.Input())

	// Parse message JSON and populate fields
	if test.Message != "" {
		msgJSON := substituteVariables(test.Message, variables)
		if err := protojson.Unmarshal([]byte(msgJSON), reqMsg); err != nil {
			return nil, fmt.Errorf("failed to parse request message: %w", err)
		}
	}

	// Apply rate limiting if configured
	if e.rateLimiter != nil {
		if err := e.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limit wait failed: %w", err)
		}
	}

	// Build the full method path for conn.Invoke
	fullMethod := fmt.Sprintf("/%s/%s", methodDesc.Parent().FullName(), methodDesc.Name())

	// Execute the RPC call using conn.Invoke
	var respMD metadata.MD
	respMsg := dynamicpb.NewMessage(methodDesc.Output())
	err := e.conn.Invoke(ctx, fullMethod, reqMsg, respMsg, grpc.Header(&respMD))

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

	// Build response body with size checks to prevent excessive memory allocation
	var responseBody string
	if err == nil {
		bodyBytes, marshalErr := protojson.MarshalOptions{UseProtoNames: true}.Marshal(respMsg)
		switch {
		case marshalErr != nil:
			log.Debug("failed to marshal gRPC response: %v", marshalErr)
		case len(bodyBytes) > MaxGRPCResponseBodySize:
			// Check size before string conversion to avoid doubling memory allocation
			return nil, fmt.Errorf("gRPC response exceeds maximum size of %d bytes", MaxGRPCResponseBodySize)
		default:
			responseBody = string(bodyBytes)
		}
	}
	if statusMessage != "" && responseBody == "" {
		errJSON, _ := json.Marshal(map[string]string{"error": statusMessage})
		responseBody = string(errJSON)
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

// matchRegex checks if a regex pattern matches the input
func matchRegex(pattern, input string) bool {
	matched, err := regexp.MatchString(pattern, input)
	if err != nil {
		log.Debug("invalid regex pattern %q: %v", pattern, err)
		return false
	}
	return matched
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
