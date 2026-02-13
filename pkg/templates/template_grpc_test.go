package templates

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseGRPCTemplate_BasicStructure tests that gRPC templates can be parsed
func TestParseGRPCTemplate_BasicStructure(t *testing.T) {
	yamlData := `
id: grpc-test-bola
info:
  name: "gRPC BOLA Test"
  category: "API1:2023"
  severity: "HIGH"
  author: "hadrian"
  tags: ["grpc", "bola"]
  requires_llm_triage: true
  test_pattern: "simple"

endpoint_selector:
  requires_auth: true
  methods: ["Get*"]

role_selector:
  attacker_permission_level: "lower"
  victim_permission_level: "higher"

grpc:
  - method: "{{operation.method}}"
    service: "{{operation.service}}"
    message: '{"user_id": "{{victim_id}}"}'
    metadata:
      authorization: "Bearer {{attacker_token}}"
    repeat: 3
    rate_limit:
      threshold: 10
      status_codes: [8]
      body_patterns: ["rate limit"]
    backoff:
      status_codes: [14]
      body_patterns: ["unavailable"]
      wait_seconds: 5
      limit: 3
    matchers:
      - type: "status"
        code: [0]

detection:
  success_indicators:
    - type: "grpc_status"
      code: 0
    - type: "body_field"
      body_field: "data"
      exists: true
  failure_indicators:
    - type: "grpc_status"
      code: [7, 16]
    - type: "body_contains"
      patterns: ["permission denied", "not found"]
  vulnerability_pattern: "grpc_bola_detected"
`

	tmpl, err := ParseYAML([]byte(yamlData))
	require.NoError(t, err)
	require.NotNil(t, tmpl)

	// Verify basic template info
	assert.Equal(t, "grpc-test-bola", tmpl.ID)
	assert.Equal(t, "gRPC BOLA Test", tmpl.Info.Name)

	// Verify gRPC test is present
	require.Len(t, tmpl.GRPC, 1)
	grpcTest := tmpl.GRPC[0]

	// Verify gRPC test fields
	assert.Equal(t, "{{operation.method}}", grpcTest.Method)
	assert.Equal(t, "{{operation.service}}", grpcTest.Service)
	assert.Equal(t, `{"user_id": "{{victim_id}}"}`, grpcTest.Message)
	assert.Equal(t, "Bearer {{attacker_token}}", grpcTest.Metadata["authorization"])

	// Verify repeat
	assert.Equal(t, 3, grpcTest.Repeat)

	// Verify rate_limit
	require.NotNil(t, grpcTest.RateLimit)
	assert.Equal(t, 10, grpcTest.RateLimit.Threshold)
	assert.Equal(t, []int{8}, grpcTest.RateLimit.StatusCodes)
	assert.Equal(t, []string{"rate limit"}, grpcTest.RateLimit.BodyPatterns)

	// Verify backoff
	require.NotNil(t, grpcTest.Backoff)
	assert.Equal(t, []int{14}, grpcTest.Backoff.StatusCodes)
	assert.Equal(t, []string{"unavailable"}, grpcTest.Backoff.BodyPatterns)
	assert.Equal(t, 5, grpcTest.Backoff.WaitSeconds)
	assert.Equal(t, 3, grpcTest.Backoff.Limit)

	// Verify matchers
	require.Len(t, grpcTest.Matchers, 1)
	assert.Equal(t, "status", grpcTest.Matchers[0].Type)
	assert.Equal(t, []int{0}, grpcTest.Matchers[0].Code)

	// Verify detection success indicators
	require.Len(t, tmpl.Detection.SuccessIndicators, 2)
	assert.Equal(t, "grpc_status", tmpl.Detection.SuccessIndicators[0].Type)
	assert.Equal(t, 0, tmpl.Detection.SuccessIndicators[0].Code)

	// Verify detection failure indicators
	require.Len(t, tmpl.Detection.FailureIndicators, 2)
	assert.Equal(t, "grpc_status", tmpl.Detection.FailureIndicators[0].Type)
	assert.Equal(t, []interface{}{7, 16}, tmpl.Detection.FailureIndicators[0].Code)
	assert.Equal(t, "body_contains", tmpl.Detection.FailureIndicators[1].Type)
	assert.Equal(t, []string{"permission denied", "not found"}, tmpl.Detection.FailureIndicators[1].Patterns)
}

// TestParseGRPCTemplate_StoreResponseFields tests store_response_fields support
func TestParseGRPCTemplate_StoreResponseFields(t *testing.T) {
	yamlData := `
id: grpc-test-store
info:
  name: "gRPC Store Test"
  category: "TEST"
  severity: "LOW"
  author: "hadrian"
  tags: ["grpc"]
  requires_llm_triage: false
  test_pattern: "simple"

endpoint_selector:
  requires_auth: true
  methods: ["*"]

role_selector:
  attacker_permission_level: "all"
  victim_permission_level: "all"

grpc:
  - method: "CreateUser"
    service: "UserService"
    message: '{"name": "test"}'
    store_response_fields:
      user_id: "id"
      user_email: "email"
  - method: "GetUser"
    service: "UserService"
    message: '{"id": "{{user_id}}"}'
    use_stored_field: "user_id"

detection:
  success_indicators:
    - type: "grpc_status"
      code: 0
  vulnerability_pattern: "test"
`

	tmpl, err := ParseYAML([]byte(yamlData))
	require.NoError(t, err)
	require.NotNil(t, tmpl)

	// Verify store_response_fields in first test
	require.Len(t, tmpl.GRPC, 2)
	firstTest := tmpl.GRPC[0]
	require.NotNil(t, firstTest.StoreResponseFields)
	assert.Equal(t, "id", firstTest.StoreResponseFields["user_id"])
	assert.Equal(t, "email", firstTest.StoreResponseFields["user_email"])

	// Verify use_stored_field in second test
	secondTest := tmpl.GRPC[1]
	assert.Equal(t, "user_id", secondTest.UseStoredField)
}

// TestParseGRPCTemplate_FromActualFile tests parsing an actual gRPC template file
func TestParseGRPCTemplate_FromActualFile(t *testing.T) {
	tmpl, err := Parse("../../templates/grpc/01-api1-bola-read.yaml")
	require.NoError(t, err)
	require.NotNil(t, tmpl)

	// Verify basic structure
	assert.Equal(t, "01-grpc-api1-bola-read", tmpl.ID)
	assert.Equal(t, "gRPC BOLA - Unauthorized Resource Read", tmpl.Info.Name)

	// Verify gRPC test is present and parseable
	require.Len(t, tmpl.GRPC, 1)
	grpcTest := tmpl.GRPC[0]
	assert.Equal(t, "{{operation.method}}", grpcTest.Method)
	assert.Equal(t, "{{operation.service}}", grpcTest.Service)
	assert.NotEmpty(t, grpcTest.Message)

	// Verify detection indicators
	require.NotEmpty(t, tmpl.Detection.SuccessIndicators)

	// Check for failure indicators (should be present in template)
	require.NotEmpty(t, tmpl.Detection.FailureIndicators)
}
