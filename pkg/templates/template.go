package templates

import (
	"gopkg.in/yaml.v3"
)

// Template represents a parsed YAML test template
type Template struct {
	ID   string       `yaml:"id"`
	Info TemplateInfo `yaml:"info"`

	// Endpoint selection criteria
	EndpointSelector EndpointSelector `yaml:"endpoint_selector"`

	// Role selection criteria
	RoleSelector RoleSelector `yaml:"role_selector"`

	// Test execution phases
	TestPhases *TestPhases `yaml:"test_phases,omitempty"`

	// Simple single-phase test (for non-mutation tests)
	HTTP []HTTPTest `yaml:"http,omitempty"`

	// GraphQL test execution (for GraphQL APIs)
	GraphQL []GraphQLTest `yaml:"graphql,omitempty"`

	// gRPC test execution (for gRPC APIs)
	GRPC []GRPCTest `yaml:"grpc,omitempty"`

	// Detection logic
	Detection Detection `yaml:"detection"`
}

type TemplateInfo struct {
	Name              string   `yaml:"name"`
	Category          string   `yaml:"category"`
	Severity          string   `yaml:"severity"`
	Author            string   `yaml:"author"`
	Description       string   `yaml:"description"`
	Tags              []string `yaml:"tags"`
	RequiresLLMTriage bool     `yaml:"requires_llm_triage"`
	TestPattern       string   `yaml:"test_pattern"`
}

type EndpointSelector struct {
	HasPathParameter bool     `yaml:"has_path_parameter"`
	RequiresAuth     bool     `yaml:"requires_auth"`
	Methods          []string `yaml:"methods"`
	Service          string   `yaml:"service,omitempty"` // gRPC: exact service name filter
	Method           string   `yaml:"method,omitempty"`  // gRPC: exact method name filter
	ReturnsObject    bool     `yaml:"returns_object"`
	PathPattern      string   `yaml:"path_pattern,omitempty"`
	Tags             []string `yaml:"tags,omitempty"`
}

type RoleSelector struct {
	AttackerPermissionLevel string `yaml:"attacker_permission_level"` // lower, higher, all
	VictimPermissionLevel   string `yaml:"victim_permission_level"`
}

// SetupPhases supports both single phase and array of phases in YAML
type SetupPhases []*Phase

// UnmarshalYAML handles both single object and array syntax for backwards compatibility
func (s *SetupPhases) UnmarshalYAML(value *yaml.Node) error {
	// If it's a sequence (array), unmarshal as []*Phase
	if value.Kind == yaml.SequenceNode {
		var phases []*Phase
		if err := value.Decode(&phases); err != nil {
			return err
		}
		*s = phases
		return nil
	}

	// If it's a mapping (single object), unmarshal as *Phase and wrap in slice
	var phase Phase
	if err := value.Decode(&phase); err != nil {
		return err
	}
	*s = []*Phase{&phase}
	return nil
}

type TestPhases struct {
	Setup  SetupPhases `yaml:"setup,omitempty"` // Now supports single or array
	Attack *Phase      `yaml:"attack"`
	Verify *Phase      `yaml:"verify"`
}

type Phase struct {
	Path                string            `yaml:"path,omitempty"`                  // Endpoint path for this phase
	Operation           string            `yaml:"operation"`                       // create, read, update, delete
	Auth                string            `yaml:"auth"`                            // attacker, victim
	Data                map[string]string `yaml:"data,omitempty"`                  // Request body data
	StoreResponseField  string            `yaml:"store_response_field,omitempty"`  // Single field to store (backwards compat)
	StoreResponseFields map[string]string `yaml:"store_response_fields,omitempty"` // Multiple fields: alias -> json_path
	UseStoredField      string            `yaml:"use_stored_field,omitempty"`      // Use stored value
	CheckField          string            `yaml:"check_field,omitempty"`           // Field to verify
	ExpectedValue       string            `yaml:"expected_value,omitempty"`        // Expected value
	ExpectedStatus      int               `yaml:"expected_status,omitempty"`
}

// RateLimit defines rate limiting detection criteria
type RateLimit struct {
	Threshold    int      `yaml:"threshold"`
	StatusCodes  []int    `yaml:"status_codes"`
	BodyPatterns []string `yaml:"body_patterns"`
}

// Backoff defines backoff/retry behavior for server overwhelm
type Backoff struct {
	StatusCodes  []int    `yaml:"status_codes"`
	BodyPatterns []string `yaml:"body_patterns"`
	WaitSeconds  int      `yaml:"wait_seconds"`
	Limit        int      `yaml:"limit"`
}

type HTTPTest struct {
	Method  string            `yaml:"method"`
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
	Body    string            `yaml:"body,omitempty"`

	// Number of times to repeat request
	Repeat int `yaml:"repeat,omitempty"`

	// Rate limiting detection (separate from backoff)
	RateLimit *RateLimit `yaml:"rate_limit,omitempty"`

	// Backoff/retry behavior for server overwhelm
	Backoff *Backoff `yaml:"backoff,omitempty"`

	Matchers []Matcher `yaml:"matchers"`
}

// GraphQLTest defines a GraphQL query/mutation test
type GraphQLTest struct {
	Query         string      `yaml:"query"`
	Variables     interface{} `yaml:"variables,omitempty"` // Accepts any JSON-compatible structure
	OperationName string      `yaml:"operation_name,omitempty"`

	// Auth
	Auth string `yaml:"auth,omitempty"` // attacker, victim

	// Matchers
	Matchers []Matcher `yaml:"matchers,omitempty"`

	// For attack testing
	Repeat    int        `yaml:"repeat,omitempty"`
	RateLimit *RateLimit `yaml:"rate_limit,omitempty"`
	Backoff   *Backoff   `yaml:"backoff,omitempty"`

	// Store/Use fields for multi-phase
	StoreResponseFields map[string]string `yaml:"store_response_fields,omitempty"`
	UseStoredField      string            `yaml:"use_stored_field,omitempty"`
}

// GRPCTest represents a gRPC test configuration
type GRPCTest struct {
	Method              string            `yaml:"method"`
	Service             string            `yaml:"service"`
	Message             string            `yaml:"message"`
	Metadata            map[string]string `yaml:"metadata,omitempty"`
	DeadlineMs          int               `yaml:"deadline_ms,omitempty"`
	Repeat              int               `yaml:"repeat,omitempty"`
	RateLimit           *RateLimit        `yaml:"rate_limit,omitempty"`
	Backoff             *Backoff          `yaml:"backoff,omitempty"`
	Matchers            []Matcher         `yaml:"matchers,omitempty"`
	StoreResponseFields map[string]string `yaml:"store_response_fields,omitempty"`
	UseStoredField      string            `yaml:"use_stored_field,omitempty"`
}

type Matcher struct {
	Type      string   `yaml:"type"` // word, regex, status, size, dsl
	Words     []string `yaml:"words,omitempty"`
	Regex     []string `yaml:"regex,omitempty"`
	Status    []int    `yaml:"status,omitempty"`
	Code      []int    `yaml:"code,omitempty"`      // gRPC status codes
	Part      string   `yaml:"part,omitempty"`      // body, header, all
	Condition string   `yaml:"condition,omitempty"` // and, or
}

type Detection struct {
	SuccessIndicators    []Indicator `yaml:"success_indicators"`
	FailureIndicators    []Indicator `yaml:"failure_indicators,omitempty"`
	VulnerabilityPattern string      `yaml:"vulnerability_pattern"`
	Conditions           []Condition `yaml:"conditions"`
	ResourceShouldExist  *bool       `yaml:"resource_should_exist,omitempty"`
	ResourceDeleted      *bool       `yaml:"resource_deleted,omitempty"`
}

type Indicator struct {
	Type       string      `yaml:"type,omitempty"`        // status_code, body_field, regex_match, sensitive_fields_exposed
	StatusCode interface{} `yaml:"status_code,omitempty"` // Can be int or "{{var}}"
	Code       interface{} `yaml:"code,omitempty"`        // gRPC status code
	BodyField  string      `yaml:"body_field,omitempty"`
	Value      interface{} `yaml:"value,omitempty"`
	Pattern    string      `yaml:"pattern,omitempty"`  // For regex_match type indicators
	Patterns   []string    `yaml:"patterns,omitempty"` // For body_contains checks
	Fields     []string    `yaml:"fields,omitempty"`   // For sensitive_fields_exposed type indicators
	Exists     *bool       `yaml:"exists,omitempty"`
	MinMs      int         `yaml:"min_ms,omitempty"`
}

type Condition struct {
	AttackPhaseStatus  []int `yaml:"attack_phase_status,omitempty"`
	VerifyPhaseStatus  []int `yaml:"verify_phase_status,omitempty"`
	VerifyFieldChanged bool  `yaml:"verify_field_changed,omitempty"`
}
