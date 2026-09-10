package templates

import (
	"gopkg.in/yaml.v3"
)

// Template represents a parsed YAML test template
type Template struct {
	ID   string       `yaml:"id"`
	Info TemplateInfo `yaml:"info"`

	// FilePath is the source path the template was loaded from. It is set by the
	// loader (not the YAML); yaml:"-" keeps the strict decoder (KnownFields)
	// from treating it as an input key. The GraphQL loader copies it to
	// CompiledTemplate.FilePath so helpUri resolution and duplicate-id
	// diagnostics work the same as for REST/gRPC.
	FilePath string `yaml:"-"`

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

	// CacheDeception config (only consumed for test_pattern: "cache-deception")
	CacheDeception *CacheDeception `yaml:"cache_deception,omitempty"`
}

// CacheDeception configures the two-phase self-priming Web Cache Deception test
// (test_pattern: "cache-deception"). None of the existing Phase fields model an
// operation-driven prime-repeat count, a cache-HIT header pattern set, or a
// canary strategy, so a dedicated block is required.
type CacheDeception struct {
	// PrimeRole is the EXACT roles.yaml/auth.yaml role name whose authenticated
	// session primes the cache. It MUST name a self-scoped canary account whose
	// response embeds no real third-party PII: the prime writes that account's
	// authenticated response into a SHARED cache. The dispatch resolves only this
	// named role and SKIPs (with a warning) when it is unset or not
	// authenticatable — it never guesses a role, so a privileged account is never
	// selected implicitly and no privileged data is written to a shared cache.
	PrimeRole string `yaml:"prime_role,omitempty"`

	// PrimeRepeat is the number of authenticated GETs sent to warm the cache
	// before the anonymous replay. Default 2 (warms cache-on-second-hit CDNs).
	// Values < 1 fall back to the default; values above the internal cap are
	// clamped down to it (DoS guard).
	PrimeRepeat int `yaml:"prime_repeat,omitempty"`

	// CanaryField is the JSON path (dot/array notation, per extractField) of a
	// stable, self-scoped value in the authenticated body that must appear in the
	// anonymous body to prove the victim's cached content leaked. Empty selects
	// the exact body-equality fallback.
	CanaryField string `yaml:"canary_field,omitempty"`

	// CacheHitHeaders are regexes matched (per-header, over "Header: value") to
	// confirm an explicit CDN cache HIT. Empty selects the two built-in defaults
	// (CF-Cache-Status HIT, X-Cache ...HIT).
	CacheHitHeaders []string `yaml:"cache_hit_headers,omitempty"`
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

	// Parameter-scoped selection: target endpoints where the user/owner identity
	// is carried in a query parameter or request-body field rather than the path.
	HasQueryParameter   bool     `yaml:"has_query_parameter"`             // operation has >=1 query parameter
	HasBodyField        bool     `yaml:"has_body_field"`                  // operation has a request body with >=1 field
	QueryParameterNames []string `yaml:"query_parameter_names,omitempty"` // match ops with a query param named one of these (case-insensitive)
	BodyFieldNames      []string `yaml:"body_field_names,omitempty"`      // match ops whose request body has a field named one of these (case-insensitive)
}

type RoleSelector struct {
	AttackerPermissionLevel string `yaml:"attacker_permission_level"` // lower, higher, all, none
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
	Operation           string            `yaml:"operation"`                       // create, read, update, delete, patch, write
	Auth                string            `yaml:"auth"`                            // attacker, victim
	Data                map[string]string `yaml:"data,omitempty"`                  // Request body data (gRPC; flat key/value map)
	Body                string            `yaml:"body,omitempty"`                  // Raw request body (REST). Supports {alias} placeholder substitution from stored fields.
	ContentType         string            `yaml:"content_type,omitempty"`          // Content-Type header for Body; defaults to application/json
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
