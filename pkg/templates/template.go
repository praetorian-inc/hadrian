package templates

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

	// Detection logic
	Detection Detection `yaml:"detection"`
}

type TemplateInfo struct {
	Name              string   `yaml:"name"`
	Category          string   `yaml:"category"`
	Severity          string   `yaml:"severity"`
	Author            string   `yaml:"author"`
	Tags              []string `yaml:"tags"`
	RequiresLLMTriage bool     `yaml:"requires_llm_triage"`
	TestPattern       string   `yaml:"test_pattern"`
}

type EndpointSelector struct {
	HasPathParameter bool     `yaml:"has_path_parameter"`
	RequiresAuth     bool     `yaml:"requires_auth"`
	Methods          []string `yaml:"methods"`
	ReturnsObject    bool     `yaml:"returns_object"`
	PathPattern      string   `yaml:"path_pattern,omitempty"`
	Tags             []string `yaml:"tags,omitempty"`
}

type RoleSelector struct {
	AttackerPermissionLevel string `yaml:"attacker_permission_level"` // lower, higher, all
	VictimPermissionLevel   string `yaml:"victim_permission_level"`
}

type TestPhases struct {
	Setup  *Phase `yaml:"setup"`
	Attack *Phase `yaml:"attack"`
	Verify *Phase `yaml:"verify"`
}

type Phase struct {
	Operation          string            `yaml:"operation"`                     // create, read, update, delete
	Auth               string            `yaml:"auth"`                          // attacker, victim
	Data               map[string]string `yaml:"data,omitempty"`                // Request body data
	StoreResponseField string            `yaml:"store_response_field,omitempty"` // Field to store
	UseStoredField     string            `yaml:"use_stored_field,omitempty"`     // Use stored value
	CheckField         string            `yaml:"check_field,omitempty"`          // Field to verify
	ExpectedValue      string            `yaml:"expected_value,omitempty"`       // Expected value
	ExpectedStatus     int               `yaml:"expected_status,omitempty"`
}

type HTTPTest struct {
	Method  string            `yaml:"method"`
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
	Body    string            `yaml:"body,omitempty"`

	Matchers []Matcher `yaml:"matchers"`
}

type Matcher struct {
	Type      string   `yaml:"type"`  // word, regex, status, size, dsl
	Words     []string `yaml:"words,omitempty"`
	Regex     []string `yaml:"regex,omitempty"`
	Status    []int    `yaml:"status,omitempty"`
	Part      string   `yaml:"part,omitempty"`      // body, header, all
	Condition string   `yaml:"condition,omitempty"` // and, or
}

type Detection struct {
	SuccessIndicators    []Indicator `yaml:"success_indicators"`
	VulnerabilityPattern string      `yaml:"vulnerability_pattern"`
	Conditions           []Condition `yaml:"conditions"`
	ResourceShouldExist  *bool       `yaml:"resource_should_exist,omitempty"`
	ResourceDeleted      *bool       `yaml:"resource_deleted,omitempty"`
}

type Indicator struct {
	Type       string      `yaml:"type,omitempty"`        // status_code, body_field
	StatusCode interface{} `yaml:"status_code,omitempty"` // Can be int or "{{var}}"
	BodyField  string      `yaml:"body_field,omitempty"`
	Value      interface{} `yaml:"value,omitempty"`
	Exists     *bool       `yaml:"exists,omitempty"`
}

type Condition struct {
	AttackPhaseStatus  []int `yaml:"attack_phase_status,omitempty"`
	VerifyPhaseStatus  []int `yaml:"verify_phase_status,omitempty"`
	VerifyFieldChanged bool  `yaml:"verify_field_changed,omitempty"`
}
