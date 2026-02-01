package injection

import "net/http"

// InjectionType represents the type of injection attack
type InjectionType string

const (
	InjectionTypeXSS             InjectionType = "xss"
	InjectionTypeSSRF            InjectionType = "ssrf"
	InjectionTypeSSTI            InjectionType = "ssti"
	InjectionTypeDeserialization InjectionType = "deserialization"
)

// String returns the string representation of InjectionType
func (t InjectionType) String() string {
	return string(t)
}

// Payload represents an injection test payload
type Payload struct {
	Value       string // The payload to inject
	Expected    string // Expected response indicating vulnerability
	Engine      string // Target template engine (for SSTI)
	Description string // Human-readable description
}

// IsValid checks if payload has required fields
func (p Payload) IsValid() bool {
	return p.Value != "" && p.Expected != ""
}

// DetectionResult represents the result of injection detection
type DetectionResult struct {
	Detected  bool   // Whether injection was detected
	Payload   string // The payload that succeeded
	Evidence  string // Evidence from response
	MatchType string // Type of match (exact, encoded, error)
}

// Config holds configuration for injection testing
type Config struct {
	MaxPayloadsPerTest int // Maximum number of payloads to test per endpoint
	TimeoutSeconds     int // Timeout for individual tests
}

// Module defines the interface for injection testing modules
type Module interface {
	// Name returns the module name
	Name() string

	// Type returns the injection type this module tests for
	Type() InjectionType

	// Payloads returns the list of test payloads
	Payloads() []Payload

	// Detect analyzes an HTTP response for injection vulnerabilities
	Detect(response *http.Response, body string, payload Payload) DetectionResult
}
