package ssti

import (
	"net/http"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/injection"
)

// SSTIModule implements injection testing for Server-Side Template Injection
type SSTIModule struct {
	payloads []injection.Payload
}

// NewSSTIModule creates a new SSTI injection testing module
func NewSSTIModule() *SSTIModule {
	return &SSTIModule{
		payloads: defaultPayloads(),
	}
}

// Name returns the module name
func (m *SSTIModule) Name() string {
	return "SSTI"
}

// Type returns the injection type
func (m *SSTIModule) Type() injection.InjectionType {
	return injection.InjectionTypeSSTI
}

// Payloads returns the list of SSTI test payloads
func (m *SSTIModule) Payloads() []injection.Payload {
	return m.payloads
}

// Detect analyzes HTTP response for SSTI vulnerabilities
func (m *SSTIModule) Detect(response *http.Response, body string, payload injection.Payload) injection.DetectionResult {
	result := injection.DetectionResult{
		Detected:  false,
		Payload:   payload.Value,
		Evidence:  "",
		MatchType: "",
	}

	// Error-based detection
	if payload.Expected == "error" {
		if m.detectTemplateError(response, body) {
			result.Detected = true
			result.Evidence = body
			result.MatchType = "error"
			return result
		}
	}

	// Exact match detection
	if strings.Contains(body, payload.Expected) {
		result.Detected = true
		result.Evidence = body
		result.MatchType = "exact"
		return result
	}

	return result
}

// detectTemplateError checks for template engine error messages
func (m *SSTIModule) detectTemplateError(response *http.Response, body string) bool {
	// Check for 500 status code
	if response.StatusCode != http.StatusInternalServerError {
		return false
	}

	// Common template error indicators
	errorIndicators := []string{
		"TemplateSyntaxError",
		"TemplateError",
		"TemplateException",
		"template",
		"syntax error",
		"unexpected end of template",
	}

	bodyLower := strings.ToLower(body)
	for _, indicator := range errorIndicators {
		if strings.Contains(bodyLower, strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}

// defaultPayloads returns the default set of SSTI payloads
func defaultPayloads() []injection.Payload {
	return []injection.Payload{
		// Universal - arithmetic operations
		{
			Value:       "{{7*7}}",
			Expected:    "49",
			Engine:      "universal",
			Description: "Universal arithmetic test (Jinja2, Twig)",
		},
		{
			Value:       "${7*7}",
			Expected:    "49",
			Engine:      "universal",
			Description: "Universal arithmetic test (FreeMarker, Velocity)",
		},
		{
			Value:       "<%= 7*7 %>",
			Expected:    "49",
			Engine:      "universal",
			Description: "Universal arithmetic test (ERB)",
		},

		// Jinja2-specific
		{
			Value:       "{{config}}",
			Expected:    "error",
			Engine:      "jinja2",
			Description: "Jinja2 config object access (error-based)",
		},
		{
			Value:       "{{''.__class__}}",
			Expected:    "str",
			Engine:      "jinja2",
			Description: "Jinja2 class introspection",
		},

		// FreeMarker-specific
		{
			Value:       "<#assign x=7*7>${x}",
			Expected:    "49",
			Engine:      "freemarker",
			Description: "FreeMarker variable assignment",
		},
	}
}
