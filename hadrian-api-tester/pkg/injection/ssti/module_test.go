package ssti

import (
	"net/http"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/injection"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSTIModule_Name(t *testing.T) {
	module := NewSSTIModule()
	assert.Equal(t, "SSTI", module.Name())
}

func TestSSTIModule_Type(t *testing.T) {
	module := NewSSTIModule()
	assert.Equal(t, injection.InjectionTypeSSTI, module.Type())
}

func TestSSTIModule_Payloads(t *testing.T) {
	module := NewSSTIModule()
	payloads := module.Payloads()

	require.NotEmpty(t, payloads, "SSTI module should have payloads")

	// Verify all payloads are valid
	for _, payload := range payloads {
		assert.True(t, payload.IsValid(), "All payloads should be valid")
	}

	// Verify we have payloads for different engines
	engines := make(map[string]bool)
	for _, payload := range payloads {
		engines[payload.Engine] = true
	}

	assert.True(t, engines["universal"], "Should have universal payloads")
	assert.True(t, engines["jinja2"], "Should have Jinja2 payloads")
	assert.True(t, engines["freemarker"], "Should have FreeMarker payloads")
}

func TestSSTIModule_Detect_ExactMatch(t *testing.T) {
	module := NewSSTIModule()

	// Create response with payload output
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}
	body := "Result: 49"

	payload := injection.Payload{
		Value:       "{{7*7}}",
		Expected:    "49",
		Engine:      "jinja2",
		Description: "Basic arithmetic",
	}

	result := module.Detect(resp, body, payload)

	assert.True(t, result.Detected, "Should detect SSTI when expected value is in response")
	assert.Equal(t, payload.Value, result.Payload)
	assert.Contains(t, result.Evidence, "49")
	assert.Equal(t, "exact", result.MatchType)
}

func TestSSTIModule_Detect_NoMatch(t *testing.T) {
	module := NewSSTIModule()

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}
	body := "Result: {{7*7}}"

	payload := injection.Payload{
		Value:       "{{7*7}}",
		Expected:    "49",
		Engine:      "jinja2",
		Description: "Basic arithmetic",
	}

	result := module.Detect(resp, body, payload)

	assert.False(t, result.Detected, "Should not detect when payload is not executed")
}

func TestSSTIModule_Detect_ErrorBased(t *testing.T) {
	module := NewSSTIModule()

	resp := &http.Response{
		StatusCode: http.StatusInternalServerError,
		Header:     make(http.Header),
	}
	body := "TemplateSyntaxError: unexpected 'end of template'"

	payload := injection.Payload{
		Value:       "{{config}}",
		Expected:    "error",
		Engine:      "jinja2",
		Description: "Error-based detection",
	}

	result := module.Detect(resp, body, payload)

	assert.True(t, result.Detected, "Should detect SSTI from template error")
	assert.Equal(t, "error", result.MatchType)
}
