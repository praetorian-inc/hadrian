package injection

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInjectionType_String(t *testing.T) {
	tests := []struct {
		name     string
		injType  InjectionType
		expected string
	}{
		{
			name:     "XSS type",
			injType:  InjectionTypeXSS,
			expected: "xss",
		},
		{
			name:     "SSRF type",
			injType:  InjectionTypeSSRF,
			expected: "ssrf",
		},
		{
			name:     "SSTI type",
			injType:  InjectionTypeSSTI,
			expected: "ssti",
		},
		{
			name:     "Deserialization type",
			injType:  InjectionTypeDeserialization,
			expected: "deserialization",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.injType.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPayload_IsValid(t *testing.T) {
	tests := []struct {
		name    string
		payload Payload
		valid   bool
	}{
		{
			name: "valid payload",
			payload: Payload{
				Value:       "{{7*7}}",
				Expected:    "49",
				Engine:      "jinja2",
				Description: "Basic arithmetic test",
			},
			valid: true,
		},
		{
			name: "empty value",
			payload: Payload{
				Value:       "",
				Expected:    "49",
				Engine:      "jinja2",
				Description: "Basic arithmetic test",
			},
			valid: false,
		},
		{
			name: "empty expected",
			payload: Payload{
				Value:       "{{7*7}}",
				Expected:    "",
				Engine:      "jinja2",
				Description: "Basic arithmetic test",
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.payload.IsValid()
			assert.Equal(t, tt.valid, result)
		})
	}
}
