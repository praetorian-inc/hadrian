package graphql

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindingType_String(t *testing.T) {
	tests := []struct {
		findingType FindingType
		expected    string
	}{
		{FindingTypeIntrospectionDisclosure, "introspection-disclosure"},
		{FindingTypeNoDepthLimit, "no-depth-limit"},
		{FindingTypeNoBatchingLimit, "no-batching-limit"},
		{FindingTypeNoComplexityLimit, "no-complexity-limit"},
		{FindingTypeBOLA, "bola"},
		{FindingTypeBFLA, "bfla"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.findingType.String())
		})
	}
}

func TestCategoryConstants(t *testing.T) {
	// Categories use OWASP API Security 2023 format with full descriptions to match template output
	assert.Equal(t, "API1:2023 Broken Object Level Authorization", CategoryAPI1)
	assert.Equal(t, "API4:2023 Unrestricted Resource Consumption", CategoryAPI4)
	assert.Equal(t, "API5:2023 Broken Function Level Authorization", CategoryAPI5)
	assert.Equal(t, "API8:2023 Security Misconfiguration", CategoryAPI8)
}
