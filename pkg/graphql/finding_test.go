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
	assert.Equal(t, "API3", CategoryAPI3)
	assert.Equal(t, "API4", CategoryAPI4)
	assert.Equal(t, "API5", CategoryAPI5)
	assert.Equal(t, "API1", CategoryAPI1)
}
