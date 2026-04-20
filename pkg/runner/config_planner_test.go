package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate_PlannerOnlyWithoutPlanner(t *testing.T) {
	c := validTestConfig()
	c.PlannerOnly = true
	c.PlannerEnabled = false

	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--planner-only requires --planner")
}

func TestValidate_PlannerOnlyWithPlanner(t *testing.T) {
	c := validTestConfig()
	c.PlannerOnly = true
	c.PlannerEnabled = true

	err := c.Validate()
	assert.NoError(t, err)
}

func TestSetDefaults_PlannerTimeoutZero(t *testing.T) {
	c := &Config{PlannerTimeout: 0}
	c.setDefaults()
	assert.Equal(t, 120, c.PlannerTimeout)
}

func TestSetDefaults_PlannerTimeoutNegative(t *testing.T) {
	c := &Config{PlannerTimeout: -1}
	c.setDefaults()
	assert.Equal(t, 120, c.PlannerTimeout)
}

func TestSetDefaults_PlannerTimeoutPositive(t *testing.T) {
	c := &Config{PlannerTimeout: 60}
	c.setDefaults()
	assert.Equal(t, 60, c.PlannerTimeout) // should not override
}

// validTestConfig returns a Config that passes Validate() for use as a base.
func validTestConfig() Config {
	// Create temp files for API and Roles since Validate checks os.Stat
	return Config{
		API:                  "../../test/crapi/crapi-openapi-spec.json",
		Roles:                "../../test/crapi/roles.yaml",
		Output:               "terminal",
		RateLimit:            5.0,
		RateLimitBackoff:     "exponential",
		RateLimitMaxWait:     60e9, // 60s as Duration
		RateLimitMaxRetries:  5,
		RateLimitStatusCodes: []int{429, 503},
	}
}
