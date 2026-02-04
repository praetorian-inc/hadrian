//go:build integration

package runner

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGraphQL_OOB_DVGA_SSRF(t *testing.T) {
	endpoint := os.Getenv("DVGA_ENDPOINT")
	if endpoint == "" {
		t.Skip("DVGA_ENDPOINT not set")
	}

	config := GraphQLConfig{
		Target:          endpoint,
		Endpoint:        "/graphql",
		Templates:       "../../testdata/dvga/templates/owasp",
		TemplateFilters: []string{"api7-ssrf-dvga"},
		EnableOOB:       true,
		OOBTimeout:      15,
		AllowInternal:   true,
		Timeout:         30,
		Verbose:         true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Run the GraphQL test - should not error
	// (actual OOB detection depends on DVGA being vulnerable)
	err := runGraphQLTest(ctx, config)
	require.NoError(t, err)
}
