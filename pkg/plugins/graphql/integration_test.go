//go:build integration
// +build integration

package graphql

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/hadrian/pkg/graphql"
)

func TestIntegration_IntrospectionClient(t *testing.T) {
	endpoint := os.Getenv("DVGA_ENDPOINT")
	if endpoint == "" {
		t.Skip("DVGA_ENDPOINT not set, skipping integration test")
	}

	client := graphql.NewIntrospectionClient(http.DefaultClient, endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	schema, err := client.FetchSchema(ctx)
	require.NoError(t, err)
	assert.NotNil(t, schema)
	assert.True(t, len(schema.Queries) > 0, "should have queries")
}

func TestIntegration_QueryExecution(t *testing.T) {
	endpoint := os.Getenv("DVGA_ENDPOINT")
	if endpoint == "" {
		t.Skip("DVGA_ENDPOINT not set, skipping integration test")
	}

	executor := graphql.NewExecutor(http.DefaultClient, endpoint, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := executor.Execute(ctx, "{ __typename }", nil, "", nil)
	require.NoError(t, err)
	assert.Equal(t, 200, result.StatusCode)
	assert.Contains(t, result.Body, "__typename")
}

func TestIntegration_AuthenticatedRequest(t *testing.T) {
	endpoint := os.Getenv("DVGA_ENDPOINT")
	if endpoint == "" {
		t.Skip("DVGA_ENDPOINT not set, skipping integration test")
	}

	token := os.Getenv("DVGA_ADMIN_TOKEN")
	if token == "" {
		t.Skip("DVGA_ADMIN_TOKEN not set, skipping authenticated test")
	}

	executor := graphql.NewExecutor(http.DefaultClient, endpoint, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	authInfo := &graphql.AuthInfo{
		Method: "bearer",
		Value:  "Bearer " + token,
	}

	query := `query { systemHealth }`
	result, err := executor.Execute(ctx, query, nil, "", authInfo)
	require.NoError(t, err)
	assert.Equal(t, 200, result.StatusCode)
}

func TestIntegration_SchemaDiscovery(t *testing.T) {
	endpoint := os.Getenv("DVGA_ENDPOINT")
	if endpoint == "" {
		t.Skip("DVGA_ENDPOINT not set, skipping integration test")
	}

	client := graphql.NewIntrospectionClient(http.DefaultClient, endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	schema, err := client.FetchSchema(ctx)
	require.NoError(t, err)

	// Verify expected DVGA operations exist
	hasUsersQuery := false
	hasPastesQuery := false
	for _, q := range schema.Queries {
		if q.Name == "users" {
			hasUsersQuery = true
		}
		if q.Name == "pastes" {
			hasPastesQuery = true
		}
	}

	assert.True(t, hasUsersQuery, "should have users query")
	assert.True(t, hasPastesQuery, "should have pastes query")

	// Verify mutations exist
	hasCreatePaste := false
	for _, m := range schema.Mutations {
		if m.Name == "createPaste" {
			hasCreatePaste = true
		}
	}
	assert.True(t, hasCreatePaste, "should have createPaste mutation")
}
