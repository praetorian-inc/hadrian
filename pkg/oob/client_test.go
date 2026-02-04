package oob

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	client, err := NewClient(DefaultConfig())
	require.NoError(t, err)
	require.NotNil(t, client)
	defer client.Close()
}

func TestClient_GenerateURL(t *testing.T) {
	client, err := NewClient(DefaultConfig())
	require.NoError(t, err)
	defer client.Close()

	url := client.GenerateURL()
	assert.NotEmpty(t, url)
	assert.Contains(t, url, ".") // Has subdomain
}

func TestClient_Poll_NoInteraction(t *testing.T) {
	client, err := NewClient(DefaultConfig())
	require.NoError(t, err)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	interactions, err := client.Poll(ctx)
	require.NoError(t, err)
	assert.Empty(t, interactions) // No interactions yet
}
