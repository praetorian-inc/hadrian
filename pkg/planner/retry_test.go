package planner

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		code      int
		retryable bool
	}{
		{408, true}, {429, true}, {500, true}, {502, true}, {503, true}, {504, true},
		{401, false}, {403, false}, {404, false}, {422, false}, {200, false},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("status_%d", tc.code), func(t *testing.T) {
			err := &APIError{StatusCode: tc.code, Message: "test"}
			assert.Equal(t, tc.retryable, isRetryable(err))
		})
	}
}

func TestIsRetryable_NetworkError(t *testing.T) {
	// Non-APIError (e.g., connection refused) should be retryable
	err := fmt.Errorf("connection refused")
	assert.True(t, isRetryable(err))
}

func TestRetryGenerate_SuccessFirstAttempt(t *testing.T) {
	orig := retryBackoffs
	retryBackoffs = []time.Duration{1 * time.Millisecond}
	defer func() { retryBackoffs = orig }()

	client := &sequenceMockClient{responses: []mockResponse{{result: "ok", err: nil}}}
	result, err := RetryGenerate(context.Background(), client, "prompt")
	require.NoError(t, err)
	assert.Equal(t, "ok", result)
	assert.Equal(t, 1, client.calls)
}

func TestRetryGenerate_RetriesOnRetryableError(t *testing.T) {
	orig := retryBackoffs
	retryBackoffs = []time.Duration{1 * time.Millisecond, 1 * time.Millisecond}
	defer func() { retryBackoffs = orig }()

	client := &sequenceMockClient{responses: []mockResponse{
		{err: &APIError{StatusCode: 429, Message: "rate limited"}},
		{err: &APIError{StatusCode: 503, Message: "unavailable"}},
		{result: "ok", err: nil},
	}}
	result, err := RetryGenerate(context.Background(), client, "prompt")
	require.NoError(t, err)
	assert.Equal(t, "ok", result)
	assert.Equal(t, 3, client.calls)
}

func TestRetryGenerate_NoRetryOnPermanentError(t *testing.T) {
	orig := retryBackoffs
	retryBackoffs = []time.Duration{1 * time.Millisecond}
	defer func() { retryBackoffs = orig }()

	client := &sequenceMockClient{responses: []mockResponse{
		{err: &APIError{StatusCode: 401, Message: "bad key"}},
	}}
	_, err := RetryGenerate(context.Background(), client, "prompt")
	require.Error(t, err)
	assert.Equal(t, 1, client.calls) // no retry
	assert.Contains(t, err.Error(), "bad key")
}

func TestRetryGenerate_ContextCancellation(t *testing.T) {
	orig := retryBackoffs
	retryBackoffs = []time.Duration{5 * time.Second}
	defer func() { retryBackoffs = orig }()

	// Pre-cancel the context for determinism (no timing race)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client := &sequenceMockClient{responses: []mockResponse{
		{err: &APIError{StatusCode: 429, Message: "rate limited"}},
	}}

	_, err := RetryGenerate(ctx, client, "prompt")
	require.Error(t, err)
	assert.Equal(t, 1, client.calls) // should not retry after cancel
}

func TestRetryGenerate_ExhaustsRetries(t *testing.T) {
	orig := retryBackoffs
	retryBackoffs = []time.Duration{1 * time.Millisecond, 1 * time.Millisecond}
	defer func() { retryBackoffs = orig }()

	client := &sequenceMockClient{responses: []mockResponse{
		{err: &APIError{StatusCode: 500, Message: "err1"}},
		{err: &APIError{StatusCode: 500, Message: "err2"}},
		{err: &APIError{StatusCode: 500, Message: "err3"}},
	}}
	_, err := RetryGenerate(context.Background(), client, "prompt")
	require.Error(t, err)
	assert.Equal(t, 3, client.calls)
	assert.Contains(t, err.Error(), "err3")
}

// sequenceMockClient returns responses in order, cycling the last one if exhausted.
type sequenceMockClient struct {
	responses []mockResponse
	calls     int
}

type mockResponse struct {
	result string
	err    error
}

func (m *sequenceMockClient) Generate(_ context.Context, _ string) (string, error) {
	idx := m.calls
	if idx >= len(m.responses) {
		idx = len(m.responses) - 1
	}
	m.calls++
	return m.responses[idx].result, m.responses[idx].err
}
