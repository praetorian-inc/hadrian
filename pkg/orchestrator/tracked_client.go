package orchestrator

import (
	"net/http"
	"sync"

	"github.com/praetorian-inc/hadrian/pkg/util"
)

// TrackedHTTPClient wraps an HTTPClient to add request ID tracking
type TrackedHTTPClient struct {
	client     HTTPClient
	mu         sync.Mutex
	requestIDs []string
}

// NewTrackedHTTPClient creates a new tracked client wrapper
func NewTrackedHTTPClient(client HTTPClient) *TrackedHTTPClient {
	return &TrackedHTTPClient{
		client:     client,
		requestIDs: make([]string, 0),
	}
}

// Do executes the request with a unique request ID header
func (t *TrackedHTTPClient) Do(req *http.Request) (*http.Response, error) {
	requestID := util.GenerateRequestID()
	req.Header.Set("X-Hadrian-Request-Id", requestID)
	t.mu.Lock()
	t.requestIDs = append(t.requestIDs, requestID)
	t.mu.Unlock()
	return t.client.Do(req)
}

// GetRequestIDs returns all tracked request IDs
func (t *TrackedHTTPClient) GetRequestIDs() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	ids := make([]string, len(t.requestIDs))
	copy(ids, t.requestIDs)
	return ids
}

// ClearRequestIDs clears the tracked request IDs
func (t *TrackedHTTPClient) ClearRequestIDs() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.requestIDs = make([]string, 0)
}

