package orchestrator

import "sync"

// Tracker tracks resources created during mutation tests.
// Thread-safe for concurrent test execution.
type Tracker struct {
	mu        sync.RWMutex
	resources map[string]string
}

// NewTracker creates a new resource tracker.
func NewTracker() *Tracker {
	return &Tracker{
		resources: make(map[string]string),
	}
}

// StoreResource stores a resource ID by key.
func (t *Tracker) StoreResource(key string, resourceID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.resources[key] = resourceID
}

// GetResource retrieves a stored resource ID.
// Returns empty string if key not found.
func (t *Tracker) GetResource(key string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.resources[key]
}

// Clear removes all tracked resources.
func (t *Tracker) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.resources = make(map[string]string)
}

// GetAllKeys returns all stored resource keys.
// Used for substituting multiple placeholders in paths.
func (t *Tracker) GetAllKeys() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	keys := make([]string, 0, len(t.resources))
	for k := range t.resources {
		keys = append(keys, k)
	}
	return keys
}
