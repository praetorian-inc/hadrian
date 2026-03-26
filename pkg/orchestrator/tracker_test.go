package orchestrator

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTracker(t *testing.T) {
	tracker := NewTracker()

	require.NotNil(t, tracker, "NewTracker should return non-nil tracker")
}

func TestTracker_StoreAndGetResource(t *testing.T) {
	tracker := NewTracker()

	// Store a resource
	tracker.StoreResource("resource_id", "12345")

	// Retrieve it
	got := tracker.GetResource("resource_id")
	assert.Equal(t, "12345", got, "GetResource should return stored value")
}

func TestTracker_GetResource_NotFound(t *testing.T) {
	tracker := NewTracker()

	// Get non-existent resource
	got := tracker.GetResource("nonexistent")
	assert.Equal(t, "", got, "GetResource should return empty string for non-existent key")
}

func TestTracker_StoreResource_Overwrites(t *testing.T) {
	tracker := NewTracker()

	// Store initial value
	tracker.StoreResource("resource_id", "initial")

	// Overwrite
	tracker.StoreResource("resource_id", "updated")

	got := tracker.GetResource("resource_id")
	assert.Equal(t, "updated", got, "StoreResource should overwrite existing value")
}

func TestTracker_MultipleResources(t *testing.T) {
	tracker := NewTracker()

	tracker.StoreResource("id1", "value1")
	tracker.StoreResource("id2", "value2")
	tracker.StoreResource("id3", "value3")

	assert.Equal(t, "value1", tracker.GetResource("id1"))
	assert.Equal(t, "value2", tracker.GetResource("id2"))
	assert.Equal(t, "value3", tracker.GetResource("id3"))
}

func TestTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewTracker()

	var wg sync.WaitGroup
	iterations := 100

	// Concurrent writes
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := "key"
			value := "value"
			tracker.StoreResource(key, value)
			_ = tracker.GetResource(key)
		}(i)
	}

	wg.Wait()

	// Should not panic and should have the value
	got := tracker.GetResource("key")
	assert.Equal(t, "value", got, "Should handle concurrent access without data corruption")
}

func TestTracker_Clear(t *testing.T) {
	tracker := NewTracker()

	tracker.StoreResource("id1", "value1")
	tracker.StoreResource("id2", "value2")

	tracker.Clear()

	assert.Equal(t, "", tracker.GetResource("id1"), "Clear should remove all resources")
	assert.Equal(t, "", tracker.GetResource("id2"), "Clear should remove all resources")
}
