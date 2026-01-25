package templates

import (
	"sync"
	"testing"
)

// TestNewCache tests cache creation
func TestNewCache(t *testing.T) {
	cache := NewCache(10)

	if cache == nil {
		t.Fatal("NewCache() returned nil")
	}

	if cache.capacity != 10 {
		t.Errorf("capacity: got %d, want %d", cache.capacity, 10)
	}
}

// TestCache_GetMiss tests cache miss behavior
func TestCache_GetMiss(t *testing.T) {
	cache := NewCache(5)

	result, ok := cache.Get("nonexistent")
	if ok {
		t.Error("Get() should return false for missing key")
	}

	if result != nil {
		t.Error("Get() should return nil for missing key")
	}
}

// TestCache_PutAndGet tests basic put and get operations
func TestCache_PutAndGet(t *testing.T) {
	cache := NewCache(5)

	tmpl := &Template{ID: "test-template"}
	compiled := &CompiledTemplate{Template: tmpl}

	cache.Put("key1", compiled)

	result, ok := cache.Get("key1")
	if !ok {
		t.Fatal("Get() should return true for existing key")
	}

	if result == nil {
		t.Fatal("Get() should return template for existing key")
	}

	if result.Template.ID != "test-template" {
		t.Errorf("Template ID: got %q, want %q", result.Template.ID, "test-template")
	}
}

// TestCache_LRUEviction tests that cache evicts least recently used items at capacity
func TestCache_LRUEviction(t *testing.T) {
	cache := NewCache(3)

	// Add 3 items (fill to capacity)
	cache.Put("key1", &CompiledTemplate{Template: &Template{ID: "tmpl1"}})
	cache.Put("key2", &CompiledTemplate{Template: &Template{ID: "tmpl2"}})
	cache.Put("key3", &CompiledTemplate{Template: &Template{ID: "tmpl3"}})

	// Add 4th item - should evict key1 (oldest, no access)
	cache.Put("key4", &CompiledTemplate{Template: &Template{ID: "tmpl4"}})

	// Verify key1 was evicted
	if _, ok := cache.Get("key1"); ok {
		t.Error("key1 should be evicted after adding 4th item")
	}

	// Verify others still exist
	if _, ok := cache.Get("key2"); !ok {
		t.Error("key2 should still exist")
	}
	if _, ok := cache.Get("key3"); !ok {
		t.Error("key3 should still exist")
	}
	if _, ok := cache.Get("key4"); !ok {
		t.Error("key4 should exist")
	}
}

// TestCache_UpdateExisting tests updating an existing cache entry
func TestCache_UpdateExisting(t *testing.T) {
	cache := NewCache(5)

	tmpl1 := &CompiledTemplate{Template: &Template{ID: "original"}}
	cache.Put("key1", tmpl1)

	tmpl2 := &CompiledTemplate{Template: &Template{ID: "updated"}}
	cache.Put("key1", tmpl2)

	result, ok := cache.Get("key1")
	if !ok {
		t.Fatal("Get() should return true for updated key")
	}

	if result.Template.ID != "updated" {
		t.Errorf("Template ID: got %q, want %q", result.Template.ID, "updated")
	}
}

// TestCache_ConcurrentAccess tests thread safety with race detector
func TestCache_ConcurrentAccess(t *testing.T) {
	cache := NewCache(10)

	var wg sync.WaitGroup
	concurrency := 50

	// Concurrent writes
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := "key"
			tmpl := &CompiledTemplate{Template: &Template{ID: "concurrent-test"}}
			cache.Put(key, tmpl)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cache.Get("key")
		}(i)
	}

	wg.Wait()
}

// TestCache_MoveToFront tests LRU ordering on access
func TestCache_MoveToFront(t *testing.T) {
	cache := NewCache(3)

	// Add 3 items
	cache.Put("key1", &CompiledTemplate{Template: &Template{ID: "tmpl1"}})
	cache.Put("key2", &CompiledTemplate{Template: &Template{ID: "tmpl2"}})
	cache.Put("key3", &CompiledTemplate{Template: &Template{ID: "tmpl3"}})

	// Access key1 (moves to front)
	cache.Get("key1")

	// Add 4th item - should evict key2 (now oldest, not key1)
	cache.Put("key4", &CompiledTemplate{Template: &Template{ID: "tmpl4"}})

	// Verify key1 still exists (was moved to front by Get)
	if _, ok := cache.Get("key1"); !ok {
		t.Error("key1 should still exist after being accessed")
	}

	// Verify key2 was evicted
	if _, ok := cache.Get("key2"); ok {
		t.Error("key2 should be evicted as least recently used")
	}

	// Verify others still exist
	if _, ok := cache.Get("key3"); !ok {
		t.Error("key3 should still exist")
	}
	if _, ok := cache.Get("key4"); !ok {
		t.Error("key4 should exist")
	}
}
