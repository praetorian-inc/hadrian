package templates

import (
	"container/list"
	"sync"
)

// Cache stores compiled templates with LRU eviction
type Cache struct {
	capacity int
	cache    map[string]*cacheEntry
	lru      *list.List
	mu       sync.RWMutex
}

type cacheEntry struct {
	key      string
	template *CompiledTemplate
	element  *list.Element
}

// NewCache creates a new template cache with specified capacity
func NewCache(capacity int) *Cache {
	return &Cache{
		capacity: capacity,
		cache:    make(map[string]*cacheEntry),
		lru:      list.New(),
	}
}

// Get retrieves compiled template from cache
func (c *Cache) Get(key string) (*CompiledTemplate, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.cache[key]; ok {
		// Move to front (most recently used)
		c.lru.MoveToFront(entry.element)
		return entry.template, true
	}

	return nil, false
}

// Put adds compiled template to cache
func (c *Cache) Put(key string, template *CompiledTemplate) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update if exists
	if entry, ok := c.cache[key]; ok {
		entry.template = template
		c.lru.MoveToFront(entry.element)
		return
	}

	// Evict if at capacity
	if c.lru.Len() >= c.capacity {
		oldest := c.lru.Back()
		if oldest != nil {
			c.lru.Remove(oldest)
			delete(c.cache, oldest.Value.(*cacheEntry).key)
		}
	}

	// Add new entry
	entry := &cacheEntry{
		key:      key,
		template: template,
	}
	element := c.lru.PushFront(entry)
	entry.element = element
	c.cache[key] = entry
}
