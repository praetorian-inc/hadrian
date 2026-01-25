package plugins

import (
	"sync"

	"github.com/praetorian-inc/hadrian/pkg/model"
)

// Protocol types
type Protocol string

const (
	ProtocolREST    Protocol = "rest"
	ProtocolGraphQL Protocol = "graphql"  // v1.5
	ProtocolGRPC    Protocol = "grpc"     // v2.0
	ProtocolSOAP    Protocol = "soap"     // v2.0+
)

// Plugin parses protocol-specific API definitions to internal model
type Plugin interface {
	Name() string
	Type() Protocol
	CanParse(input []byte, filename string) bool
	Parse(input []byte) (*model.APISpec, error)
}

// Thread-safe plugin registry (from fingerprintx pattern)
var (
	mu      sync.RWMutex
	plugins = make(map[Protocol]Plugin)
)

// Register adds a plugin to the registry
func Register(proto Protocol, plugin Plugin) {
	mu.Lock()
	defer mu.Unlock()

	if _, exists := plugins[proto]; exists {
		panic("plugin already registered: " + string(proto))
	}

	plugins[proto] = plugin
}

// Get retrieves a plugin by protocol
func Get(proto Protocol) (Plugin, bool) {
	mu.RLock()
	defer mu.RUnlock()

	plugin, ok := plugins[proto]
	return plugin, ok
}

// All returns all registered plugins
func All() []Plugin {
	mu.RLock()
	defer mu.RUnlock()

	all := make([]Plugin, 0, len(plugins))
	for _, plugin := range plugins {
		all = append(all, plugin)
	}
	return all
}

// AutoDetect attempts to detect protocol from input
func AutoDetect(input []byte, filename string) (Plugin, bool) {
	mu.RLock()
	defer mu.RUnlock()

	for _, plugin := range plugins {
		if plugin.CanParse(input, filename) {
			return plugin, true
		}
	}

	return nil, false
}
