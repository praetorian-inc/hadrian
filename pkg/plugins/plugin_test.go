package plugins

import (
	"sync"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/model"
)

// mockPlugin implements Plugin interface for testing
type mockPlugin struct {
	name     string
	protocol Protocol
	canParse bool
}

func (m *mockPlugin) Name() string {
	return m.name
}

func (m *mockPlugin) Type() Protocol {
	return m.protocol
}

func (m *mockPlugin) CanParse(input []byte, filename string) bool {
	return m.canParse
}

func (m *mockPlugin) Parse(input []byte) (*model.APISpec, error) {
	return &model.APISpec{
		BaseURL: "https://api.example.com",
		Info: model.APIInfo{
			Title:   m.name,
			Version: "1.0.0",
		},
	}, nil
}

func resetRegistry() {
	mu.Lock()
	defer mu.Unlock()
	plugins = make(map[Protocol]Plugin)
}

func TestRegister(t *testing.T) {
	t.Run("register new plugin", func(t *testing.T) {
		resetRegistry()

		mock := &mockPlugin{name: "test", protocol: ProtocolREST}
		Register(ProtocolREST, mock)

		plugin, ok := Get(ProtocolREST)
		if !ok {
			t.Fatal("expected plugin to be registered")
		}
		if plugin.Name() != "test" {
			t.Errorf("expected Name=test, got %s", plugin.Name())
		}
	})

	t.Run("panic on duplicate registration", func(t *testing.T) {
		resetRegistry()

		mock1 := &mockPlugin{name: "first", protocol: ProtocolREST}
		Register(ProtocolREST, mock1)

		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic on duplicate registration")
			}
		}()

		mock2 := &mockPlugin{name: "second", protocol: ProtocolREST}
		Register(ProtocolREST, mock2)
	})

	t.Run("register multiple protocols", func(t *testing.T) {
		resetRegistry()

		Register(ProtocolREST, &mockPlugin{name: "rest", protocol: ProtocolREST})
		Register(ProtocolGraphQL, &mockPlugin{name: "graphql", protocol: ProtocolGraphQL})
		Register(ProtocolGRPC, &mockPlugin{name: "grpc", protocol: ProtocolGRPC})

		if _, ok := Get(ProtocolREST); !ok {
			t.Error("expected REST plugin to be registered")
		}
		if _, ok := Get(ProtocolGraphQL); !ok {
			t.Error("expected GraphQL plugin to be registered")
		}
		if _, ok := Get(ProtocolGRPC); !ok {
			t.Error("expected gRPC plugin to be registered")
		}
	})
}

func TestGet(t *testing.T) {
	t.Run("get existing plugin", func(t *testing.T) {
		resetRegistry()

		mock := &mockPlugin{name: "test", protocol: ProtocolREST}
		Register(ProtocolREST, mock)

		plugin, ok := Get(ProtocolREST)
		if !ok {
			t.Fatal("expected plugin to be found")
		}
		if plugin.Name() != "test" {
			t.Errorf("expected Name=test, got %s", plugin.Name())
		}
	})

	t.Run("get non-existent plugin", func(t *testing.T) {
		resetRegistry()

		_, ok := Get(ProtocolSOAP)
		if ok {
			t.Error("expected plugin not to be found")
		}
	})
}

func TestAll(t *testing.T) {
	t.Run("get all plugins", func(t *testing.T) {
		resetRegistry()

		Register(ProtocolREST, &mockPlugin{name: "rest", protocol: ProtocolREST})
		Register(ProtocolGraphQL, &mockPlugin{name: "graphql", protocol: ProtocolGraphQL})

		all := All()
		if len(all) != 2 {
			t.Errorf("expected 2 plugins, got %d", len(all))
		}

		names := make(map[string]bool)
		for _, plugin := range all {
			names[plugin.Name()] = true
		}

		if !names["rest"] {
			t.Error("expected rest plugin in results")
		}
		if !names["graphql"] {
			t.Error("expected graphql plugin in results")
		}
	})

	t.Run("empty registry", func(t *testing.T) {
		resetRegistry()

		all := All()
		if len(all) != 0 {
			t.Errorf("expected 0 plugins, got %d", len(all))
		}
	})
}

func TestAutoDetect(t *testing.T) {
	t.Run("detect matching plugin", func(t *testing.T) {
		resetRegistry()

		Register(ProtocolREST, &mockPlugin{name: "rest", protocol: ProtocolREST, canParse: true})
		Register(ProtocolGraphQL, &mockPlugin{name: "graphql", protocol: ProtocolGraphQL, canParse: false})

		plugin, ok := AutoDetect([]byte("test"), "test.json")
		if !ok {
			t.Fatal("expected plugin to be detected")
		}
		if plugin.Name() != "rest" {
			t.Errorf("expected rest plugin, got %s", plugin.Name())
		}
	})

	t.Run("no matching plugin", func(t *testing.T) {
		resetRegistry()

		Register(ProtocolREST, &mockPlugin{name: "rest", protocol: ProtocolREST, canParse: false})

		_, ok := AutoDetect([]byte("test"), "test.json")
		if ok {
			t.Error("expected no plugin to be detected")
		}
	})

	t.Run("first matching plugin wins", func(t *testing.T) {
		resetRegistry()

		Register(ProtocolREST, &mockPlugin{name: "rest", protocol: ProtocolREST, canParse: true})
		Register(ProtocolGraphQL, &mockPlugin{name: "graphql", protocol: ProtocolGraphQL, canParse: true})

		plugin, ok := AutoDetect([]byte("test"), "test.json")
		if !ok {
			t.Fatal("expected plugin to be detected")
		}
		// Should match one of them (order not guaranteed in map iteration)
		name := plugin.Name()
		if name != "rest" && name != "graphql" {
			t.Errorf("expected rest or graphql, got %s", name)
		}
	})
}

func TestProtocolConstants(t *testing.T) {
	t.Run("all protocol constants", func(t *testing.T) {
		if ProtocolREST != "rest" {
			t.Errorf("expected rest, got %s", ProtocolREST)
		}
		if ProtocolGraphQL != "graphql" {
			t.Errorf("expected graphql, got %s", ProtocolGraphQL)
		}
		if ProtocolGRPC != "grpc" {
			t.Errorf("expected grpc, got %s", ProtocolGRPC)
		}
		if ProtocolSOAP != "soap" {
			t.Errorf("expected soap, got %s", ProtocolSOAP)
		}
	})
}

// Race detector tests
func TestConcurrentRegistration(t *testing.T) {
	t.Run("concurrent registration of different protocols", func(t *testing.T) {
		resetRegistry()

		var wg sync.WaitGroup
		protocols := []Protocol{ProtocolREST, ProtocolGraphQL, ProtocolGRPC, ProtocolSOAP}

		for i, proto := range protocols {
			wg.Add(1)
			go func(p Protocol, idx int) {
				defer wg.Done()
				mock := &mockPlugin{
					name:     string(p),
					protocol: p,
				}
				Register(p, mock)
			}(proto, i)
		}

		wg.Wait()

		// Verify all registered
		all := All()
		if len(all) != 4 {
			t.Errorf("expected 4 plugins after concurrent registration, got %d", len(all))
		}
	})

	t.Run("concurrent reads while registering", func(t *testing.T) {
		resetRegistry()

		var wg sync.WaitGroup

		// Register plugins concurrently
		wg.Add(2)
		go func() {
			defer wg.Done()
			Register(ProtocolREST, &mockPlugin{name: "rest", protocol: ProtocolREST})
		}()
		go func() {
			defer wg.Done()
			Register(ProtocolGraphQL, &mockPlugin{name: "graphql", protocol: ProtocolGraphQL})
		}()

		// Read plugins concurrently
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				Get(ProtocolREST)
				Get(ProtocolGraphQL)
				All()
			}()
		}

		wg.Wait()
	})

	t.Run("concurrent AutoDetect calls", func(t *testing.T) {
		resetRegistry()

		Register(ProtocolREST, &mockPlugin{name: "rest", protocol: ProtocolREST, canParse: true})
		Register(ProtocolGraphQL, &mockPlugin{name: "graphql", protocol: ProtocolGraphQL, canParse: false})

		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				AutoDetect([]byte("test"), "test.json")
			}()
		}

		wg.Wait()
	})
}
