package parser

import (
	"fmt"
	"sort"
	"sync"
)

// Factory builds a Parser from its config block. Generic map so each
// parser type can have its own option keys.
type Factory func(config map[string]any) (Parser, error)

// Inline initialisation (not via init()) because Go does not guarantee
// init() ordering across files within a package, and the per-format
// files register themselves from their own init().
var (
	registry = map[string]Factory{}
	regMu    sync.RWMutex
)

// Register adds a factory under name. Duplicates panic — that's always
// a programming error.
func Register(name string, f Factory) {
	if name == "" {
		panic("parser.Register: empty name")
	}
	if f == nil {
		panic("parser.Register: nil Factory for " + name)
	}
	regMu.Lock()
	defer regMu.Unlock()
	if _, exists := registry[name]; exists {
		panic("parser.Register: duplicate registration for " + name)
	}
	registry[name] = f
}

// Build returns an error (not a panic) for unknown names — that path
// is reached by user config, not by code.
func Build(name string, config map[string]any) (Parser, error) {
	regMu.RLock()
	f, ok := registry[name]
	regMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("parser: unknown type %q (known: %v)", name, RegisteredNames())
	}
	return f(config)
}

// RegisteredNames returns the registered type names, sorted.
func RegisteredNames() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// resetRegistryForTest / snapshotRegistryForTest let tests that
// exercise Register restore the global state for the rest of the suite.
func resetRegistryForTest(snapshot map[string]Factory) {
	regMu.Lock()
	defer regMu.Unlock()
	registry = make(map[string]Factory, len(snapshot))
	for k, v := range snapshot {
		registry[k] = v
	}
}

func snapshotRegistryForTest() map[string]Factory {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make(map[string]Factory, len(registry))
	for k, v := range registry {
		out[k] = v
	}
	return out
}
