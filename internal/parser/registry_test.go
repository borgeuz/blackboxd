package parser

import (
	"errors"
	"strings"
	"testing"
)

// stubParser is a no-op Parser used to exercise Register/Build.
type stubParser struct{ name string }

func (s *stubParser) Name() string { return s.name }
func (s *stubParser) Parse(string) (*LogEntry, error) {
	return nil, errors.New("stub: not implemented")
}

func TestRegisterAndBuild_RoundTrip(t *testing.T) {
	defer resetRegistryForTest(snapshotRegistryForTest())

	Register("__roundtrip", func(map[string]any) (Parser, error) {
		return &stubParser{name: "__roundtrip"}, nil
	})

	p, err := Build("__roundtrip", nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if p.Name() != "__roundtrip" {
		t.Fatalf("Name() = %q, want __roundtrip", p.Name())
	}

	names := RegisteredNames()
	found := false
	for _, n := range names {
		if n == "__roundtrip" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("RegisteredNames missing __roundtrip; got %v", names)
	}
}

func TestBuild_UnknownName(t *testing.T) {
	_, err := Build("__definitely_not_registered__", nil)
	if err == nil {
		t.Fatalf("expected error for unknown parser type")
	}
	if !strings.Contains(err.Error(), "unknown type") {
		t.Fatalf("error message lacks 'unknown type': %v", err)
	}
}

func TestBuild_FactoryError(t *testing.T) {
	defer resetRegistryForTest(snapshotRegistryForTest())

	sentinel := errors.New("sentinel")
	Register("__fac_err", func(map[string]any) (Parser, error) {
		return nil, sentinel
	})

	_, err := Build("__fac_err", nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapping of sentinel, got %v", err)
	}
}

func TestRegister_DuplicatePanics(t *testing.T) {
	defer resetRegistryForTest(snapshotRegistryForTest())

	Register("__dup", func(map[string]any) (Parser, error) {
		return &stubParser{name: "__dup"}, nil
	})

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected panic on duplicate registration")
		}
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, "duplicate registration") {
			t.Fatalf("unexpected panic value: %v", r)
		}
	}()
	Register("__dup", func(map[string]any) (Parser, error) {
		return &stubParser{name: "__dup"}, nil
	})
}

func TestRegister_EmptyNamePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on empty name")
		}
	}()
	Register("", func(map[string]any) (Parser, error) { return &stubParser{}, nil })
}

func TestRegister_NilFactoryPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on nil factory")
		}
	}()
	Register("__nilfac", nil)
}
