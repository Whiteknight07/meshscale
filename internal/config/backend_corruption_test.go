package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNullBackendStateFailsClosed(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "backend.json"), []byte(" \nnull\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBackend(); err == nil {
		t.Fatal("null backend state silently restored defaults")
	}
	if !Paused() {
		t.Fatal("corrupt backend state allowed automatic reconnection")
	}
}

func TestNullMeshStateIsRejected(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mesh-state.json"), []byte("null"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMeshState(); err == nil {
		t.Fatal("null Mesh association state silently discarded verified links")
	}
}
