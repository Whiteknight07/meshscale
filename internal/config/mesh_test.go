package config

import (
	"os"
	"testing"
)

func TestMeshStatePersistence(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	state, err := LoadMeshState()
	if err != nil {
		t.Fatal(err)
	}
	state.Remember("account", "node", "reg")
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadMeshState()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Node("account", "reg") != "node" || loaded.Node("other", "reg") != "" || loaded.Node("account", "new-registration") != "" {
		t.Fatalf("incorrect scope: %#v", loaded)
	}
	info, err := os.Stat(loaded.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %v", info.Mode())
	}
	// A live API observation overrides a remembered association.
	loaded.Remember("account", "new-node", "reg")
	if loaded.Node("account", "reg") != "new-node" {
		t.Fatal("stale association retained")
	}
}
