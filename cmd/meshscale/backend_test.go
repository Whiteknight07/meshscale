package main

import (
	"testing"

	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/native"
	"github.com/Whiteknight07/meshscale/internal/warpcli"
)

func TestSelectedBackendNeverFallsBack(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	local, _, err := selectedBackend()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := local.(*warpcli.Client); !ok {
		t.Fatalf("default backend=%T", local)
	}
	settings, err := config.LoadBackend()
	if err != nil {
		t.Fatal(err)
	}
	settings.Backend = "native"
	settings.NativeDir = "/nonexistent/private/native"
	if err := settings.Save(); err != nil {
		t.Fatal(err)
	}
	local, _, err = selectedBackend()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := local.(*native.Client); !ok {
		t.Fatalf("native selection fell back to %T", local)
	}
}
