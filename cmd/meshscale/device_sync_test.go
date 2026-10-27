package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
)

func TestDevicePollPreservesUnchangedCache(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	state, err := config.LoadMeshState()
	if err != nil {
		t.Fatal(err)
	}
	state.Remember("account", "node", "registration")
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	dir, _ := config.Dir()
	path := filepath.Join(dir, "mesh-state.json")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []any{}})
	}))
	defer server.Close()
	client := cfapi.New(cfapi.StaticToken("test"), "test")
	client.BaseURL = server.URL
	if _, err := deviceSnapshot(context.Background(), client, "account"); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("unchanged poll rewrote cache")
	}
}
