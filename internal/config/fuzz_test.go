package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// FuzzLoaders writes arbitrary bytes to each saved settings file. A loader
// either refuses the file or returns settings that save and reload unchanged.
func FuzzLoaders(f *testing.F) {
	for _, seed := range []string{
		`{"backend":"native","native_state_dir":"/var/lib/meshscale","paused":true}`,
		`{"ssh":true,"ssh_port":2222,"poll_interval":1000000000,"forwards":[{"port":80,"mesh_port":8080}]}`,
		`{"accounts":{"a":{"reg":"node"}}}`,
		`{"hosts":"on"}`,
		`null`, `{"backend":"warp\u0000"}`, `{"ssh_port":-1}`, `{"forwards":[{"port":1,"mesh_port":1},{"port":2,"mesh_port":1}]}`,
	} {
		f.Add([]byte(seed))
	}
	home := f.TempDir()
	f.Setenv("XDG_CONFIG_HOME", home)
	f.Fuzz(func(t *testing.T, data []byte) {
		dir, err := Dir()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "service"), 0700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"backend.json", "service/config.json", "mesh-state.json", "dns.json"} {
			if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if s, err := LoadBackend(); err == nil {
			if s.Backend != "warp" && s.Backend != "native" || s.NativeDir != "" && !filepath.IsAbs(s.NativeDir) {
				t.Fatalf("accepted backend settings %+v", s)
			}
			roundTrip(t, s, (*BackendSettings).Save, LoadBackend)
		}
		if s, err := LoadService(); err == nil {
			if s.SSHPort < 1 || s.SSHPort > 65535 {
				t.Fatalf("accepted SSH port %d", s.SSHPort)
			}
			roundTrip(t, s, (*ServiceSettings).Save, LoadService)
		}
		if s, err := LoadDNS(); err == nil {
			roundTrip(t, s, (*DNSSettings).Save, LoadDNS)
		}
		if s, err := LoadMeshState(); err == nil {
			if err := s.Save(); err != nil {
				t.Fatal(err)
			}
			again, err := LoadMeshState()
			if err != nil || !reflect.DeepEqual(again.Accounts, s.Accounts) && len(s.Accounts)+len(again.Accounts) > 0 {
				t.Fatalf("mesh state reloads differently: %v vs %v (%v)", again.Accounts, s.Accounts, err)
			}
		}
	})
}

func roundTrip[T any](t *testing.T, s *T, save func(*T) error, load func() (*T, error)) {
	t.Helper()
	if err := save(s); err != nil {
		t.Fatal(err)
	}
	// Compare encodings: an empty saved list reloads as nil under omitempty.
	again, err := load()
	a, _ := json.Marshal(again)
	b, _ := json.Marshal(s)
	if err != nil || string(a) != string(b) {
		t.Fatalf("settings reload differently: %+v vs %+v (%v)", again, s, err)
	}
}
