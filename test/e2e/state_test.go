package e2e

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/localstate"
	"github.com/Whiteknight07/meshscale/internal/secure"
)

func containerOnly(t *testing.T) {
	t.Helper()
	if os.Getenv("MESHSCALE_E2E_STATE") != "1" {
		t.Skip("opt in with MESHSCALE_E2E_STATE=1 inside a test container")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("state chaos must run inside Docker")
	}
}

// Mutate private copies, never the fleet's credentials or running daemon state.
// Every JSON file found in the enrolled node is covered, including key files.
func TestContainerStateCorruption(t *testing.T) {
	containerOnly(t)
	base, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(base, "meshscale")
	var paths []string
	err = filepath.WalkDir(original, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() && strings.HasSuffix(path, ".json") {
			rel, err := filepath.Rel(original, path)
			if err != nil {
				return err
			}
			paths = append(paths, rel)
		}
		return nil
	})
	if err != nil || len(paths) == 0 {
		t.Fatal("cannot inventory enrolled node state")
	}
	for _, rel := range paths {
		for name, content := range map[string][]byte{"truncated": {}, "corrupt": []byte("{broken"), "null": []byte(" \nnull\n")} {
			t.Run(filepath.ToSlash(rel)+"/"+name, func(t *testing.T) {
				xdg := t.TempDir()
				t.Setenv("XDG_CONFIG_HOME", xdg)
				dest := filepath.Join(xdg, "meshscale", rel)
				if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(dest, content, 0600); err != nil {
					t.Fatal(err)
				}
				var err error
				switch filepath.ToSlash(rel) {
				case "backend.json":
					_, err = config.LoadBackend()
					if !config.Paused() {
						t.Error("corrupt backend allows reconnection")
					}
				case "mesh-state.json":
					_, err = config.LoadMeshState()
				case "service/config.json":
					_, err = config.LoadService()
				case "secure/config.json":
					_, err = secure.LoadConfig(filepath.Dir(dest))
				default:
					var value any
					err = localstate.Read(dest, &value)
				}
				if err == nil {
					t.Fatal("corrupted state was accepted")
				}
				after, readErr := os.ReadFile(dest)
				if readErr != nil || !bytes.Equal(after, content) {
					t.Fatal("read repaired or replaced corrupted state without consent")
				}
			})
		}
	}
}

func TestContainerDiskFullPreservesIntent(t *testing.T) {
	containerOnly(t)
	dir := os.Getenv("MESHSCALE_E2E_TMPFS")
	if dir != "/tmp/meshscale-battle-full" {
		t.Skip("requires the runner's dedicated 1 MiB tmpfs")
	}
	path := filepath.Join(dir, "config.json")
	before := struct{ Enabled bool }{true}
	if err := localstate.Write(path, before); err != nil {
		t.Fatal("cannot seed private state")
	}
	f, err := os.OpenFile(filepath.Join(dir, "fill"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	chunk := make([]byte, 4096)
	for i := 0; i < 1024; i++ {
		if _, err = f.Write(chunk); err != nil {
			break
		}
	}
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatal("expected ENOSPC on bounded test tmpfs")
	}
	if err := localstate.Write(path, struct{ Enabled bool }{false}); err == nil {
		t.Fatal("config save succeeded on full disk")
	}
	var after struct{ Enabled bool }
	if err := localstate.Read(path, &after); err != nil || after != before {
		t.Fatal("failed config save lost existing user intent")
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".state-*"))
	if err != nil || len(matches) != 0 {
		t.Fatal("failed config save leaked temporary state")
	}
}
