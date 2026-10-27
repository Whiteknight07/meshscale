//go:build linux || darwin

package localstate

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func privateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Every way of substituting or loosening private state is refused by both
// Read and Write, before any content is trusted or replaced.
func TestReadAndWriteRefuseUnsafeState(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir string) (path string)
		write bool // Write must refuse too, not only Read
	}{
		{"symlinked file", func(t *testing.T, dir string) string {
			victim := filepath.Join(t.TempDir(), "victim.json")
			os.WriteFile(victim, []byte(`{"x":1}`), 0600)
			path := filepath.Join(dir, "state.json")
			os.Symlink(victim, path)
			return path
		}, false},
		{"fifo", func(t *testing.T, dir string) string {
			path := filepath.Join(dir, "state.json")
			unix.Mkfifo(path, 0600)
			return path
		}, false},
		{"directory in place", func(t *testing.T, dir string) string {
			path := filepath.Join(dir, "state.json")
			os.Mkdir(path, 0700)
			return path
		}, true},
		{"world-readable file", func(t *testing.T, dir string) string {
			path := filepath.Join(dir, "state.json")
			os.WriteFile(path, []byte(`{}`), 0600)
			os.Chmod(path, 0644)
			return path
		}, false},
		{"group-accessible directory", func(t *testing.T, dir string) string {
			os.Chmod(dir, 0750)
			return filepath.Join(dir, "state.json")
		}, true},
		{"symlinked directory", func(t *testing.T, dir string) string {
			link := filepath.Join(filepath.Dir(dir), "link")
			os.Symlink(dir, link)
			return filepath.Join(link, "state.json")
		}, true},
		{"symlinked ancestor", func(t *testing.T, dir string) string {
			link := filepath.Join(t.TempDir(), "ancestor")
			os.Symlink(filepath.Dir(dir), link)
			return filepath.Join(link, "state", "state.json")
		}, true},
		{"group-writable ancestor", func(t *testing.T, dir string) string {
			os.Chmod(filepath.Dir(dir), 0770)
			return filepath.Join(dir, "state.json")
		}, true},
		{"foreign-owned file", func(t *testing.T, dir string) string {
			if os.Geteuid() != 0 {
				t.Skip("changing ownership requires root")
			}
			path := filepath.Join(dir, "state.json")
			os.WriteFile(path, []byte(`{}`), 0600)
			os.Chown(path, 65534, 65534)
			return path
		}, false},
		{"foreign-owned directory", func(t *testing.T, dir string) string {
			if os.Geteuid() != 0 {
				t.Skip("changing ownership requires root")
			}
			os.Chown(dir, 65534, 65534)
			return filepath.Join(dir, "state.json")
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.setup(t, privateDir(t))
			var out map[string]any
			if err := Read(path, &out); err == nil {
				t.Fatalf("read unsafe state: %v", out)
			}
			if tc.write {
				if err := Write(path, map[string]int{"y": 2}); err == nil {
					t.Fatal("wrote through unsafe state")
				}
			}
		})
	}
}

// Write replaces a planted symlink itself; it never writes through it.
func TestWriteDoesNotFollowSymlink(t *testing.T) {
	dir := privateDir(t)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, map[string]int{"y": 2}); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(victim); string(data) != "keep" {
		t.Fatalf("wrote through symlink: %q", data)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("state is not a private regular file: %v %v", info, err)
	}
	var out map[string]int
	if err := Read(path, &out); err != nil || out["y"] != 2 {
		t.Fatal(out, err)
	}
}
