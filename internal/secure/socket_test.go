//go:build linux || darwin

package secure

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveStaleSocketRefusesSubstitutes(t *testing.T) {
	dir, err := os.MkdirTemp("", "ms-secure-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	live, err := net.Listen("unix", filepath.Join(dir, "live.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	file := filepath.Join(dir, "file")
	os.WriteFile(file, nil, 0600)
	link := filepath.Join(dir, "link")
	os.Symlink(filepath.Join(dir, "live.sock"), link)
	for _, path := range []string{file, link, filepath.Join(dir, "live.sock")} {
		if err := removeStaleSocket(path); err == nil {
			t.Errorf("%s: removed a non-stale socket path", filepath.Base(path))
		}
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("%s: %v", filepath.Base(path), err)
		}
	}
	stale, err := net.Listen("unix", filepath.Join(dir, "stale.sock"))
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()
	if err := removeStaleSocket(filepath.Join(dir, "stale.sock")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "stale.sock")); !os.IsNotExist(err) {
		t.Fatal("stale socket kept")
	}
}
