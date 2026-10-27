//go:build linux || darwin

package hostsdns

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Docker bind-mounts /etc/hosts, so renaming over it fails with EBUSY.
func TestUpdateRewritesBindMountedFileInPlace(t *testing.T) {
	rename = func(oldpath, newpath string) error {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: unix.EBUSY}
	}
	t.Cleanup(func() { rename = os.Rename })
	path := filepath.Join(t.TempDir(), "hosts")
	original := []byte("127.0.0.1 localhost\n172.17.0.2 container\n")
	if err := os.WriteFile(path, original, 0644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	if err := Update(t.Context(), path, fixtureRecords, nil); err != nil {
		t.Fatalf("bind-mounted update: %v", err)
	}
	data, _ := os.ReadFile(path)
	want, _ := Rewrite(original, fixtureRecords)
	if !bytes.Equal(data, want) {
		t.Fatalf("in-place update: %q", data)
	}
	if err := Update(t.Context(), path, nil, nil); err != nil {
		t.Fatalf("bind-mounted cleanup: %v", err)
	}
	data, _ = os.ReadFile(path)
	if !bytes.Equal(data, original) {
		t.Fatalf("cleanup left %q", data)
	}
	after, _ := os.Stat(path)
	if !os.SameFile(before, after) {
		t.Fatal("bind-mounted hosts file was replaced instead of rewritten")
	}
	if matches, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".meshscale-hosts-*")); len(matches) != 0 {
		t.Fatalf("left temp files: %v", matches)
	}
}
