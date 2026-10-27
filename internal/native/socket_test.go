//go:build linux || darwin

package native

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestListenControlRefusesSubstitutes(t *testing.T) {
	dir, err := os.MkdirTemp("", "ms-native-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("keep"), 0600)
	for name, plant := range map[string]func(string) error{
		"file":      func(p string) error { return os.WriteFile(p, []byte("keep"), 0600) },
		"symlink":   func(p string) error { return os.Symlink(target, p) },
		"directory": func(p string) error { return os.Mkdir(p, 0700) },
	} {
		path := filepath.Join(dir, name+".sock")
		if err := plant(path); err != nil {
			t.Fatal(err)
		}
		if l, err := listenControl(path); err == nil {
			l.Close()
			t.Errorf("%s: replaced a substituted control path", name)
		}
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("%s: removed: %v", name, err)
		}
	}
	if data, _ := os.ReadFile(target); string(data) != "keep" {
		t.Fatal("symlink target changed")
	}
	path := filepath.Join(dir, "control.sock")
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()
	l, err := listenControl(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("control socket not private: %v %v", info, err)
	}
}
