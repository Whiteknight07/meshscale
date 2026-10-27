//go:build linux || darwin

package service

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// A file, directory or symlink planted at the socket path is never removed
// or replaced; only a stale socket is.
func TestControlRefusesSubstitutedSocket(t *testing.T) {
	for _, kind := range []string{"file", "directory", "symlink to socket", "dangling symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir, err := os.MkdirTemp("", "ms-socket-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			path := Socket(dir)
			switch kind {
			case "file":
				err = os.WriteFile(path, []byte("keep"), 0600)
			case "directory":
				err = os.Mkdir(path, 0700)
			case "symlink to socket":
				other := filepath.Join(dir, "other.sock")
				l, listenErr := net.Listen("unix", other)
				if listenErr != nil {
					t.Fatal(listenErr)
				}
				defer l.Close()
				err = os.Symlink(other, path)
			case "dangling symlink":
				err = os.Symlink(filepath.Join(dir, "missing"), path)
			}
			if err != nil {
				t.Fatal(err)
			}
			before, _ := os.Lstat(path)
			if err := (&Control{Proxies: &Proxies{}}).Run(context.Background(), dir, nil); err == nil {
				t.Fatal("served on a substituted socket path")
			}
			after, err := os.Lstat(path)
			if err != nil || after.Mode() != before.Mode() {
				t.Fatalf("substituted path was replaced: %v %v", after, err)
			}
		})
	}
}

// A socket left by a crashed daemon is replaced with an owner-only socket.
func TestControlReplacesStaleSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "ms-socket-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	stale, err := net.Listen("unix", Socket(dir))
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()
	ctx, cancel := context.WithCancel(context.Background())
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() { done <- (&Control{Proxies: &Proxies{}}).Run(ctx, dir, ready) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal(err)
	}
	info, err := os.Lstat(Socket(dir))
	if err != nil || info.Mode().Type() != os.ModeSocket || info.Mode().Perm() != 0600 {
		t.Fatalf("socket not private: %v %v", info, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Clients refuse a state directory another user could have prepared.
func TestRequestRefusesUnsafeDirectory(t *testing.T) {
	dir, err := os.MkdirTemp("", "ms-socket-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := Request(context.Background(), dir, "GET", "/status", nil, nil); err == nil {
		t.Fatal("dialed a socket in a shared directory")
	}
	link := dir + "-link"
	os.Chmod(dir, 0700)
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(link)
	if err := Request(context.Background(), link, "GET", "/status", nil, nil); err == nil {
		t.Fatal("dialed through a symlinked directory")
	}
}
