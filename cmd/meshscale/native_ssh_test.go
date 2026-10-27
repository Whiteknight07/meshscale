package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestNativeSSHHostKeyPinning(t *testing.T) {
	key := func() ssh.PublicKey {
		t.Helper()
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		k, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "known_hosts")
	var out bytes.Buffer
	check := nativeHostKeyCallback(path, &out)
	remote := &net.TCPAddr{IP: net.ParseIP("100.96.0.2"), Port: 2222}
	first := key()
	if err := check("100.96.0.2:2222", remote, first); err != nil {
		t.Fatal(err)
	}
	if err := check("100.96.0.2:2222", remote, first); err != nil {
		t.Fatal(err)
	}
	if err := check("100.96.0.2:2222", remote, key()); err == nil {
		t.Fatal("accepted changed SSH host key")
	}
	if strings.Count(out.String(), "Added Mesh SSH host") != 1 {
		t.Fatal("host was trusted more than once")
	}
}

func TestNativeSSHHostPinsRejectSymlinks(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, nil, 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "known_hosts")
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := nativeHostKeyCallback(path, &out)("100.96.0.2:22", &net.TCPAddr{}, key); err == nil {
		t.Fatal("accepted symlinked host pin store")
	}
	data, err := os.ReadFile(victim)
	if err != nil || len(data) != 0 {
		t.Fatal("modified host pin symlink target")
	}
}
