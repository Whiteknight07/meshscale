package sshserver

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicy(t *testing.T) {
	node := Identity{Device: "build-box", Node: true, DeviceID: "dev-1", Owner: "alice@example.com"}
	laptop := Identity{Device: "build-box", DeviceID: "dev-2", Owner: "Mallory@Example.com"}
	id := node
	for _, tc := range []struct {
		name, data, user string
		uid              uint32
		want             bool
	}{
		{"node name", `{"rules":[{"from":["build-box"],"users":["alice"]}]}`, "alice", 1000, true},
		{"device id", `{"rules":[{"from":["device:dev-1"],"users":["alice"]}]}`, "alice", 1000, true},
		{"email ignores case", `{"rules":[{"from":["ALICE@example.com"],"users":["bob"]}]}`, "bob", 1001, true},
		{"email", `{"rules":[{"from":["alice@example.com"],"users":["bob"]}]}`, "bob", 1001, true},
		{"nonroot", `{"rules":[{"from":["*"],"users":["autogroup:nonroot"]}]}`, "alice", 1000, true},
		{"root default", `{"rules":[{"from":["*"],"users":["autogroup:nonroot"]}]}`, "root", 0, false},
		{"root explicit", `{"rules":[{"from":["build-box"],"users":["root"]}]}`, "root", 0, true},
		{"uid zero alias", `{"rules":[{"from":["*"],"users":["admin","autogroup:nonroot","root"]}]}`, "admin", 0, false},
		{"other user", `{"rules":[{"from":["*"],"users":["alice"]}]}`, "bob", 1001, false},
		{"other device", `{"rules":[{"from":["other"],"users":["alice"]}]}`, "alice", 1000, false},
		{"deny all", `{"rules":[]}`, "alice", 1000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParsePolicy([]byte(tc.data))
			if err != nil {
				t.Fatal(err)
			}
			if got := p.Allows(id, tc.user, tc.uid); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
	for _, data := range []string{`null`, `{}`, `{"rules":null}`, `{"rules":[{"from":[],"users":["alice"]}]}`, `{"rules":[{"from":["*"],"users":["*"]}]}`, `{"rules":[{"from":["*"],"users":["autogroup:all"]}]}`, `{"rules":[],"typo":true}`, `{"rules":[]} {"rules":[]}`, `{"rules":[{"from":["device:"],"users":["alice"]}]}`} {
		if _, err := ParsePolicy([]byte(data)); err == nil {
			t.Errorf("accepted invalid policy %s", data)
		}
	}
	if DefaultPolicy().Allows(id, "root", 0) || DefaultPolicy().Allows(id, "alice", 1000) {
		t.Fatal("incorrect default")
	}
	// A user device that names itself after a node gains nothing from the name.
	p, _ := ParsePolicy([]byte(`{"rules":[{"from":["build-box","device:dev-1"],"users":["alice"]}]}`))
	if p.Allows(laptop, "alice", 1000) {
		t.Fatal("self-reported device name granted access")
	}
}

func TestPolicyProtectedFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned file checks")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh.json")
	p, err := LoadPolicy(path)
	if err != nil || p.Allows(Identity{}, "alice", 1000) || !p.Missing() {
		t.Fatalf("missing file: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"rules":[]}`), 0644); err != nil {
		t.Fatal(err)
	}
	p, err = LoadPolicy(path)
	if err != nil || p.Allows(Identity{}, "alice", 1000) {
		t.Fatalf("deny-all file: %v", err)
	}
	os.Chmod(path, 0666)
	if _, err := LoadPolicy(path); err == nil {
		t.Fatal("accepted writable policy")
	}
	os.Remove(path)
	os.Symlink(filepath.Join(dir, "missing"), path)
	if _, err := LoadPolicy(path); err == nil {
		t.Fatal("accepted policy symlink as absent")
	}
	os.Remove(path)
	os.WriteFile(path, []byte(`broken`), 0600)
	if _, err := LoadPolicy(path); err == nil {
		t.Fatal("accepted malformed policy")
	}
}
