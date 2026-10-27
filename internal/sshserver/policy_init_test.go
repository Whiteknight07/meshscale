package sshserver

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestStarterPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, owner string
		root, valid bool
	}{
		{"nonroot", "alice@example.com", false, true},
		{"explicit root", "alice@example.com", true, true},
		{"empty owner", "", false, false},
		{"display name", "Alice <alice@example.com>", false, false},
		{"newline", "alice@example.com\n", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := StarterPolicy(tc.owner, tc.root)
			if (err == nil) != tc.valid {
				t.Fatalf("policy=%+v error=%v", p, err)
			}
			if err != nil {
				return
			}
			owner := Identity{Owner: "ALICE@example.com"}
			if !p.Allows(owner, "alice", 1000) || p.Allows(owner, "root", 0) != tc.root || p.Allows(owner, "alias", 0) || p.Allows(Identity{Owner: "mallory@example.com"}, "alice", 1000) {
				t.Fatal("unsafe starter policy")
			}
		})
	}
}

func TestMissingPolicyDefaultDeny(t *testing.T) {
	for _, missing := range []string{"ssh.json", "absent/ssh.json"} {
		t.Run(missing, func(t *testing.T) {
			p, err := LoadPolicy(filepath.Join(t.TempDir(), missing))
			if err != nil || !p.Missing() || !strings.Contains(p.MissingMessage(), "meshscale ssh policy init") {
				t.Fatalf("%+v %v", p, err)
			}
			for _, u := range []struct {
				name string
				uid  uint32
			}{{"alice", 1000}, {"root", 0}, {"alias", 0}} {
				if p.Allows(Identity{Owner: "alice@example.com", Node: true, Device: "node"}, u.name, u.uid) {
					t.Fatalf("missing policy allowed %s", u.name)
				}
			}
		})
	}
}

func TestInitPolicyFiles(t *testing.T) {
	for _, tc := range []struct {
		name                                                                          string
		existing, force, symlink, parentLink, insecure, malformed, allowRoot, success bool
	}{
		{name: "new", success: true},
		{name: "exists", existing: true},
		{name: "force", existing: true, force: true, success: true},
		{name: "malformed without force", existing: true, malformed: true},
		{name: "malformed with force", existing: true, malformed: true, force: true, success: true},
		{name: "symlink", symlink: true},
		{name: "force symlink", symlink: true, force: true},
		{name: "parent symlink", parentLink: true},
		{name: "unsafe file", existing: true, insecure: true, force: true},
		{name: "explicit root", allowRoot: true, success: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "new", "ssh.json")
			original := []byte(`{"rules":[]}`)
			if tc.malformed {
				original = []byte(`broken`)
			}
			if tc.existing || tc.symlink {
				if err := os.Mkdir(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
			}
			if tc.existing {
				if err := os.WriteFile(path, original, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if tc.insecure {
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			}
			if tc.symlink {
				if err := os.Symlink(filepath.Join(dir, "target"), path); err != nil {
					t.Fatal(err)
				}
			}
			if tc.parentLink {
				if err := os.Symlink(filepath.Join(dir, "missing"), filepath.Dir(path)); err != nil {
					t.Fatal(err)
				}
			}
			_, err := InitPolicy(path, "alice@example.com", tc.allowRoot, tc.force)
			if (err == nil) != tc.success {
				t.Fatalf("error=%v success=%v", err, tc.success)
			}
			if !tc.success {
				if tc.existing {
					got, err := os.ReadFile(path)
					if err != nil || string(got) != string(original) {
						t.Fatalf("modified existing file: %q %v", got, err)
					}
				}
				if tc.symlink {
					if _, err := os.Lstat(filepath.Join(dir, "target")); !os.IsNotExist(err) {
						t.Fatal("followed symlink")
					}
				}
				return
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0644 {
				t.Fatalf("mode: %v %v", info, err)
			}
			p, err := LoadPolicy(path)
			if err != nil || p.Missing() || !p.Allows(Identity{Owner: "alice@example.com"}, "alice", 1000) || p.Allows(Identity{Owner: "alice@example.com"}, "root", 0) != tc.allowRoot {
				t.Fatalf("policy=%+v error=%v", p, err)
			}
		})
	}
}

func TestConcurrentPolicyInit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh.json")
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Go(func() { _, err := InitPolicy(path, "alice@example.com", false, false); results <- err })
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("%d creators won", wins)
	}
	if _, err := LoadPolicy(path); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyDenialExplanation(t *testing.T) {
	p := Policy{Rules: []Rule{{Name: "builders", From: []string{"alice@example.com"}, Users: []string{"builder"}}}}
	for _, tc := range []struct {
		id   Identity
		name string
		uid  uint32
		want string
	}{
		{Identity{Owner: "alice@example.com"}, "alice", 1000, `rule 1 ("builders")`},
		{Identity{Owner: "mallory@example.com"}, "builder", 1000, "no rule matched"},
		{Identity{Owner: "alice@example.com"}, "alias", 0, "UID 0"},
	} {
		if got := p.DenialReason(tc.id, tc.name, tc.uid); !strings.Contains(got, tc.want) {
			t.Fatalf("got %q want %q", got, tc.want)
		}
	}
}
