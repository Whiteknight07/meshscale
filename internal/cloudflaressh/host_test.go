package cloudflaressh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeHostSystem struct {
	world                                   *fakeWorld
	dir                                     string
	failValidate, failEffective, failReload bool
}

func (f fakeHostSystem) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	if args[0] == "-t" {
		if f.failValidate {
			return nil, errors.New("invalid sshd config")
		}
		return nil, nil
	}
	if f.failEffective {
		return []byte("authorizedkeysfile .ssh/authorized_keys\n"), nil
	}
	return []byte("trustedusercakeys " + filepath.Join(f.dir, "meshscale-cloudflare/ca.pub") + "\nauthorizedprincipalsfile " + filepath.Join(f.dir, "meshscale-cloudflare/%u") + "\nauthorizedkeysfile none\nauthorizedkeyscommand none\nauthenticationmethods publickey\npasswordauthentication no\nkbdinteractiveauthentication no\nhostbasedauthentication no\npubkeyacceptedalgorithms ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com\n"), nil
}
func (f fakeHostSystem) Stop(context.Context, *State) error { return f.world.event("stop own") }
func (f fakeHostSystem) Restore(_ context.Context, _ *State, own bool) error {
	if own {
		return f.world.event("restore own")
	}
	return f.world.event("off")
}

type fakeOpenSSH struct{ fakeHostSystem }

func (f fakeOpenSSH) Reload(context.Context, *State) error {
	if f.failReload {
		return errors.New("reload failed")
	}
	return f.world.event("reload OpenSSH")
}
func (f fakeOpenSSH) Restore(context.Context, *State) error { return f.world.event("restore OpenSSH") }
func TestFileHostValidationAndRollback(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		validation, effective, reload bool
	}{{"valid", false, false, false}, {"syntax failure", true, false, false}, {"ignored Include", false, true, false}, {"reload failure", false, false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "sshd_config.d"), 0755); err != nil {
				t.Fatal(err)
			}
			world := &fakeWorld{}
			system := fakeHostSystem{world: world, dir: dir, failValidate: tc.validation, failEffective: tc.effective, failReload: tc.reload}
			host := FileHost{SSHDir: dir, Run: system, Own: system, Service: fakeOpenSSH{system}, Store: world}
			state := testState()
			err := host.Enable(context.Background(), &state, "ssh-public-key")
			wantFail := tc.validation || tc.effective || tc.reload
			if (err != nil) != wantFail {
				t.Fatalf("error %v", err)
			}
			if wantFail {
				if _, e := os.Stat(host.dropIn()); !os.IsNotExist(e) {
					t.Fatal("failed configuration left installed")
				}
				if tc.validation || tc.effective {
					if strings.Contains(strings.Join(world.events, ","), "stop own") {
						t.Fatal("stopped previous server before validating configuration")
					}
				}
				return
			}
			data, err := os.ReadFile(host.dropIn())
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), "Match LocalAddress 100.96.0.2 LocalPort 22") || strings.Contains(string(data), "ListenAddress") {
				t.Fatalf("changed public listener: %s", data)
			}
			if _, err = os.Stat(filepath.Join(host.privateDir(), "root")); !os.IsNotExist(err) {
				t.Fatal("root mapping was not explicit")
			}
			if err = host.Disable(context.Background(), &state, "own"); err != nil {
				t.Fatal(err)
			}
			if _, err = os.Stat(host.dropIn()); !os.IsNotExist(err) {
				t.Fatal("drop-in remains")
			}
			if _, err = os.Stat(host.privateDir()); !os.IsNotExist(err) {
				t.Fatal("trust material remains")
			}
		})
	}
}
func TestFileHostRefusesUntrackedAndModifiedFiles(t *testing.T) {
	for _, path := range []string{"sshd_config.d/50-meshscale-cloudflare.conf", "meshscale-cloudflare"} {
		t.Run(path, func(t *testing.T) {
			dir := t.TempDir()
			_ = os.Mkdir(filepath.Join(dir, "sshd_config.d"), 0755)
			file := filepath.Join(dir, path)
			if path == "meshscale-cloudflare" {
				_ = os.Mkdir(file, 0700)
			} else {
				_ = os.WriteFile(file, []byte("admin config"), 0600)
			}
			world := &fakeWorld{}
			host := FileHost{SSHDir: dir, Store: world}
			state := testState()
			if err := host.Enable(context.Background(), &state, "key"); err == nil {
				t.Fatal("adopted untracked path")
			}
			if _, err := os.Stat(file); err != nil {
				t.Fatal("removed administrator path")
			}
		})
	}
}

func TestTrustCleanupPreservesAdministratorFiles(t *testing.T) {
	for _, change := range []string{"additional file", "modified CA", "symlink"} {
		t.Run(change, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "sshd_config.d"), 0755); err != nil {
				t.Fatal(err)
			}
			world := &fakeWorld{}
			system := fakeHostSystem{world: world, dir: dir}
			host := FileHost{SSHDir: dir, Run: system, Own: system, Service: fakeOpenSSH{system}, Store: world}
			state := testState()
			if err := host.Enable(context.Background(), &state, "public key"); err != nil {
				t.Fatal(err)
			}
			// Repeated provisioning accepts only the recorded file contents.
			if err := host.Enable(context.Background(), &state, "public key"); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(host.privateDir(), "ca.pub")
			if change == "additional file" {
				path = filepath.Join(host.privateDir(), "admin")
			}
			if change == "symlink" {
				target := filepath.Join(dir, "admin-ca")
				if err := os.WriteFile(target, []byte("admin content"), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte("admin content"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := host.Disable(context.Background(), &state, "own"); err == nil {
				t.Fatal("expected cleanup conflict")
			}
			if data, err := os.ReadFile(path); err != nil || string(data) != "admin content" {
				t.Fatalf("administrator file changed: %q, %v", data, err)
			}
		})
	}
}

func TestCloudflareToOffRemovesTrustWithoutRestoringOwn(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sshd_config.d"), 0755); err != nil {
		t.Fatal(err)
	}
	world := &fakeWorld{}
	system := fakeHostSystem{world: world, dir: dir}
	host := FileHost{SSHDir: dir, Run: system, Own: system, Service: fakeOpenSSH{system}, Store: world}
	state := testState()
	if err := host.Enable(context.Background(), &state, "public key"); err != nil {
		t.Fatal(err)
	}
	world.events = nil
	if err := host.Disable(context.Background(), &state, "off"); err != nil {
		t.Fatal(err)
	}
	if state.Mode != "off" || state.Host != nil {
		t.Fatalf("unexpected state: %+v", state)
	}
	events := strings.Join(world.events, ",")
	if !strings.Contains(events, "off") || strings.Contains(events, "restore own") {
		t.Fatalf("unexpected server restoration: %s", events)
	}
	for _, path := range []string{host.dropIn(), host.privateDir()} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("managed path remains: %s: %v", path, err)
		}
	}
}

func TestRetryDoesNotAdoptAdministratorDropIn(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sshd_config.d"), 0755); err != nil {
		t.Fatal(err)
	}
	world := &fakeWorld{}
	host := FileHost{SSHDir: dir, Store: world}
	state := testState()
	// A previous attempt saved migration state before writing the drop-in.
	state.Host = &HostState{}
	if err := os.WriteFile(host.dropIn(), []byte("administrator config"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := host.Enable(context.Background(), &state, "public key"); err == nil {
		t.Fatal("retry adopted an administrator drop-in")
	}
	if data, err := os.ReadFile(host.dropIn()); err != nil || string(data) != "administrator config" {
		t.Fatalf("administrator drop-in changed: %q, %v", data, err)
	}
}
