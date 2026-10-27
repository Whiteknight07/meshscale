package native

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/localstate"
)

func TestStatePermissionsAndRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "native")
	if err := localstate.Dir(dir); err != nil {
		t.Fatal(err)
	}
	_, r := fixture(t)
	private, public, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	r.Key = public
	state := &State{Account: "account", NodeID: "node", Name: "meshscale-native-fixture", PrivateKey: private, Registration: r}
	if err := state.Save(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(StatePath(dir))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("file permissions: %v %v", info, err)
	}
	loaded, err := LoadState(dir)
	if err != nil || loaded.PrivateKey != private || loaded.Registration.Token != r.Token {
		t.Fatalf("roundtrip: %v", err)
	}
	if err := os.Chmod(StatePath(dir), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); err == nil {
		t.Fatal("accepted public credentials")
	}
	os.Remove(StatePath(dir))
	target := filepath.Join(dir, "elsewhere")
	os.WriteFile(target, []byte(`{}`), 0600)
	os.Symlink(target, StatePath(dir))
	if _, err := LoadState(dir); err == nil {
		t.Fatal("accepted symlink")
	}
}
func TestExclusiveStateLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "native")
	if err := localstate.Dir(dir); err != nil {
		t.Fatal(err)
	}
	release, err := localstate.Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := localstate.Lock(dir); err == nil {
		other()
		t.Fatal("accepted a second daemon")
	}
	release()
	other, err := localstate.Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	other()
}
func TestPrivateDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "native")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := localstate.Dir(dir); err == nil {
		t.Fatal("accepted public state directory")
	}
}

func TestInterruptedEnrollmentCanBeRemoved(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "native")
	s := &State{Account: "account", NodeID: "node", Name: "meshscale-native-fixture", Pending: true, PrivateKey: "incomplete", Registration: Registration{ID: "t.fixture", Token: "REDACTED"}}
	if err := s.Save(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); err == nil {
		t.Fatal("incomplete registration accepted for connection")
	}
	cleanup, err := LoadStateForRemoval(dir)
	if err != nil || cleanup.Registration.Token != "REDACTED" {
		t.Fatal("lost credential needed for cleanup")
	}
}
