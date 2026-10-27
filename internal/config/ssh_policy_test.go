package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSSHPolicyDefaultPath(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path, err := DefaultSSHPolicyPath()
	if err != nil {
		t.Fatal(err)
	}
	want := "/etc/meshscale/ssh.json"
	if os.Geteuid() != 0 {
		dir, err := Dir()
		if err != nil {
			t.Fatal(err)
		}
		want = filepath.Join(dir, "ssh.json")
	}
	if path != want {
		t.Fatalf("got %q want %q", path, want)
	}
	settings, err := LoadService()
	if err != nil || settings.SSHPolicy != want {
		t.Fatalf("%+v %v", settings, err)
	}
	custom := filepath.Join(t.TempDir(), "custom-ssh.json")
	settings.SSHPolicy = custom
	if err := settings.Save(); err != nil {
		t.Fatal(err)
	}
	settings, err = LoadService()
	if err != nil || settings.SSHPolicy != custom {
		t.Fatalf("%+v %v", settings, err)
	}
}
