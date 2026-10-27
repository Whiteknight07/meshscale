//go:build linux

package main

import (
	"os"
	"slices"
	"testing"
)

func TestOwnPort22(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{{nil, true}, {[]string{"--port", "22"}, true}, {[]string{"--port=2222"}, false}, {[]string{"-port", "2222"}, false}, {[]string{"--state-dir", "/var/lib/meshscale"}, true}, {[]string{"--port"}, false}} {
		if got := ownPort22(tc.args); got != tc.want {
			t.Errorf("%v: %v", tc.args, got)
		}
	}
}

// A restored meshscale sshd needs environment-only credentials; no other
// restored program may receive them.
func TestSSHProcessEnvironmentCredentials(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	credentials := []string{"CLOUDFLARE_API_TOKEN=sealed"}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	has := func(env []string) bool { return slices.Contains(env, "CLOUDFLARE_API_TOKEN=sealed") }
	if !has(sshProcessEnvironment(self, credentials)) {
		t.Fatal("meshscale sshd did not receive sealed credentials")
	}
	if has(sshProcessEnvironment("/bin/sh", credentials)) {
		t.Fatal("another program received sealed credentials")
	}
}
