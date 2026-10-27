package config

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestSealCredentialEnvironment(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("CLOUDFLARE_API_TOKEN", "sealed-token")
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "sealed-account")
	t.Setenv("CF_API_KEY", "other-key")
	t.Cleanup(func() { sealed = nil })
	SealCredentialEnvironment()
	for _, k := range []string{"CLOUDFLARE_API_TOKEN", "CF_API_KEY"} {
		if _, ok := os.LookupEnv(k); ok {
			t.Fatalf("%s still in the process environment", k)
		}
	}
	env, err := LoadEnv()
	if err != nil {
		t.Fatal(err)
	}
	if env["CLOUDFLARE_API_TOKEN"] != "sealed-token" || env["CLOUDFLARE_ACCOUNT_ID"] != "sealed-account" {
		t.Fatalf("LoadEnv lost sealed credentials: %v", env)
	}
	// A child started without an explicit Env inherits nothing secret.
	out, err := exec.Command("env").Output()
	if err != nil {
		t.Skip("env unavailable")
	}
	if strings.Contains(string(out), "sealed-token") || strings.Contains(string(out), "other-key") {
		t.Fatal("child process inherited a credential")
	}
}

func TestSealedCredentialEnvironment(t *testing.T) {
	t.Cleanup(func() { sealed = nil })
	sealed = map[string]string{"CLOUDFLARE_API_TOKEN": "tok", "CLOUDFLARE_ACCOUNT_ID": "acct"}
	if got := SealedCredentialEnvironment(); len(got) != 1 || got[0] != "CLOUDFLARE_API_TOKEN=tok" {
		t.Fatalf("got %v", got)
	}
	sealed = nil
	if got := SealedCredentialEnvironment(); got != nil {
		t.Fatalf("got %v", got)
	}
}
