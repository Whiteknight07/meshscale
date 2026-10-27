package config

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestChildEnvironmentWithOnlyCredentials(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix subprocess fixture")
	}
	const sentinel = "meshscale-child-environment-test"
	if os.Getenv("CLOUDFLARE_API_TOKEN") == sentinel {
		cmd := exec.Command("/usr/bin/env")
		cmd.Env = ChildEnvironment()
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "CLOUDFLARE_API_TOKEN=") {
			t.Fatal("empty filtered environment inherited parent credentials")
		}
		return
	}
	// Use an isolated process so the test never clears the test runner's env.
	cmd := exec.Command(os.Args[0], "-test.run=^TestChildEnvironmentWithOnlyCredentials$")
	cmd.Env = []string{"CLOUDFLARE_API_TOKEN=" + sentinel}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated environment regression: %v\n%s", err, out)
	}
}
