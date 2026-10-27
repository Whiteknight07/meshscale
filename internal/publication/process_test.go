package publication

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCloudflaredSupervision(t *testing.T) {
	dir := privateDir(t)
	marker := filepath.Join(dir, "starts")
	script := "#!/bin/sh\nprintf '%s|%s|%s\\n' \"$*\" \"$TUNNEL_TOKEN\" \"$CLOUDFLARE_API_TOKEN\" >> \"$PUBLICATION_TEST_MARKER\"\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "cloudflared"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("PUBLICATION_TEST_MARKER", marker)
	t.Setenv("CLOUDFLARE_API_TOKEN", "account-credential-must-not-be-inherited")
	t.Setenv("TUNNEL_TOKEN", "stale-token")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	process := &Cloudflared{}
	if err := process.Start(ctx, "tunnel-only-token"); err != nil {
		t.Fatal(err)
	}
	defer process.Stop()
	deadline := time.Now().Add(4 * time.Second)
	var data []byte
	for time.Now().Before(deadline) {
		data, _ = os.ReadFile(marker)
		if strings.Count(string(data), "\n") >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if strings.Count(string(data), "\n") < 2 {
		t.Fatalf("child was not restarted: %s", data)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		parts := strings.Split(line, "|")
		if len(parts) != 3 || strings.Contains(parts[0], "token") || parts[1] != "tunnel-only-token" || parts[2] != "" {
			t.Fatalf("unsafe child environment or argv: %q", line)
		}
	}
	process.Stop()
	running, _ := process.Status()
	if running {
		t.Fatal("child still running after stop")
	}
	before, _ := os.ReadFile(marker)
	// Stop joins the child and prevents another backoff restart.
	if after, _ := os.ReadFile(marker); string(before) != string(after) {
		t.Fatal("child restarted after stop")
	}
}
func TestCloudflaredMissing(t *testing.T) {
	t.Setenv("PATH", privateDir(t))
	process := &Cloudflared{}
	if err := process.Start(context.Background(), "unused"); err == nil || !strings.Contains(err.Error(), "install") {
		t.Fatal("missing install instructions", err)
	}
	process.Stop()
}
