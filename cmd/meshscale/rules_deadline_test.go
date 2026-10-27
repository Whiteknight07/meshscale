package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type stalledRulesTransport struct{}

func (stalledRulesTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func TestRulesCommandBoundsUnresponsiveAPI(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "test-account")
	t.Setenv("CLOUDFLARE_API_TOKEN", "test-token")
	previous := http.DefaultTransport
	http.DefaultTransport = stalledRulesTransport{}
	t.Cleanup(func() { http.DefaultTransport = previous })
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, []byte(`{"rules":[{"from":["*"],"to":["*:22"]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runRules(ctx, []string{"check", path}) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("unresponsive API reported success")
		}
	case <-time.After(30 * time.Second):
		cancel()
		<-done
		t.Fatal("rules check hung more than 30 seconds waiting for the API")
	}
}
