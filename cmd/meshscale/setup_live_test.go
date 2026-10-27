package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/auth"
	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
)

type getOnlyTransport struct {
	base            http.RoundTripper
	reads, rejected int
}

func (t *getOnlyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet {
		t.rejected++
		return nil, fmt.Errorf("live setup check refused %s %s", r.Method, r.URL.Path)
	}
	t.reads++
	return t.base.RoundTrip(r)
}

// Explicit opt-in. The transport prevents every account mutation, even if a
// regression mistakenly tries to change the already-configured dev account.
func TestLiveSetupReadOnly(t *testing.T) {
	if os.Getenv("MESHSCALE_LIVE_SETUP_CHECK") != "1" {
		t.Skip("set MESHSCALE_LIVE_SETUP_CHECK=1 for a GET-only check of the configured dev account")
	}
	env, err := config.LoadEnv()
	if err != nil {
		t.Fatal(err)
	}
	account, token := env["CLOUDFLARE_ACCOUNT_ID"], env["CLOUDFLARE_API_TOKEN"]
	if account == "" || token == "" {
		t.Fatal("dev account/token must already be configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport := &getOnlyTransport{base: http.DefaultTransport}
	source := cfapi.StaticToken(token)
	identity := auth.NewClient()
	identity.HTTPClient = &http.Client{Transport: transport, Timeout: 30 * time.Second}
	email, err := identity.Email(ctx, source, false)
	client := cfapi.New(source, "live-check")
	client.HTTPClient = &http.Client{Transport: transport, Timeout: 30 * time.Second}
	if err != nil {
		email, err = client.SoleAccountOwnerEmail(ctx, account)
	}
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the same helper used by login and setup --devices, including its
	// human-readable "already ready" summary. Never log tokens or raw responses.
	var output strings.Builder
	if err := completeAccountSetup(ctx, &output, client, account, email); err != nil {
		t.Fatal(err)
	}
	if transport.rejected != 0 || !strings.Contains(output.String(), "Mesh is already ready (no changes).") || strings.Contains(output.String(), "Changed:") {
		t.Fatalf("not ready without writes: rejected=%d output=%s", transport.rejected, output.String())
	}
	t.Log(output.String())
	t.Logf("%d GETs; zero writes attempted or sent", transport.reads)
}
