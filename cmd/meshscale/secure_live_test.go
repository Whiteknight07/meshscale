package main

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/auth"
	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/secure"
)

type directoryOnlyTransport struct {
	base          http.RoundTripper
	reads, writes int
}

func (t *directoryOnlyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodGet {
		t.reads++
	} else {
		if !strings.Contains(r.URL.Path, "/gateway/lists") || (r.Method != "POST" && r.Method != "PUT") {
			return nil, fmt.Errorf("live secure check rejected mutation %s %s", r.Method, r.URL.Path)
		}
		t.writes++
	}
	return t.base.RoundTrip(r)
}

// Opt-in API contract check. Only a disabled, isolated key-store resource is
// created/updated. No registration, rule, route, or host network is changed.
func TestLiveSecureDirectory(t *testing.T) {
	if os.Getenv("MESHSCALE_LIVE_SECURE_CHECK") != "1" {
		t.Skip("set MESHSCALE_LIVE_SECURE_CHECK=1 to check only the dev key directory")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	account, tokens, err := resolveCredentials()
	if err != nil {
		t.Fatal(err)
	}
	// Optional OAuth-specific contract check, without the API-token override.
	if os.Getenv("MESHSCALE_LIVE_SECURE_OAUTH") == "1" {
		store, err := auth.DefaultStore()
		if err != nil {
			t.Fatal(err)
		}
		session, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		account, tokens = session.Account.ID, auth.NewTokenSource(auth.NewClient(), store, session)
	}
	t.Logf("directory credential source: %T", tokens)
	transport := &directoryOnlyTransport{base: http.DefaultTransport}
	client := cfapi.New(tokens, "secure-live-check")
	client.HTTPClient = &http.Client{Transport: transport, Timeout: 30 * time.Second}
	key, err := secure.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	public, _ := key.Public()
	record := secure.Record{RegistrationID: "00000000-0000-4000-8000-000000000021", PublicKey: public, Enabled: false}
	for i := 0; i < 2; i++ {
		if err := secure.Publish(ctx, client, account, record, netip.MustParseAddr("100.96.255.254")); err != nil {
			t.Fatal(err)
		}
	}
	if transport.writes != 1 {
		t.Fatalf("expected one key-store write, got %d", transport.writes)
	}
	if _, _, err := secure.Records(ctx, client, account); err != nil {
		t.Fatal(err)
	}
	t.Logf("key-store create/update, paginated readback and idempotency verified: %d GETs, %d key-store write; disabled fixture retained", transport.reads, transport.writes)
}
