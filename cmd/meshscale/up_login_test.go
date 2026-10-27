package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/auth"
	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/mesh"
)

// Exercise the account part of up with real credential persistence and only a
// fake OAuth/API server. Network enrollment is separately tested by bringUp's
// fake warp-cli, so this test cannot mutate host routes, DNS or services.
func TestUpLoginPlanFailureAndResume(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "")
	t.Setenv("SSH_CONNECTION", "fixture")
	plan, exchanges, writes := false, 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var result any
		switch r.URL.Path {
		case "/oauth2/token":
			exchanges++
			fmt.Fprint(w, `{"access_token":"fixture-access","refresh_token":"fixture-refresh","token_type":"Bearer","expires_in":3600}`)
			return
		case "/oauth2/userinfo":
			fmt.Fprint(w, `{"email":"owner@example.com"}`)
			return
		case "/client/v4/accounts":
			result = []auth.Account{{ID: "selected", Name: "Test"}}
		default:
			if r.Method != "GET" {
				writes++
				t.Errorf("ready account received a write: %s", r.URL.Path)
			}
			if r.Header.Get("Authorization") != "Bearer fixture-access" {
				t.Error("wrong account credentials")
			}
			switch strings.TrimPrefix(r.URL.Path, "/client/v4/accounts/selected") {
			case "/access/organizations":
				result = cfapi.Organization{AuthDomain: "team.cloudflareaccess.com"}
			case "/subscriptions":
				result = []any{}
				if plan {
					result = []any{map[string]any{"state": "Paid", "rate_plan": map[string]any{"id": "teams_free"}}}
				}
			case "/gateway":
				result = cfapi.GatewayAccount{ID: "gateway"}
			case "/devices/settings":
				result = cfapi.DeviceSettings{UseZTVirtualIP: true, GatewayProxyEnabled: true, GatewayUDPProxyEnabled: true}
			case "/zerotrust/connectivity_settings":
				result = cfapi.ConnectivitySettings{OfframpWARPEnabled: true}
			case "/devices/policies":
				result = []cfapi.DeviceProfile{readyLoginNodeProfile(), readyLoginUserProfile()}
			case "/devices/policy/users":
				result = readyLoginUserProfile()
			case "/access/apps":
				result = []cfapi.EnrollmentApp{{ID: "warp", Type: "warp"}}
			case "/access/identity_providers":
				result = []cfapi.EnrollmentIDP{{ID: "pin", Type: "onetimepin"}}
			case "/access/apps/warp/policies":
				result = []cfapi.EnrollmentPolicy{{ID: "owner", Name: mesh.EnrollmentPolicyPrefix + "owner@example.com", Decision: "allow", Include: []cfapi.AccessRule{{"email": json.RawMessage(`{"email":"owner@example.com"}`)}}}}
			default:
				t.Errorf("unexpected API %s", r.URL.Path)
				http.Error(w, "unexpected", 500)
				return
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
	}))
	defer server.Close()
	oldTransport := http.DefaultTransport
	http.DefaultTransport = loginTestTransport{target: server.Listener.Addr().String(), base: oldTransport}
	defer func() { http.DefaultTransport = oldTransport }()
	input, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if _, err := io.WriteString(input, "fixture-code\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	output, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = input, output
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()
	if err := ensureUpLogin(t.Context(), false, ""); err != nil {
		t.Fatal(err)
	}
	account, tokens, err := resolveCredentials()
	if err != nil {
		t.Fatal(err)
	}
	client := cfapi.New(tokens, "test")
	var progress bytes.Buffer
	err = completeUpSetup(t.Context(), &progress, client, account, "owner@example.com")
	if err == nil {
		t.Fatal("missing plan proceeded to enrollment")
	}
	if strings.Count(progress.String(), "https://one.dash.cloudflare.com/") != 1 || !strings.Contains(progress.String(), "meshscale up") || strings.Count(progress.String(), "\n") != 1 {
		t.Fatalf("dashboard instruction must be one line/link: %q", progress.String())
	}
	// Completing the dashboard step and rerunning up reuses the saved login.
	plan = true
	if err := ensureUpLogin(t.Context(), true, ""); err != nil {
		t.Fatal(err)
	}
	progress.Reset()
	for i := 0; i < 2; i++ {
		if err := completeUpSetup(context.Background(), &progress, client, account, "owner@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if exchanges != 1 || writes != 0 {
		t.Fatalf("resume: OAuth exchanges=%d, writes=%d", exchanges, writes)
	}
	if err := ensureUpLogin(t.Context(), true, "other"); err == nil {
		t.Fatal("silently switched selected account")
	}
	data, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"fixture-access", "fixture-refresh"} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatal("output leaked fixture credentials")
		}
	}
	if !bytes.Contains(data, []byte("Sign in with Cloudflare:")) || !bytes.Contains(data, []byte("Paste the callback URL")) {
		t.Fatalf("SSH sign-in lacks URL/paste instructions: %s", data)
	}
}
