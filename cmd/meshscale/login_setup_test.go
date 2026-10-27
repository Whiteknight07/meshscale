package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/auth"
	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/mesh"
)

type loginTestTransport struct {
	target string
	base   http.RoundTripper
}

func (t loginTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	u := *r.URL
	u.Scheme = "http"
	u.Host = t.target
	clone.URL = &u
	return t.base.RoundTrip(clone)
}

func TestLoginRunsSetupWithNewOAuthSession(t *testing.T) {
	for _, failSetup := range []bool{false, true} {
		t.Run(fmt.Sprint("setupFailure=", failSetup), func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			// Credentials for another account must never be used for post-login setup.
			t.Setenv("CLOUDFLARE_API_TOKEN", "other-account-token")
			t.Setenv("CLOUDFLARE_ACCOUNT_ID", "other-account")
			store, err := auth.DefaultStore()
			if err != nil {
				t.Fatal(err)
			}
			setupReads, writes := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var result any
				switch r.URL.Path {
				case "/oauth2/token":
					fmt.Fprint(w, `{"access_token":"new-oauth-token","refresh_token":"refresh","token_type":"Bearer","expires_in":3600}`)
					return
				case "/oauth2/userinfo":
					fmt.Fprint(w, `{"email":"owner@example.com"}`)
					return
				case "/client/v4/accounts":
					result = []auth.Account{{ID: "selected", Name: "Selected account"}}
				default:
					setupReads++
					session, err := store.Load()
					if err != nil || session.Account.ID != "selected" {
						t.Errorf("setup ran before login was saved: %v", err)
					}
					if r.Method != "GET" {
						writes++
						t.Errorf("ready account received %s %s", r.Method, r.URL.Path)
					}
					if r.Header.Get("Authorization") != "Bearer new-oauth-token" || !strings.HasPrefix(r.URL.Path, "/client/v4/accounts/selected/") {
						t.Errorf("setup used wrong credentials: %s", r.URL.Path)
					}
					switch strings.TrimPrefix(r.URL.Path, "/client/v4/accounts/selected") {
					case "/access/organizations":
						if failSetup {
							w.WriteHeader(403)
							fmt.Fprint(w, `{"success":false,"errors":[{"message":"forbidden"}]}`)
							return
						}
						result = cfapi.Organization{AuthDomain: "team.cloudflareaccess.com"}
					case "/subscriptions":
						result = []any{map[string]any{"state": "Paid", "rate_plan": map[string]any{"id": "teams_free"}}}
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
						t.Errorf("unexpected %s", r.URL.Path)
						http.Error(w, "unexpected", 500)
						return
					}
				}
				json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
			}))
			defer server.Close()
			previousTransport := http.DefaultTransport
			http.DefaultTransport = loginTestTransport{target: server.Listener.Addr().String(), base: previousTransport}
			defer func() { http.DefaultTransport = previousTransport }()
			input, err := os.CreateTemp(t.TempDir(), "stdin")
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			if _, err := io.WriteString(input, "test-code\n"); err != nil {
				t.Fatal(err)
			}
			if _, err := input.Seek(0, 0); err != nil {
				t.Fatal(err)
			}
			output, err := os.Create(filepath.Join(t.TempDir(), "output"))
			if err != nil {
				t.Fatal(err)
			}
			defer output.Close()
			oldInput, oldOutput := os.Stdin, os.Stdout
			os.Stdin, os.Stdout = input, output
			defer func() { os.Stdin, os.Stdout = oldInput, oldOutput }()
			err = runLogin(context.Background(), []string{"--no-browser"})
			if (err != nil) != failSetup {
				t.Fatalf("login error: %v", err)
			}
			session, loadErr := store.Load()
			if loadErr != nil || session.Account.ID != "selected" {
				t.Fatalf("login lost after setup: %v", loadErr)
			}
			if setupReads == 0 || writes != 0 {
				t.Fatalf("setup reads=%d writes=%d", setupReads, writes)
			}
			if failSetup && !strings.Contains(err.Error(), "login saved") {
				t.Fatalf("missing saved-login explanation: %v", err)
			}
			data, readErr := os.ReadFile(output.Name())
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !failSetup && !strings.Contains(string(data), "Mesh is already ready (no changes).") {
				t.Fatalf("missing setup summary: %s", data)
			}
		})
	}
}

func readyLoginNodeProfile() cfapi.DeviceProfile {
	return cfapi.DeviceProfile{PolicyID: "nodes", Name: mesh.ProfileName, Enabled: true, Match: `identity.email == "warp_connector@team.cloudflareaccess.com"`, Precedence: 100, ProfileType: "warp", TunnelProtocol: "masque", ServiceModeV2: cfapi.ServiceMode{Mode: "warp"}, Include: []cfapi.SplitTunnelEntry{{Address: "100.96.0.0/12"}}}
}
func readyLoginUserProfile() cfapi.DeviceProfile {
	return cfapi.DeviceProfile{PolicyID: "users", Name: mesh.UserProfileName, Description: mesh.UserProfileOwner, Enabled: true, Match: `identity.email == "owner@example.com"`, Precedence: 50, ProfileType: "warp", TunnelProtocol: "masque", ServiceModeV2: cfapi.ServiceMode{Mode: "warp"}, Include: []cfapi.SplitTunnelEntry{{Address: "100.96.0.0/12"}, {Address: "2606:4700:cf1::/48"}, {Host: "team.cloudflareaccess.com"}}}
}
