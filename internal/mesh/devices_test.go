package mesh

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

func TestDeviceEnrollmentSafetyAndIdempotency(t *testing.T) {
	for _, scenario := range []string{"fresh", "reuse", "broad policy", "unsafe owned profile", "readback unsafe", "profile failure", "no owner", "shadowed profile", "restricted owner policy", "conflicting owned policy"} {
		t.Run(scenario, func(t *testing.T) {
			email := "owner@example.com"
			entries := userIncludes("team.cloudflareaccess.com", []cfapi.EnrollmentIDP{{Type: "github"}})
			safe := cfapi.DeviceProfile{PolicyID: "user-profile", Name: UserProfileName, Description: UserProfileOwner, Enabled: true, Match: `identity.email == "owner@example.com"`, Precedence: 50, ProfileType: "warp", TunnelProtocol: "masque", ServiceModeV2: cfapi.ServiceMode{Mode: "warp"}, Include: entries}
			policy := cfapi.EnrollmentPolicy{ID: "owned-policy", Name: EnrollmentPolicyPrefix + email, Decision: "allow", Precedence: 1, Include: []cfapi.AccessRule{{"email": json.RawMessage(`{"email":"owner@example.com"}`)}}}
			var writes []string
			exists := scenario == "reuse" || scenario == "unsafe owned profile" || scenario == "shadowed profile"
			mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := strings.TrimPrefix(r.URL.Path, "/accounts/account")
				if r.Method != "GET" {
					writes = append(writes, r.Method+" "+path)
				}
				var result any
				switch r.Method + " " + path {
				case "GET /access/organizations":
					result = cfapi.Organization{AuthDomain: "team.cloudflareaccess.com"}
				case "GET /access/apps":
					result = []cfapi.EnrollmentApp{{ID: "warp", Type: "warp"}}
				case "GET /access/identity_providers":
					result = []cfapi.EnrollmentIDP{{ID: "pin", Type: "onetimepin"}, {ID: "github", Type: "github"}, {ID: "github2", Type: "github"}}
				case "GET /access/apps/warp/policies":
					result = []cfapi.EnrollmentPolicy{}
					if scenario == "reuse" {
						result = []cfapi.EnrollmentPolicy{policy}
					}
					if scenario == "broad policy" {
						result = []cfapi.EnrollmentPolicy{{ID: "other", Name: "everyone", Decision: "allow", Include: []cfapi.AccessRule{{"everyone": json.RawMessage(`{}`)}}}}
					}
					if scenario == "restricted owner policy" {
						p := policy
						p.Name = "owner with MFA"
						p.Require = []cfapi.AccessRule{{"any_valid_service_token": json.RawMessage(`{}`)}}
						result = []cfapi.EnrollmentPolicy{p}
					}
					if scenario == "conflicting owned policy" {
						p := policy
						p.Require = []cfapi.AccessRule{{"any_valid_service_token": json.RawMessage(`{}`)}}
						result = []cfapi.EnrollmentPolicy{p}
					}
				case "GET /devices/policies":
					profiles := []cfapi.DeviceProfile{{PolicyID: "default", Default: true, Exclude: []cfapi.SplitTunnelEntry{{Address: "10.0.0.0/8"}}}, {PolicyID: "nodes", Precedence: 100}}
					if exists {
						p := safe
						if scenario == "unsafe owned profile" {
							p.Include = nil
							p.Exclude = []cfapi.SplitTunnelEntry{{Address: "10.0.0.0/8"}}
						}
						profiles = append(profiles, p)
					}
					if scenario == "shadowed profile" {
						profiles = append(profiles, cfapi.DeviceProfile{PolicyID: "higher", Precedence: 25})
					}
					result = profiles
				case "POST /devices/policy":
					if scenario == "profile failure" {
						w.WriteHeader(503)
						return
					}
					var body cfapi.CreateDeviceProfileParams
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if body.Exclude != nil || body.Include == nil || body.Match != safe.Match || body.Precedence == nil || *body.Precedence >= 100 {
						t.Errorf("unsafe profile: %+v", body)
					}
					exists = true
					result = safe
				case "GET /devices/policy/user-profile":
					p := safe
					if scenario == "readback unsafe" {
						p.Include = nil
					}
					result = p
				case "POST /access/apps/warp/policies":
					if !exists {
						t.Error("policy written before profile")
					}
					var p cfapi.EnrollmentPolicy
					if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
						t.Error(err)
					}
					if !ownerOnly(p, email) {
						t.Errorf("unsafe policy: %+v", p)
					}
					result = policy
				default:
					t.Errorf("unexpected API: %s %s", r.Method, path)
					w.WriteHeader(500)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
			})
			server := httptest.NewServer(mux)
			defer server.Close()
			client := cfapi.New(cfapi.StaticToken("test"), "test")
			client.BaseURL = server.URL
			if scenario == "no owner" {
				email = ""
			}
			_, err := EnsureDeviceEnrollment(context.Background(), client, "account", email)
			success := scenario == "fresh" || scenario == "reuse"
			if (err == nil) != success {
				t.Fatalf("err=%v writes=%v", err, writes)
			}
			if scenario == "fresh" && len(writes) != 2 {
				t.Fatal(writes)
			}
			if scenario == "reuse" && len(writes) != 0 {
				t.Fatal(writes)
			}
			if !success {
				for _, write := range writes {
					if strings.Contains(write, "/access/") {
						t.Fatal("enrollment granted on failure", writes)
					}
				}
			}
		})
	}
}
