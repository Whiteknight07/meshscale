package mesh

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

// This fake retains every write and unrelated settings, and models both absent
// resources and the billing authorization gap in Cloudflare's OAuth catalog.
type setupAccount struct {
	org, gateway, app, plan, billingDenied bool
	orgDenied                              bool
	badUserReadback                        bool
	settings                               map[string]any
	connectivity                           map[string]any
	profiles                               []cfapi.DeviceProfile
	idps                                   []cfapi.EnrollmentIDP
	policies                               []cfapi.EnrollmentPolicy
	writes                                 []string
}

func (a *setupAccount) serve(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/accounts/a")
		if r.Method != http.MethodGet {
			a.writes = append(a.writes, r.Method+" "+path)
		}
		absent := func(status int) {
			w.WriteHeader(status)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":1000,"message":"missing or forbidden"}]}`)
		}
		var result any
		switch r.Method + " " + path {
		case "GET /access/organizations":
			if a.orgDenied {
				absent(403)
				return
			}
			if !a.org {
				absent(404)
				return
			}
			result = cfapi.Organization{AuthDomain: "generated-team.cloudflareaccess.com"}
		case "POST /access/organizations":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if len(body) != 0 || a.org {
				t.Errorf("organization must only be created once with generated domain: %v", body)
			}
			a.org = true
			result = cfapi.Organization{AuthDomain: "generated-team.cloudflareaccess.com"}
		case "GET /subscriptions":
			if a.billingDenied {
				absent(403)
				return
			}
			if a.plan {
				result = []any{map[string]any{"state": "Paid", "rate_plan": map[string]any{"id": "teams_free"}}}
			} else {
				result = []any{}
			}
		case "GET /gateway":
			if !a.gateway {
				absent(404)
				return
			}
			result = cfapi.GatewayAccount{ID: "gateway"}
		case "POST /gateway":
			if a.gateway {
				t.Error("recreated Gateway")
			}
			a.gateway = true
			result = cfapi.GatewayAccount{ID: "gateway"}
		case "GET /devices/settings":
			if a.settings == nil {
				absent(404)
				return
			}
			result = a.settings
		case "PATCH /devices/settings":
			var patch map[string]any
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
				t.Error(err)
			}
			if a.settings == nil {
				a.settings = map[string]any{}
			}
			for k, v := range patch {
				if (k != "use_zt_virtual_ip" && k != "gateway_proxy_enabled" && k != "gateway_udp_proxy_enabled") || v != true || a.settings[k] == true {
					t.Errorf("unnecessary/unsafe setting patch %s=%v", k, v)
				}
				a.settings[k] = v
			}
			result = a.settings
		case "GET /zerotrust/connectivity_settings":
			if a.connectivity == nil {
				absent(404)
				return
			}
			result = a.connectivity
		case "PATCH /zerotrust/connectivity_settings":
			var patch map[string]any
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
				t.Error(err)
			}
			if len(patch) != 1 || patch["offramp_warp_enabled"] != true {
				t.Errorf("unsafe connectivity patch: %v", patch)
			}
			if a.connectivity == nil {
				a.connectivity = map[string]any{}
			}
			a.connectivity["offramp_warp_enabled"] = true
			result = a.connectivity
		case "GET /devices/policies":
			result = append([]cfapi.DeviceProfile{}, a.profiles...)
		case "POST /devices/policy":
			var p cfapi.DeviceProfile
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				t.Error(err)
			}
			p.PolicyID = fmt.Sprintf("profile-%d", len(a.profiles))
			a.profiles = append(a.profiles, p)
			result = p
		case "GET /access/apps":
			result = []cfapi.EnrollmentApp{}
			if a.app {
				result = []cfapi.EnrollmentApp{{ID: "warp", Type: "warp"}}
			}
		case "GET /access/identity_providers":
			result = append([]cfapi.EnrollmentIDP{}, a.idps...)
		case "POST /access/identity_providers":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if len(a.idps) != 0 || body["type"] != "onetimepin" {
				t.Errorf("unnecessary/unsafe IdP create: %v", body)
			}
			p := cfapi.EnrollmentIDP{ID: "pin", Type: "onetimepin"}
			a.idps = append(a.idps, p)
			result = p
		case "POST /access/apps":
			var body struct {
				Type        string                   `json:"type"`
				Policies    []cfapi.EnrollmentPolicy `json:"policies"`
				AllowedIDPs []string                 `json:"allowed_idps"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if a.app || body.Type != "warp" || len(body.Policies) != 1 || !ownerOnly(body.Policies[0], "owner@example.com") || len(body.AllowedIDPs) == 0 {
				t.Errorf("unsafe app creation: %+v", body)
			}
			if len(a.profiles) < 2 {
				t.Error("enrollment created before safe profiles")
			}
			a.app = true
			a.policies = body.Policies
			a.policies[0].ID = "owner"
			result = cfapi.EnrollmentApp{ID: "warp", Type: "warp"}
		case "GET /access/apps/warp/policies":
			result = append([]cfapi.EnrollmentPolicy{}, a.policies...)
		case "POST /access/apps/warp/policies":
			var p cfapi.EnrollmentPolicy
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				t.Error(err)
			}
			if !ownerOnly(p, "owner@example.com") {
				t.Errorf("unsafe policy: %+v", p)
			}
			p.ID = "owner"
			a.policies = append(a.policies, p)
			result = p
		default:
			if r.Method == "GET" && strings.HasPrefix(path, "/devices/policy/") {
				for _, p := range a.profiles {
					if strings.HasSuffix(path, "/"+p.PolicyID) {
						result = p
						if a.badUserReadback && p.Name == UserProfileName {
							p.Include = nil
							result = p
						}
					}
				}
			} else {
				t.Errorf("unexpected request %s %s", r.Method, path)
				absent(500)
				return
			}
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result}); err != nil {
			t.Error(err)
		}
	}
}

func TestFullSetupFreshPartialAndReady(t *testing.T) {
	for _, scenario := range []string{"fresh with active plan", "partial", "fully ready", "no plan", "OAuth billing unavailable", "organization forbidden"} {
		t.Run(scenario, func(t *testing.T) {
			a := &setupAccount{plan: true}
			if scenario == "no plan" {
				a.plan = false
			}
			if scenario == "organization forbidden" {
				a.orgDenied = true
			}
			if scenario == "OAuth billing unavailable" {
				a.billingDenied = true
			}
			if scenario == "partial" || scenario == "fully ready" {
				a.org = true
				a.gateway = true
				a.app = true
				a.idps = []cfapi.EnrollmentIDP{{ID: "pin", Type: "onetimepin"}}
				a.settings = map[string]any{"use_zt_virtual_ip": true, "gateway_proxy_enabled": true, "gateway_udp_proxy_enabled": false, "disable_for_time": 600.0}
				a.connectivity = map[string]any{"offramp_warp_enabled": false, "icmp_proxy_enabled": true, "future_flag": "preserve"}
			}
			server := httptest.NewServer(a.serve(t))
			defer server.Close()
			c := cfapi.New(cfapi.StaticToken("test"), "test")
			c.BaseURL = server.URL
			if scenario == "fully ready" {
				if _, err := EnsureSetup(context.Background(), c, "a", "owner@example.com"); err != nil {
					t.Fatal(err)
				}
				a.writes = nil
			}
			report, err := EnsureSetup(context.Background(), c, "a", "owner@example.com")
			if scenario == "no plan" {
				if err == nil || len(report.Manual) != 1 || !strings.Contains(report.Manual[0], "https://one.dash.cloudflare.com/a/settings/billing") || len(a.writes) != 1 {
					t.Fatalf("report=%+v err=%v writes=%v", report, err, a.writes)
				}
				return
			}
			if scenario == "organization forbidden" {
				if err == nil || len(a.writes) != 0 {
					t.Fatalf("err=%v writes=%v", err, a.writes)
				}
				return
			}
			if err != nil {
				t.Fatalf("err=%v writes=%v", err, a.writes)
			}
			if scenario == "fully ready" && (len(a.writes) != 0 || len(report.Changed) != 0 || len(report.Manual) != 0) {
				t.Fatalf("ready account changed: %+v %v", report, a.writes)
			}
			if scenario == "OAuth billing unavailable" && len(report.Manual) != 1 {
				t.Fatalf("billing gap not reported: %+v", report)
			}
			if scenario == "partial" && (a.settings["disable_for_time"] != 600.0 || a.connectivity["icmp_proxy_enabled"] != true || a.connectivity["future_flag"] != "preserve") {
				t.Fatal("unrelated settings changed")
			}
			if scenario != "fully ready" && len(report.Changed) == 0 {
				t.Fatal("missing changes report")
			}
			a.writes = nil
			again, err := EnsureSetup(context.Background(), c, "a", "owner@example.com")
			if err != nil || len(a.writes) != 0 || len(again.Changed) != 0 {
				t.Fatalf("second setup: %+v err=%v writes=%v", again, err, a.writes)
			}
		})
	}
}

func TestFullSetupRetainsPartialChangesOnEnrollmentFailure(t *testing.T) {
	a := &setupAccount{plan: true, badUserReadback: true}
	server := httptest.NewServer(a.serve(t))
	defer server.Close()
	c := cfapi.New(cfapi.StaticToken("test"), "test")
	c.BaseURL = server.URL
	report, err := EnsureSetup(context.Background(), c, "a", "owner@example.com")
	if err == nil || !strings.Contains(err.Error(), "safe Include profile did not verify") {
		t.Fatalf("expected readback failure, got %v", err)
	}
	if len(report.Changed) == 0 || !strings.Contains(strings.Join(report.Changed, "\n"), "created device profile "+UserProfileName) {
		t.Fatalf("partial changes lost: %+v", report)
	}
	for _, write := range a.writes {
		if write == "POST /access/apps" || strings.Contains(write, "/policies") {
			t.Fatalf("enrollment granted before safe routing: %v", a.writes)
		}
	}
}
