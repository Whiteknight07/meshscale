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

func TestSetupIdempotency(t *testing.T) {
	settings := map[string]any{"use_zt_virtual_ip": false, "gateway_proxy_enabled": true, "gateway_udp_proxy_enabled": false, "root_certificate_installation_enabled": true, "disable_for_time": 600}
	profiles := []cfapi.DeviceProfile{{Default: true, Enabled: true}, {PolicyID: "existing", Name: "Other", Enabled: true, Precedence: 10, Match: `identity.email == "someone@example.com"`}}
	patches, creates := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var result any
		switch r.Method + " " + r.URL.Path {
		case "GET /accounts/a/access/organizations":
			result = cfapi.Organization{AuthDomain: "team.cloudflareaccess.com"}
		case "GET /accounts/a/gateway":
			result = cfapi.GatewayAccount{ID: "gateway"}
		case "GET /accounts/a/zerotrust/connectivity_settings":
			result = cfapi.ConnectivitySettings{OfframpWARPEnabled: true}
		case "GET /accounts/a/devices/policies":
			result = profiles
		case "GET /accounts/a/devices/settings":
			result = settings
		case "PATCH /accounts/a/devices/settings":
			patches++
			var patch map[string]any
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
				t.Error(err)
			}
			if len(patch) != 2 || patch["use_zt_virtual_ip"] != true || patch["gateway_udp_proxy_enabled"] != true {
				t.Errorf("unsafe patch: %#v", patch)
			}
			for k, v := range patch {
				settings[k] = v
			}
			result = settings
		case "POST /accounts/a/devices/policy":
			creates++
			var raw map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
				t.Error(err)
			}
			if _, ok := raw["exclude"]; ok {
				t.Error("exclude must be omitted")
			}
			data, _ := json.Marshal(raw)
			var p cfapi.DeviceProfile
			if err := json.Unmarshal(data, &p); err != nil {
				t.Error(err)
			}
			if !matchingProfile(p, `identity.email == "warp_connector@team.cloudflareaccess.com"`) || p.Name != ProfileName || p.Precedence >= 10 {
				t.Errorf("incorrect profile: %#v", p)
			}
			p.PolicyID = "new"
			profiles = append(profiles, p)
			result = p
		default:
			t.Errorf("unexpected mutation/request: %s %s", r.Method, r.URL)
			http.Error(w, "unexpected", 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
	}))
	defer server.Close()
	client := cfapi.New(cfapi.StaticToken("test"), "test")
	client.BaseURL = server.URL
	first, err := EnsureAccountReady(context.Background(), client, "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Changed) != 3 || first.ProfileID != "new" || len(first.Manual) != 0 {
		t.Fatalf("report: %#v", first)
	}
	second, err := EnsureAccountReady(context.Background(), client, "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Changed) != 0 || len(second.AlreadyReady) != 7 || patches != 1 || creates != 1 {
		t.Fatalf("not idempotent: %#v patches %d creates %d", second, patches, creates)
	}
	if settings["disable_for_time"] != 600 || settings["root_certificate_installation_enabled"] != true || profiles[1].Name != "Other" {
		t.Fatal("unrelated settings changed")
	}
}

func TestSetupRefusesConflictingProfile(t *testing.T) {
	for _, p := range []cfapi.DeviceProfile{{Name: ProfileName}, {Name: "broad", Precedence: 0, Enabled: true}} {
		t.Run(p.Name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Errorf("mutation on conflict: %s", r.Method)
				}
				switch {
				case strings.HasSuffix(r.URL.Path, "organizations"):
					fmt.Fprint(w, `{"success":true,"result":{"auth_domain":"team.cloudflareaccess.com"}}`)
				case strings.HasSuffix(r.URL.Path, "/gateway"):
					fmt.Fprint(w, `{"success":true,"result":{"id":"gateway"}}`)
				case strings.HasSuffix(r.URL.Path, "policies"):
					json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []cfapi.DeviceProfile{p}})
				default:
					t.Errorf("unexpected %s", r.URL.Path)
				}
			}))
			defer server.Close()
			client := cfapi.New(cfapi.StaticToken("test"), "test")
			client.BaseURL = server.URL
			if _, err := EnsureAccountReady(context.Background(), client, "a"); err == nil {
				t.Fatal("wanted actionable conflict")
			}
		})
	}
}

func TestMatchingProfile(t *testing.T) {
	match := `identity.email == "warp_connector@team.cloudflareaccess.com"`
	base := cfapi.DeviceProfile{Enabled: true, Match: match, ServiceModeV2: cfapi.ServiceMode{Mode: "warp"}, TunnelProtocol: "masque", Include: []cfapi.SplitTunnelEntry{{Address: "100.96.0.0/12"}}}
	if !matchingProfile(base, match) {
		t.Fatal("matching profile rejected")
	}
	for _, mutate := range []func(*cfapi.DeviceProfile){
		func(p *cfapi.DeviceProfile) { p.Enabled = false },
		func(p *cfapi.DeviceProfile) { p.Exclude = []cfapi.SplitTunnelEntry{{Address: "10.0.0.0/8"}} },
		func(p *cfapi.DeviceProfile) {
			p.Include = append(p.Include, cfapi.SplitTunnelEntry{Address: "0.0.0.0/0"})
		},
		func(p *cfapi.DeviceProfile) { p.TunnelProtocol = "wireguard" },
		func(p *cfapi.DeviceProfile) { p.Match = `identity.email == "other@example.com"` },
	} {
		p := base
		mutate(&p)
		if matchingProfile(p, match) {
			t.Fatalf("unsafe profile accepted: %#v", p)
		}
	}
}
