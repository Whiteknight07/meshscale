package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/names"
)

func TestDNSSyncDryRunApplyAndList(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("MESHSCALE_DNS_SUFFIX", "mesh")
	other := cfapi.GatewayRule{ID: "customer", Name: "Do Not Inspect", Action: "off"}
	rules := []cfapi.GatewayRule{other}
	writes := 0
	client := commandAPI(t, func(w http.ResponseWriter, r *http.Request) {
		var result any
		switch r.URL.Path {
		case "/accounts/acc/devices/registrations":
			result = []cfapi.Registration{{ID: "reg", Device: cfapi.RegistrationDevice{ID: "device", Name: "Phone"}, VirtualIPv4: "100.96.0.4"}}
		case "/accounts/acc/devices/physical-devices":
			result = []cfapi.PhysicalDevice{}
		case "/accounts/acc/warp_connector":
			result = []cfapi.MeshNode{}
		case "/accounts/acc/gateway/rules":
			switch r.Method {
			case "GET":
				result = rules
			case "POST":
				var rule cfapi.GatewayRule
				if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
					t.Fatal(err)
				}
				rule.ID = "dns-rule"
				rules = append(rules, rule)
				result = rule
				writes++
			default:
				t.Errorf("unexpected method: %s", r.Method)
			}
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
	})
	var out bytes.Buffer
	if err := syncDNS(t.Context(), &out, client, "acc", true); err != nil || writes != 0 || !strings.Contains(out.String(), "create\tphone.mesh\t100.96.0.4") {
		t.Fatalf("dry-run: %s, writes=%d, err=%v", out.String(), writes, err)
	}
	out.Reset()
	if err := syncDNS(t.Context(), &out, client, "acc", false); err != nil || writes != 1 {
		t.Fatalf("sync: %s, writes=%d, err=%v", out.String(), writes, err)
	}
	out.Reset()
	if err := syncDNS(t.Context(), &out, client, "acc", false); err != nil || writes != 1 || !strings.Contains(out.String(), "0 change(s)") {
		t.Fatalf("idempotent sync: %s, writes=%d, err=%v", out.String(), writes, err)
	}
	out.Reset()
	if err := writeDNSRules(&out, rules); err != nil || !strings.Contains(out.String(), "phone.mesh") || strings.Contains(out.String(), "Do Not Inspect") {
		t.Fatalf("list: %s, err=%v", out.String(), err)
	}
	if rules[0].Name != other.Name || rules[0].Action != other.Action || names.Owner(rules[1]) != "device/reg" {
		t.Fatalf("ownership: %v", rules)
	}
}

func TestDNSNamesInStatusAndWhois(t *testing.T) {
	t.Setenv("MESHSCALE_DNS_SUFFIX", "MY.MESH")
	devices := []meshDevice{
		{ID: "1", Kind: "node", Name: "Mac Laptop", IPv4: "100.96.0.2"},
		{ID: "2", Kind: "device", Name: "Phone", IPv6: "2606:4700:cf1::3"},
	}
	if err := assignDNSNames(devices); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"mac-laptop", "MAC-LAPTOP.MY.MESH.", "100.96.0.2", "::ffff:100.96.0.2"} {
		d, ip, err := findMeshNameOrIP(devices, query)
		if err != nil || d.ID != "1" || ip != "100.96.0.2" {
			t.Errorf("%s: %v %s %v", query, d, ip, err)
		}
	}
	for _, query := range []string{"missing.mesh", "100.96.0.99", "100.96.0.2/32", "fe80::1%eth0"} {
		if _, _, err := findMeshNameOrIP(devices, query); err == nil {
			t.Errorf("accepted %s", query)
		}
	}
	var out bytes.Buffer
	if err := writeStatus(&out, devices, false, fixtureNow); err != nil || !strings.Contains(out.String(), "mac-laptop.my.mesh") {
		t.Fatalf("status: %s %v", out.String(), err)
	}
	out.Reset()
	if err := writeStatus(&out, devices, true, fixtureNow); err != nil || !strings.Contains(out.String(), `"dns_name": "phone.my.mesh"`) {
		t.Fatalf("status JSON: %s %v", out.String(), err)
	}
	t.Setenv("MESHSCALE_DNS_SUFFIX", "invalid_suffix")
	if err := assignDNSNames(devices); err == nil {
		t.Fatal("accepted invalid suffix")
	}
}
