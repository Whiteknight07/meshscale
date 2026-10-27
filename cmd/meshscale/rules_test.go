package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/devicesync"
	"github.com/Whiteknight07/meshscale/internal/rules"
)

func TestRulesSyncAndReset(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"rules":[{"from":["alice@example.com"],"to":["Phone:22"]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	other := cfapi.GatewayRule{ID: "customer", Name: "Default deny for private traffic", Filters: []string{"l4"}, Precedence: 10000}
	existing := []cfapi.GatewayRule{other}
	writes := 0
	client := commandAPI(t, func(w http.ResponseWriter, r *http.Request) {
		var result any
		switch r.URL.Path {
		case "/accounts/acc/gateway/lists":
			result = []cfapi.GatewayList{}
		case "/accounts/acc/devices/registrations":
			result = []cfapi.Registration{{ID: "reg", Device: cfapi.RegistrationDevice{ID: "device", Name: "Phone"}, User: cfapi.User{Email: "alice@example.com"}, VirtualIPv4: "100.96.0.4"}}
		case "/accounts/acc/devices/physical-devices":
			result = []cfapi.PhysicalDevice{}
		case "/accounts/acc/warp_connector":
			result = []cfapi.MeshNode{}
		case "/accounts/acc/gateway/rules":
			switch r.Method {
			case "GET":
				result = existing
			case "POST":
				var rule cfapi.GatewayRule
				if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
					t.Error(err)
				}
				rule.ID = strings.TrimPrefix(rule.Name, rules.RulePrefix)
				existing = append(existing, rule)
				result = rule
				writes++
			default:
				t.Errorf("unexpected method %s", r.Method)
			}
		default:
			if r.Method != "DELETE" || !strings.HasPrefix(r.URL.Path, "/accounts/acc/gateway/rules/") {
				t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				break
			}
			id := strings.TrimPrefix(r.URL.Path, "/accounts/acc/gateway/rules/")
			if id == "customer" {
				t.Error("customer deletion")
			}
			for i, rule := range existing {
				if rule.ID == id {
					existing = append(existing[:i], existing[i+1:]...)
					break
				}
			}
			writes++
			result = map[string]string{"id": id}
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
	})
	var out bytes.Buffer
	if err := SyncRules(t.Context(), &out, client, "acc", path, true); err != nil || writes != 0 || !strings.Contains(out.String(), "default-deny") {
		t.Fatalf("dry: %s %v writes=%d", out.String(), err, writes)
	}
	out.Reset()
	if err := SyncRules(t.Context(), &out, client, "acc", path, false); err != nil || writes != 2 {
		t.Fatalf("sync: %s %v writes=%d", out.String(), err, writes)
	}
	out.Reset()
	if err := SyncRules(t.Context(), &out, client, "acc", path, false); err != nil || writes != 2 || !strings.Contains(out.String(), "0 change(s)") {
		t.Fatalf("repeat: %s %v writes=%d", out.String(), err, writes)
	}
	if err := resetRules(t.Context(), &out, client, "acc"); err != nil || writes != 4 || len(existing) != 1 || !reflect.DeepEqual(existing[0], other) {
		t.Fatalf("reset: %v writes=%d existing=%v", err, writes, existing)
	}
}

func TestRulesOptionalFileAndHook(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := SyncRules(t.Context(), &bytes.Buffer{}, nil, "acc", "", false); err != nil {
		t.Fatal(err)
	}
	if err := SyncRules(t.Context(), &bytes.Buffer{}, nil, "acc", "/missing/policy", false); err == nil {
		t.Fatal("missing explicit file accepted")
	}
	// The registry can safely call the rules hook without credentials when no
	// default file exists. Other registered hooks use an empty API inventory.
	client := commandAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("unexpected write: %s", r.Method)
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []any{}})
	})
	if err := devicesync.Default.Run(t.Context(), devicesync.Snapshot{Client: client, Account: "acc"}); err != nil {
		t.Fatal(err)
	}
}
