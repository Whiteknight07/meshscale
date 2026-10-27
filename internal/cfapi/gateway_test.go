package cfapi

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestGatewayMethods(t *testing.T) {
	rule := GatewayRule{ID: "rule", Name: "meshscale dns: node.mesh", Enabled: true, Action: "override", Filters: []string{"dns"}, Traffic: `dns.fqdn == "node.mesh"`, RuleSettings: GatewayRuleSettings{OverrideIPs: []string{"100.96.0.2"}}}
	var methods []string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		path := "/accounts/acc/gateway/rules"
		if r.Method == "PUT" || r.Method == "DELETE" {
			path += "/rule"
		}
		if r.URL.Path != path || r.URL.RawQuery != "" {
			t.Errorf("unexpected URL: %s", r.URL)
		}
		switch r.Method {
		case "GET":
			reply(w, []GatewayRule{rule})
		case "POST", "PUT":
			var body GatewayRule
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.ID != "" || body.ReadOnly || body.Action != "override" || body.RuleSettings.OverrideIPs[0] != "100.96.0.2" {
				t.Errorf("bad write: %+v", body)
			}
			reply(w, rule)
		case "DELETE":
			w.WriteHeader(http.StatusNoContent)
		}
	})
	ctx := t.Context()
	rules, err := c.ListGatewayRules(ctx, "acc")
	if err != nil || len(rules) != 1 || rules[0].RuleSettings.OverrideIPs[0] != "100.96.0.2" {
		t.Fatalf("list: %v, %v", rules, err)
	}
	if _, err := c.CreateGatewayRule(ctx, "acc", rule); err != nil {
		t.Fatal(err)
	}
	if _, err := c.UpdateGatewayRule(ctx, "acc", "rule", rule); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteGatewayRule(ctx, "acc", "rule"); err != nil {
		t.Fatal(err)
	}
	if len(methods) != 4 {
		t.Fatal(methods)
	}
}
