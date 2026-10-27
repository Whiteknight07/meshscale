package cfapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInfrastructureEndpoints(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name, method, path, result string
		call                       func(*Client) error
	}{{"read CA", "GET", "/access/gateway_ca", `{"id":"ca","public_key":"ssh-key"}`, func(c *Client) error {
		ca, e := c.SSHCA(ctx, "acc")
		if e == nil && ca.ID != "ca" {
			t.Error(ca)
		}
		return e
	}}, {"create CA", "POST", "/access/gateway_ca", `{"id":"ca","public_key":"ssh-key"}`, func(c *Client) error { _, e := c.CreateSSHCA(ctx, "acc"); return e }}, {"list targets", "GET", "/infrastructure/targets", `[{"id":"target","hostname":"server","ip":{"ipv4":{"ip_addr":"100.96.0.2","virtual_network_id":"vnet"}}}]`, func(c *Client) error {
		r, e := c.ListInfrastructureTargets(ctx, "acc")
		if e == nil && (len(r) != 1 || r[0].IP.IPv4.Address != "100.96.0.2" || r[0].IP.IPv4.VirtualNetworkID != "vnet") {
			t.Error(r)
		}
		return e
	}}, {"read target", "GET", "/infrastructure/targets/target", `{"id":"target","hostname":"server","ip":{"ipv4":{"ip_addr":"100.96.0.2"}}}`, func(c *Client) error {
		target, e := c.InfrastructureTarget(ctx, "acc", "target")
		if e == nil && target.ID != "target" {
			t.Error(target)
		}
		return e
	}}, {"create target", "POST", "/infrastructure/targets", `{"id":"target"}`, func(c *Client) error {
		_, e := c.PutInfrastructureTarget(ctx, "acc", InfrastructureTarget{Hostname: "server"})
		return e
	}}, {"update target", "PUT", "/infrastructure/targets/target", `{"id":"target"}`, func(c *Client) error {
		_, e := c.PutInfrastructureTarget(ctx, "acc", InfrastructureTarget{ID: "target", Hostname: "server"})
		return e
	}}, {"delete target", "DELETE", "/infrastructure/targets/target", `{}`, func(c *Client) error { return c.DeleteInfrastructureTarget(ctx, "acc", "target") }}, {"create app", "POST", "/access/apps", `{"id":"app","policies":[{"id":"policy"}]}`, func(c *Client) error {
		a, e := c.PutInfrastructureApplication(ctx, "acc", InfrastructureApplication{Type: "infrastructure"})
		if e == nil && (a.ID != "app" || len(a.Policies) != 1 || a.Policies[0].ID != "policy") {
			t.Error(a)
		}
		return e
	}}, {"update app", "PUT", "/access/apps/app", `{"id":"app"}`, func(c *Client) error {
		_, e := c.PutInfrastructureApplication(ctx, "acc", InfrastructureApplication{ID: "app", Type: "infrastructure"})
		return e
	}}, {"delete app", "DELETE", "/access/apps/app", `{}`, func(c *Client) error { return c.DeleteInfrastructureApplication(ctx, "acc", "app") }}} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tc.method || r.URL.Path != "/accounts/acc"+tc.path {
					t.Errorf("%s %s", r.Method, r.URL)
				}
				if tc.name == "create CA" && r.ContentLength > 0 {
					t.Error("CA creation must be bodyless")
				}
				if tc.method == "PUT" || tc.method == "POST" && tc.name != "create CA" {
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
				}
				fmt.Fprintf(w, `{"success":true,"result":%s}`, tc.result)
			}))
			defer srv.Close()
			c := New(StaticToken("test"), "test")
			c.BaseURL = srv.URL
			if err := tc.call(c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInfrastructureApplicationLoadsEffectivePolicies(t *testing.T) {
	calls := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.URL.Path {
		case "/accounts/acc/access/apps/app":
			reply(w, InfrastructureApplication{ID: "app", Type: "infrastructure"})
		case "/accounts/acc/access/apps/app/policies":
			fmt.Fprint(w, `{"success":true,"result":[{"id":"policy","decision":"allow","include":[{"email":{"email":"owner@example.com"}}],"exclude":[{"everyone":{}}],"connection_rules":{"ssh":{"usernames":["alice"]}}}]}`)
		default:
			t.Errorf("unexpected URL %s", r.URL)
		}
	})
	app, err := c.InfrastructureApplication(t.Context(), "acc", "app")
	if err != nil || calls != 2 || len(app.Policies) != 1 || len(app.Policies[0].Exclude) != 1 {
		t.Fatalf("lost effective policy: %+v %v", app, err)
	}
}
