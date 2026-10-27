package cfapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPublicationAPI(t *testing.T) {
	ctx := context.Background()
	for _, test := range []struct {
		name, method, path, result string
		invoke                     func(*Client) error
		check                      func(*testing.T, map[string]any)
	}{
		{name: "zones", method: "GET", path: "/zones", result: `[{"id":"mine","name":"example.com","status":"active","account":{"id":"account"}},{"id":"other","account":{"id":"another"}}]`, invoke: func(c *Client) error {
			zones, err := c.PublicationZones(ctx, "account")
			if err == nil && (len(zones) != 1 || zones[0].ID != "mine") {
				return fmt.Errorf("account filter failed")
			}
			return err
		}},
		{name: "records", method: "GET", path: "/zones/zone/dns_records", result: `[{"id":"dns","type":"TXT","name":"_acme-challenge.ashburn.mesh.example.com","comment":"managed-by: meshscale"}]`, invoke: func(c *Client) error { _, err := c.PublicationRecords(ctx, "zone"); return err }},
		{name: "record read", method: "GET", path: "/zones/zone/dns_records/dns", result: `{"id":"dns"}`, invoke: func(c *Client) error { _, err := c.PublicationRecord(ctx, "zone", "dns"); return err }},
		{name: "record create", method: "POST", path: "/zones/zone/dns_records", result: `{"id":"dns"}`, invoke: func(c *Client) error {
			_, err := c.CreatePublicationRecord(ctx, "zone", DNSRecord{Type: "A", Name: "ashburn.mesh.example.com", Content: "100.96.0.7", TTL: 60, Comment: "managed-by: meshscale"})
			return err
		}, check: func(t *testing.T, b map[string]any) {
			if b["comment"] != "managed-by: meshscale" || b["proxied"] != false {
				t.Fatal("DNS payload", b)
			}
		}},
		{name: "record delete", method: "DELETE", path: "/zones/zone/dns_records/dns", result: `{"id":"dns"}`, invoke: func(c *Client) error { return c.DeletePublicationRecord(ctx, "zone", "dns") }},
		{name: "tunnel create", method: "POST", path: "/accounts/account/cfd_tunnel", result: `{"id":"tunnel"}`, invoke: func(c *Client) error {
			_, err := c.CreatePublicTunnel(ctx, "account", "meshscale-funnel-ashburn")
			return err
		}, check: func(t *testing.T, b map[string]any) {
			if b["config_src"] != "cloudflare" {
				t.Fatal("not remotely managed", b)
			}
		}},
		{name: "ingress", method: "PUT", path: "/accounts/account/cfd_tunnel/tunnel/configurations", result: `{}`, invoke: func(c *Client) error {
			return c.ConfigurePublicTunnel(ctx, "account", "tunnel", "ashburn-funnel.example.com", "http://127.0.0.1:8000", &TunnelOrigin{Access: &TunnelAccess{TeamName: "team", AudTag: []string{"aud"}, Required: true}})
		}, check: func(t *testing.T, b map[string]any) {
			config := b["config"].(map[string]any)
			ingress := config["ingress"].([]any)
			if len(ingress) != 2 || ingress[1].(map[string]any)["service"] != "http_status:404" {
				t.Fatal("missing catch-all", b)
			}
			origin := ingress[0].(map[string]any)["originRequest"].(map[string]any)
			access := origin["access"].(map[string]any)
			if access["required"] != true || access["teamName"] != "team" {
				t.Fatal("missing per-ingress JWT validation", b)
			}
		}},
		{name: "token", method: "GET", path: "/accounts/account/cfd_tunnel/tunnel/token", result: `"secret"`, invoke: func(c *Client) error {
			value, err := c.PublicTunnelToken(ctx, "account", "tunnel")
			if err == nil && value != "secret" {
				t.Fatal("bad token")
			}
			return err
		}},
		{name: "tunnel delete", method: "DELETE", path: "/accounts/account/cfd_tunnel/tunnel", result: `{"id":"tunnel"}`, invoke: func(c *Client) error { return c.DeletePublicTunnel(ctx, "account", "tunnel") }},
		{name: "access create", method: "POST", path: "/accounts/account/access/apps", result: `{"id":"app","aud":"aud"}`, invoke: func(c *Client) error {
			app, err := c.CreatePublicApplication(ctx, "account", PublicApplication{Type: "self_hosted", Domain: "ashburn-funnel.example.com"})
			if err == nil && app.AUD != "aud" {
				t.Fatal("missing audience")
			}
			return err
		}},
		{name: "access delete", method: "DELETE", path: "/accounts/account/access/apps/app", result: `{"id":"app"}`, invoke: func(c *Client) error { return c.DeletePublicApplication(ctx, "account", "app") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != test.method || r.URL.Path != test.path || r.Header.Get("Authorization") != "Bearer token" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				if test.check != nil {
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					} else {
						test.check(t, body)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"success":true,"result":%s}`, test.result)
			}))
			defer server.Close()
			client := New(StaticToken("token"), "test")
			client.BaseURL = server.URL
			if err := test.invoke(client); err != nil {
				t.Fatal(err)
			}
		})
	}
}
