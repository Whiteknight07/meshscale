package cfapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func testClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	s := httptest.NewServer(handler)
	t.Cleanup(s.Close)
	c := New(StaticToken("test-token"), "1.2.3")
	c.BaseURL, c.HTTPClient = s.URL, s.Client()
	return c
}

func reply(w http.ResponseWriter, result any) {
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result})
}

func TestPagePaginationAndHeaders(t *testing.T) {
	calls := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/accounts" || r.URL.Query().Get("per_page") != "100" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("User-Agent") != "meshscale/1.2.3" || r.Header.Get("Accept") != "application/json" {
			t.Errorf("unexpected headers: %v", r.Header)
		}
		if r.URL.Query().Get("page") != fmt.Sprint(calls) {
			t.Errorf("unexpected page: %s", r.URL)
		}
		fmt.Fprintf(w, `{"success":true,"result":[{"id":"a%d","name":"Account %d"}],"result_info":{"page":%d,"per_page":1,"count":1,"total_count":2}}`, calls, calls, calls)
	})
	accounts, err := c.ListAccounts(context.Background())
	if err != nil || len(accounts) != 2 || accounts[1].ID != "a2" || calls != 2 {
		t.Fatalf("got %#v, %v (%d calls)", accounts, err, calls)
	}
}

func TestCursorPaginationAndRegistrationShape(t *testing.T) {
	calls := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/accounts/acc/devices/registrations" || r.URL.Query().Has("page") {
			t.Errorf("unexpected URL: %s", r.URL)
		}
		if calls == 1 {
			fmt.Fprint(w, `{"success":true,"result":[{"id":"r1","device":{"id":"d1","name":"laptop","client_version":"2026.4"},"virtual_ipv4":"100.96.0.1","virtual_ipv6":"2606:4700:cf1:1000::1","last_seen_at":"2026-10-26T01:02:03Z","user":{"email":"alice@example.com"}}],"result_info":{"count":1,"per_page":100,"cursor":"next+/=","total_count":null}}`)
		} else {
			if r.URL.Query().Get("cursor") != "next+/=" {
				t.Errorf("unexpected cursor: %s", r.URL)
			}
			fmt.Fprint(w, `{"success":true,"result":[{"id":"r2","device":{"id":"d2","name":"phone"},"virtual_ipv4":null,"virtual_ipv6":null,"last_seen_at":null,"user":null}],"result_info":{"count":1,"per_page":100,"cursor":""}}`)
		}
	})
	regs, err := c.ListRegistrations(context.Background(), "acc")
	if err != nil || len(regs) != 2 || calls != 2 {
		t.Fatalf("got %#v, %v (%d calls)", regs, err, calls)
	}
	if regs[0].Device.ID != "d1" || regs[0].User.Email != "alice@example.com" || regs[0].LastSeenAt == nil || regs[0].VirtualIPv6 != "2606:4700:cf1:1000::1" || regs[1].LastSeenAt != nil || regs[1].VirtualIPv4 != "" {
		t.Fatalf("wrong decoded registration: %#v", regs)
	}
}

func TestRepeatedCursorFails(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true,"result":[{"id":"r1"}],"result_info":{"cursor":"same","count":1,"per_page":1}}`)
	})
	_, err := c.ListRegistrations(context.Background(), "acc")
	if err == nil || !strings.Contains(err.Error(), "repeated pagination cursor") {
		t.Fatalf("got %v", err)
	}
}

func TestPageMetadataVariants(t *testing.T) {
	for _, tc := range []struct {
		name, info string
		wantCalls  int
	}{
		{"total pages", `"result_info":{"page":%d,"per_page":1,"total_pages":2}`, 2},
		{"short page", `"result_info":{"page":%d,"per_page":2,"count":1}`, 1},
		{"no metadata", `"unused":%d`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				fmt.Fprintf(w, `{"success":true,"result":[{"id":"a"}],`+tc.info+`}`, calls)
			})
			_, err := c.ListAccounts(context.Background())
			if err != nil || calls != tc.wantCalls {
				t.Fatalf("got %v (%d calls)", err, calls)
			}
		})
	}
}

func TestAPIErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   string
		apiErr bool
	}{
		{"forbidden", 403, `{"success":false,"errors":[{"code":10000,"message":"Authentication error","error_chain":[{"code":42,"message":"missing scope"}]}],"messages":["try again"]}`, "10000: Authentication error: 42: missing scope", true},
		{"unsuccessful 200", 200, `{"success":false,"errors":[],"messages":["permission required"]}`, "permission required", true},
		{"HTTP error despite success", 429, `{"success":true,"errors":[],"result":{}}`, "HTTP 429", true},
		{"errors despite success", 200, `{"success":true,"errors":[{"code":1,"message":"bad request"}]}`, "bad request", true},
		{"non JSON", 502, `<html>bad gateway</html>`, "HTTP 502", true},
		{"wrong result", 200, `{"success":true,"result":"unexpected"}`, "decode result", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			})
			_, err := c.Account(context.Background(), "acc")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			var apiErr *APIError
			if errors.As(err, &apiErr) != tc.apiErr {
				t.Fatalf("APIError mismatch: %T", err)
			}
			if apiErr != nil && apiErr.StatusCode != tc.status {
				t.Fatalf("wrong status: %d", apiErr.StatusCode)
			}
		})
	}
}

type tokenFunc func(context.Context) (string, error)

func (f tokenFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

func TestTokensAndContext(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		reply(w, Account{ID: "acc"})
	})
	calls := 0
	c.Tokens = tokenFunc(func(ctx context.Context) (string, error) {
		calls++
		return "test-token", nil
	})
	for range 2 {
		if _, err := c.Account(context.Background(), "acc"); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatalf("token fetched %d times", calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Account(ctx, "acc"); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	wantErr := errors.New("refresh failed")
	c.Tokens = tokenFunc(func(context.Context) (string, error) { return "", wantErr })
	if _, err := c.Account(context.Background(), "acc"); !errors.Is(err, wantErr) {
		t.Fatalf("got %v", err)
	}
}

func TestTypedMethods(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name, method, path, result string
		body                       map[string]any
		call                       func(*Client) error
	}{
		{"account", "GET", "/accounts/acc", `{"id":"acc","name":"Example"}`, nil, func(c *Client) error {
			a, e := c.Account(ctx, "acc")
			if e == nil && a.Name != "Example" {
				t.Error(a)
			}
			return e
		}},
		{"physical devices", "GET", "/accounts/acc/devices/physical-devices", `[{"id":"d","name":"host","device_type":"linux","last_seen_at":null,"last_seen_user":{"email":"user@example.com"},"last_seen_registration":{"id":"r"}}]`, nil, func(c *Client) error {
			d, e := c.ListPhysicalDevices(ctx, "acc")
			if e == nil && (len(d) != 1 || d[0].DeviceType != "linux" || d[0].LastSeenRegistration.ID != "r") {
				t.Error(d)
			}
			return e
		}},
		{"nodes", "GET", "/accounts/acc/warp_connector", `[{"id":"n","name":"server","status":"healthy","conns_active_at":"2026-10-26T00:00:00Z","conns_inactive_at":null}]`, nil, func(c *Client) error {
			d, e := c.ListMeshNodes(ctx, "acc")
			if e == nil && (len(d) != 1 || d[0].Status != "healthy" || d[0].ConnsActiveAt == nil) {
				t.Error(d)
			}
			return e
		}},
		{"create node", "POST", "/accounts/acc/warp_connector", `{"id":"n","name":"server"}`, map[string]any{"name": "server", "ha": true}, func(c *Client) error {
			_, e := c.CreateMeshNode(ctx, "acc", CreateMeshNodeParams{Name: "server", HA: true})
			return e
		}},
		{"delete node", "DELETE", "/accounts/acc/warp_connector/n", `null`, nil, func(c *Client) error { return c.DeleteMeshNode(ctx, "acc", "n") }},
		{"node token", "GET", "/accounts/acc/warp_connector/n/token", `"connector-token"`, nil, func(c *Client) error {
			s, e := c.MeshNodeToken(ctx, "acc", "n")
			if e == nil && s != "connector-token" {
				t.Error("wrong token result")
			}
			return e
		}},
		{"routes", "GET", "/accounts/acc/teamnet/routes", `[{"id":"r","network":"10.0.0.0/24","tunnel_id":"n","comment":"LAN"}]`, nil, func(c *Client) error {
			d, e := c.ListRoutes(ctx, "acc")
			if e == nil && (len(d) != 1 || d[0].TunnelID != "n") {
				t.Error(d)
			}
			return e
		}},
		{"create route", "POST", "/accounts/acc/teamnet/routes", `{"id":"r"}`, map[string]any{"network": "10.0.0.0/24", "tunnel_id": "n", "comment": "LAN"}, func(c *Client) error {
			_, e := c.CreateRoute(ctx, "acc", CreateRouteParams{Network: "10.0.0.0/24", TunnelID: "n", Comment: "LAN"})
			return e
		}},
		{"delete route", "DELETE", "/accounts/acc/teamnet/routes/r", `null`, nil, func(c *Client) error { return c.DeleteRoute(ctx, "acc", "r") }},
		{"settings", "GET", "/accounts/acc/devices/settings", `{"use_zt_virtual_ip":true,"gateway_proxy_enabled":true,"gateway_udp_proxy_enabled":false}`, nil, func(c *Client) error {
			s, e := c.DeviceSettings(ctx, "acc")
			if e == nil && (!s.UseZTVirtualIP || !s.GatewayProxyEnabled || s.GatewayUDPProxyEnabled) {
				t.Error(s)
			}
			return e
		}},
		{"patch false setting", "PATCH", "/accounts/acc/devices/settings", `{}`, map[string]any{"use_zt_virtual_ip": false}, func(c *Client) error {
			v := false
			_, e := c.UpdateDeviceSettings(ctx, "acc", DeviceSettingsPatch{UseZTVirtualIP: &v})
			return e
		}},
		{"profiles", "GET", "/accounts/acc/devices/policies", `[{"policy_id":"p","default":true,"service_mode_v2":{"mode":"warp"}}]`, nil, func(c *Client) error {
			d, e := c.ListDeviceProfiles(ctx, "acc")
			if e == nil && (len(d) != 1 || d[0].PolicyID != "p" || d[0].ServiceModeV2.Mode != "warp") {
				t.Error(d)
			}
			return e
		}},
		{"create profile singular endpoint", "POST", "/accounts/acc/devices/policy", `{"policy_id":"p"}`, map[string]any{"name": "Mesh", "tunnel_protocol": "masque", "exclude": []any{}}, func(c *Client) error {
			empty := []SplitTunnelEntry{}
			_, e := c.CreateDeviceProfile(ctx, "acc", CreateDeviceProfileParams{Name: "Mesh", TunnelProtocol: "masque", Exclude: &empty})
			return e
		}},
		{"organization", "GET", "/accounts/acc/access/organizations", `{"name":"Example","auth_domain":"example.cloudflareaccess.com"}`, nil, func(c *Client) error {
			d, e := c.Organization(ctx, "acc")
			if e == nil && d.AuthDomain != "example.cloudflareaccess.com" {
				t.Error(d)
			}
			return e
		}},
		{"service tokens", "GET", "/accounts/acc/access/service_tokens", `[{"id":"s","name":"headless","client_id":"client","expires_at":null}]`, nil, func(c *Client) error {
			d, e := c.ListServiceTokens(ctx, "acc")
			if e == nil && (len(d) != 1 || d[0].ClientID != "client") {
				t.Error(d)
			}
			return e
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tc.method || r.URL.Path != tc.path {
					t.Errorf("got %s %s, want %s %s", r.Method, r.URL.Path, tc.method, tc.path)
				}
				if tc.body != nil {
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if !reflect.DeepEqual(body, tc.body) {
						t.Errorf("body %#v, want %#v", body, tc.body)
					}
					if r.Header.Get("Content-Type") != "application/json" {
						t.Error("missing JSON content type")
					}
				} else if r.ContentLength > 0 {
					t.Error("unexpected request body")
				}
				fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":%s}`, tc.result)
			})
			if err := tc.call(c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDeleteNoContent(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	if err := c.DeleteMeshNode(context.Background(), "acc", "node"); err != nil {
		t.Fatal(err)
	}
}
