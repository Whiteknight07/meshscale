package native

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T) ([]byte, Registration) {
	t.Helper()
	data, err := os.ReadFile("testdata/registration.json")
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Result Registration `json:"result"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	return data, envelope.Result
}
func TestRegistrationEvidence(t *testing.T) {
	_, r := fixture(t)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	endpoint, err := r.Config.Peers[0].Endpoint.Address()
	if err != nil || endpoint != "162.159.193.9:2408" {
		t.Fatalf("endpoint=%s err=%v", endpoint, err)
	}
	ips, err := r.IPs()
	if err != nil || len(ips) != 2 {
		t.Fatalf("ips=%v err=%v", ips, err)
	}
	if r.Policy.Protocol != "masque" || r.Policy.ID == "" {
		t.Fatalf("policy=%+v", r.Policy)
	}
}
func TestRegisterAndRefresh(t *testing.T) {
	data, old := fixture(t)
	token := base64.StdEncoding.EncodeToString([]byte(`{"a":"account","t":"node","s":"REDACTED"}`))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			if r.URL.Path != "/v1/accounts/account/warp_connector" || r.Header.Get("Authorization") != "" {
				t.Error("wrong registration path or administrative token sent")
			}
			raw, _ := io.ReadAll(r.Body)
			var body map[string]string
			json.Unmarshal(raw, &body)
			if body["key"] != old.Key || body["warp_connector_token"] != token || body["type"] != "linux" || len(body) != 4 {
				t.Errorf("unexpected enrollment fields")
			}
			w.Write(data)
		case "GET":
			if r.URL.Path != "/v1/accounts/account/reg/"+old.ID || r.Header.Get("Authorization") != "Bearer "+old.Token {
				t.Error("wrong refresh identity")
			}
			refreshed := old
			refreshed.Token = ""
			json.NewEncoder(w).Encode(map[string]any{"success": true, "result": refreshed})
		case "DELETE":
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	api := &API{BaseURL: server.URL, HTTP: server.Client()}
	r, err := api.Register(context.Background(), "account", "node", "meshscale-native-fixture", token, old.Key)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := api.Refresh(context.Background(), "account", r)
	if err != nil || fresh.Token != old.Token {
		t.Fatalf("lost bearer on refresh: %v", err)
	}
	if err := api.Deregister(context.Background(), "account", fresh); err != nil {
		t.Fatal(err)
	}
}
func TestDeviceAPIErrorsWithholdBodies(t *testing.T) {
	for _, code := range []int{200, 401, 403, 500} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			io.WriteString(w, `{"secret":"DO-NOT-LOG"}`)
		}))
		api := &API{BaseURL: server.URL, HTTP: server.Client()}
		_, old := fixture(t)
		_, err := api.Refresh(context.Background(), "account", old)
		server.Close()
		if err == nil || strings.Contains(err.Error(), "DO-NOT-LOG") {
			t.Fatalf("unsafe/missing error: %v", err)
		}
		if code != 200 {
			var e *HTTPError
			if !errors.As(err, &e) || e.Status != code {
				t.Fatalf("lost HTTP status: %v", err)
			}
		}
	}
}
func TestRegistrationValidation(t *testing.T) {
	cases := map[string]func(*Registration){
		"outside IPv4":     func(r *Registration) { r.Config.Interface.Addresses.V4 = "1.1.1.1" },
		"outside IPv6":     func(r *Registration) { r.Config.Interface.Addresses.V6 = "2606:4700:cf2::1" },
		"bad peer key":     func(r *Registration) { r.Config.Peers[0].PublicKey = "secret" },
		"missing ports":    func(r *Registration) { r.Config.Peers[0].Endpoint.Ports = nil },
		"private endpoint": func(r *Registration) { r.Config.Peers[0].Endpoint = Endpoint{V4: "127.0.0.1:2408"} },
		"bad id":           func(r *Registration) { r.ID = "other" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			_, r := fixture(t)
			mutate(&r)
			if err := r.Validate(); err == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
	for _, token := range []string{"broken", base64.StdEncoding.EncodeToString([]byte(`{"a":"other","t":"node","s":"REDACTED"}`)), base64.StdEncoding.EncodeToString([]byte(`{"a":"account","t":"node"}`))} {
		if err := ValidateNodeToken(token, "account", "node"); err == nil {
			t.Fatal("accepted mismatched/missing token")
		}
	}
}
