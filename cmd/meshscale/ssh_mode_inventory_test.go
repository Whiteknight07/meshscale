package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

func TestSSHModeInventoryFailureAllowsPlainSSH(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			defer server.Close()
			client := cfapi.New(cfapi.StaticToken("test-token"), "test")
			client.BaseURL = server.URL
			devices := []meshDevice{{Name: "server", IPv4: "100.96.0.1", SSHMode: "cloudflare"}}
			if err := assignSSHMode(t.Context(), client, "account", devices); err != nil {
				t.Fatal("optional SSH inventory blocked SSH", err)
			}
			if devices[0].SSHMode != "unknown" {
				t.Fatalf("mode = %q", devices[0].SSHMode)
			}
			if _, err := resolveSSHTarget(devices, "server"); err != nil {
				t.Fatal("plain SSH target unavailable", err)
			}
		})
	}
}
