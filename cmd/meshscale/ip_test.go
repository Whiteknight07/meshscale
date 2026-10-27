package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/warpcli"
)

func TestIPFlags(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want int
	}{
		{nil, 4}, {[]string{"-4"}, 4}, {[]string{"-6"}, 6},
	} {
		got, err := parseIPFlags(tc.args)
		if err != nil || got != tc.want {
			t.Fatalf("%v: %d, %v", tc.args, got, err)
		}
	}
	for _, args := range [][]string{{"-4", "-6"}, {"extra"}, {"--unknown"}} {
		if _, err := parseIPFlags(args); err == nil {
			t.Errorf("expected error for %v", args)
		}
	}
}

func TestLocalIP(t *testing.T) {
	for _, tc := range []struct {
		name   string
		info   warpcli.RegistrationInfo
		family int
		want   string
	}{
		{"IPv4 registration", warpcli.RegistrationInfo{RegistrationID: "reg1"}, 4, "100.96.0.1\n"},
		{"IPv6 device", warpcli.RegistrationInfo{DeviceID: "dev1"}, 6, "2606:4700:cf1:1000::1\n"},
		{"legacy ID", warpcli.RegistrationInfo{ID: "dev1"}, 4, "100.96.0.1\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			regs, _, _ := fixtureDevices()
			c := commandAPI(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/accounts/acc/devices/registrations" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": regs})
			})
			local := fakeLocalWARP{status: warpcli.ConnectionStatus{State: "connected", Connected: true}, info: tc.info}
			var out bytes.Buffer
			if err := writeLocalIP(context.Background(), &out, c, "acc", local, tc.family); err != nil {
				t.Fatal(err)
			}
			if out.String() != tc.want {
				t.Fatalf("got %q", out.String())
			}
		})
	}
}

func TestLocalIPErrors(t *testing.T) {
	connected := warpcli.ConnectionStatus{State: "connected", Connected: true}
	regs, _, _ := fixtureDevices()
	for _, tc := range []struct {
		name      string
		local     fakeLocalWARP
		regs      []cfapi.Registration
		family    int
		want      string
		wantCalls int
	}{
		{"disconnected", fakeLocalWARP{status: warpcli.ConnectionStatus{State: "disconnected", Reason: "Manual Disconnection"}}, nil, 4, "not connected to Cloudflare Mesh: disconnected (Manual Disconnection)", 0},
		{"missing binary", fakeLocalWARP{statusErr: errors.New("executable file not found")}, nil, 4, "cannot read local WARP status", 0},
		{"missing local registration", fakeLocalWARP{status: connected, infoErr: errors.New("no registration")}, nil, 4, "cannot identify this machine", 0},
		{"wrong account", fakeLocalWARP{status: connected, info: warpcli.RegistrationInfo{ID: "unknown"}}, regs, 4, "not found in the selected Cloudflare account", 1},
		{"no IPv6", fakeLocalWARP{status: connected, info: warpcli.RegistrationInfo{RegistrationID: "reg2"}}, regs, 6, "no Mesh IPv6", 1},
		{"revoked registration", fakeLocalWARP{status: connected, info: warpcli.RegistrationInfo{RegistrationID: "revoked"}}, regs, 4, "not found", 1},
		{"ambiguous physical device", fakeLocalWARP{status: connected, info: warpcli.RegistrationInfo{DeviceID: "d"}}, []cfapi.Registration{{ID: "r1", Device: cfapi.RegistrationDevice{ID: "d"}, VirtualIPv4: "100.96.0.1"}, {ID: "r2", Device: cfapi.RegistrationDevice{ID: "d"}, VirtualIPv4: "100.96.0.2"}}, 4, "multiple WARP registrations", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c := commandAPI(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": tc.regs})
			})
			var out bytes.Buffer
			err := writeLocalIP(context.Background(), &out, c, "acc", tc.local, tc.family)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v", err)
			}
			if out.Len() != 0 || calls != tc.wantCalls {
				t.Fatalf("output %q, requests %d", out.String(), calls)
			}
		})
	}
}
