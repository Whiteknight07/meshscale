package main

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

func TestWhoisLookupAndFormatting(t *testing.T) {
	r, p, n := fixtureDevices()
	devices := mergeMeshDevices(r, p, n, fixtureNow)
	for _, ip := range []string{"100.96.0.1", "2606:4700:0cf1:1000:0000:0000:0000:0001", "::ffff:100.96.0.1"} {
		d, err := findMeshIP(devices, netip.MustParseAddr(ip))
		if err != nil || d.ID != "reg1" {
			t.Fatalf("%s: %#v, %v", ip, d, err)
		}
	}
	d, err := findMeshIP(devices, netip.MustParseAddr("100.96.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := writeWhois(&out, d, "100.96.0.1", fixtureNow); err != nil {
		t.Fatal(err)
	}
	want := []string{"Mesh IP: 100.96.0.1", "Device: laptop", "User/owner: alice@example.com", "OS: mac", "Status: online", "Registration: reg1", "Device ID: dev1"}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != len(want) {
		t.Fatalf("got %s", out.String())
	}
	for i, line := range lines {
		if got := strings.Join(strings.Fields(line), " "); got != want[i] {
			t.Errorf("got %q, want %q", got, want[i])
		}
	}
}

func TestWhoisNotFoundAndAmbiguous(t *testing.T) {
	ip := netip.MustParseAddr("100.96.0.1")
	if _, err := findMeshIP(nil, ip); err == nil || !strings.Contains(err.Error(), "no device found") {
		t.Fatalf("got %v", err)
	}
	devices := []meshDevice{{ID: "r1", IPv4: ip.String()}, {ID: "r2", IPv4: ip.String()}}
	if _, err := findMeshIP(devices, ip); err == nil || !strings.Contains(err.Error(), "multiple devices") {
		t.Fatalf("got %v", err)
	}
}

func TestWhoisInvalidInput(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "")
	for _, args := range [][]string{nil, {"nope"}, {"100.96.0.1/32"}, {"fe80::1%eth0"}, {"100.96.0.1", "extra"}} {
		if err := runWhois(t.Context(), args); err == nil {
			t.Errorf("expected error for %v", args)
		}
	}
}
