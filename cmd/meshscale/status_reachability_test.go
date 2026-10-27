package main

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/reachability"
)

type fakeStatusProber struct {
	calls int
	err   error
}

func (p *fakeStatusProber) Probe(context.Context, netip.Addr) error { p.calls++; return p.err }

func TestStatusReachability(t *testing.T) {
	for _, tc := range []struct {
		name                               string
		last                               *time.Time
		ipv4, ipv6                         string
		initiallyOnline, reply, wantOnline bool
		calls                              int
		source                             string
	}{
		{"stale phone replies", timeAgo(time.Hour), "100.96.0.1", "", false, true, true, 1, "probe"},
		{"stale phone unreachable", timeAgo(time.Hour), "100.96.0.1", "", false, false, false, 1, "cloudflare"},
		{"recent registration", timeAgo(time.Minute), "100.96.0.1", "", true, true, true, 0, "cloudflare"},
		{"healthy node", timeAgo(time.Hour), "100.96.0.2", "", true, true, true, 0, "cloudflare"},
		{"unknown last seen", nil, "100.96.0.1", "", false, true, true, 1, "probe"},
		{"IPv6 only", timeAgo(time.Hour), "", "2606:4700:cf1:1000::1", false, true, true, 1, "probe"},
		{"unenrolled", nil, "", "", false, true, false, 0, "cloudflare"},
		{"invalid IP", nil, "not-an-IP", "", false, true, false, 0, "cloudflare"},
		{"outside mesh", nil, "1.1.1.1", "", false, true, false, 0, "cloudflare"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			devices := []meshDevice{{LastSeenAt: tc.last, IPv4: tc.ipv4, IPv6: tc.ipv6, Online: tc.initiallyOnline, OnlineSource: "cloudflare"}}
			prober := &fakeStatusProber{}
			if !tc.reply {
				prober.err = errors.New("unreachable")
			}
			results := reachability.New(prober).Check(context.Background(), statusProbeIPs(devices, fixtureNow))
			applyProbeResults(devices, results, fixtureNow)
			if devices[0].Online != tc.wantOnline || devices[0].OnlineSource != tc.source || prober.calls != tc.calls {
				t.Fatalf("device %#v calls %d", devices[0], prober.calls)
			}
			if devices[0].LastSeenAt != tc.last {
				t.Fatal("probe overwrote Cloudflare timestamp")
			}
		})
	}
}

func TestDeletedAndRevokedNeverProbed(t *testing.T) {
	for _, tc := range []struct {
		name         string
		registration cfapi.Registration
		physical     cfapi.PhysicalDevice
	}{
		{"deleted registration", cfapi.Registration{DeletedAt: timeAgo(time.Hour)}, cfapi.PhysicalDevice{}},
		{"revoked registration", cfapi.Registration{RevokedAt: timeAgo(time.Hour)}, cfapi.PhysicalDevice{}},
		{"deleted physical device", cfapi.Registration{}, cfapi.PhysicalDevice{ID: "device", DeletedAt: timeAgo(time.Hour)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.registration
			r.ID, r.Device.ID, r.VirtualIPv4, r.LastSeenAt = "reg", "device", "100.96.0.1", timeAgo(time.Hour)
			devices := mergeMeshDevices([]cfapi.Registration{r}, []cfapi.PhysicalDevice{tc.physical}, nil, fixtureNow)
			if ips := statusProbeIPs(devices, fixtureNow); len(ips) != 0 {
				t.Fatalf("probed deleted or revoked device: %v", ips)
			}
		})
	}
}
