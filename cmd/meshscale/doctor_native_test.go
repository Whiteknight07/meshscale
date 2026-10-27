package main

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/exitnode"
)

func TestDoctorNativeUserspaceDoesNotRequireWARP(t *testing.T) {
	d, b := doctorFixture(t)
	d.local = doctorReady(doctorBackend{local: b, settings: config.BackendSettings{Backend: "native", Userspace: true}}, nil)
	d.network = doctorReady(exitnode.Snapshot{}, nil)
	for name, check := range map[string]doctorCheck{
		"route": d.checkRoute(t.Context()),
		"mtu":   d.checkMTU(t.Context()),
	} {
		if check.Status == "fail" || !strings.Contains(check.Detail, "userspace") {
			t.Errorf("%s incorrectly requires an official-client interface: %+v", name, check)
		}
	}
}

func TestDoctorNativeUserspaceDoesNotRequireSystemDNS(t *testing.T) {
	d, b := doctorFixture(t)
	d.local = doctorReady(doctorBackend{local: b, settings: config.BackendSettings{Backend: "native", Userspace: true}}, nil)
	d.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		t.Fatal("private native names must not use the system resolver")
		return nil, nil
	}
	check := d.checkDNS(t.Context())
	if check.Status != "warn" || !strings.Contains(check.Detail, "userspace") {
		t.Fatalf("private native DNS diagnosed as a system resolver failure: %+v", check)
	}
}

// Go's resolver returns /etc/hosts IPv4 entries as IPv4-mapped IPv6; a correct
// hosts-file answer must not be reported as a different address.
func TestDoctorDNSAcceptsMappedHostsAnswer(t *testing.T) {
	d, _ := doctorFixture(t)
	d.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("::ffff:100.96.0.7")}, nil
	}
	if check := d.checkDNS(t.Context()); check.Status != "ok" {
		t.Fatalf("mapped hosts answer diagnosed as wrong: %+v", check)
	}
}
