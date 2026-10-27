package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

func TestRouteNodeSelection(t *testing.T) {
	devices := []meshDevice{{ID: "a", Kind: "node", Name: "router", ThisMachine: true}, {ID: "b", Kind: "device", Name: "phone"}}
	for _, name := range []string{"", "router"} {
		d, err := routeNode(devices, name)
		if err != nil || d.ID != "a" {
			t.Fatalf("%+v %v", d, err)
		}
	}
	for _, name := range []string{"missing", "phone"} {
		if _, err := routeNode(devices, name); err == nil {
			t.Fatal(name)
		}
	}
	devices = append(devices, meshDevice{ID: "c", Kind: "node", Name: "router"})
	if _, err := routeNode(devices, "router"); err == nil {
		t.Fatal("ambiguous name")
	}
}

func TestForwardingAdvice(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		var out bytes.Buffer
		key, path := "net.ipv4.ip_forward", "/proc/sys/net/ipv4/ip_forward"
		if ipv6 {
			key, path = "net.ipv6.conf.all.forwarding", "/proc/sys/net/ipv6/conf/all/forwarding"
		}
		read := func(p string) ([]byte, error) {
			if p != path {
				t.Errorf("path %s", p)
			}
			return []byte("0\n"), nil
		}
		if err := checkForwarding(&out, ipv6, read); err != nil || !strings.Contains(out.String(), "sudo sysctl -w "+key+"=1") {
			t.Fatalf("%s %v", out.String(), err)
		}
		out.Reset()
		if err := checkForwarding(&out, ipv6, func(string) ([]byte, error) { return []byte("1\n"), nil }); err != nil || out.Len() != 0 {
			t.Fatalf("%s %v", out.String(), err)
		}
		if err := checkForwarding(&out, ipv6, func(string) ([]byte, error) { return nil, fmt.Errorf("unavailable") }); err == nil {
			t.Fatal("read failure ignored")
		}
	}
}

func TestRoutesStatus(t *testing.T) {
	now := time.Now()
	devices := []meshDevice{{ID: "node", Kind: "node", Name: "router"}, {ID: "other", Kind: "device"}}
	entries := []cfapi.Route{{ID: "active", Network: "10.250.0.0/24", TunnelID: "node"}, {ID: "deleted", Network: "10.251.0.0/24", TunnelID: "node", DeletedAt: &now}, {ID: "other", Network: "10.252.0.0/24", TunnelID: "other"}}
	assignRoutes(devices, entries)
	if len(devices[0].Routes) != 1 || len(devices[1].Routes) != 0 {
		t.Fatalf("%+v", devices)
	}
	var out bytes.Buffer
	if err := writeStatus(&out, devices, false, now); err != nil || !strings.Contains(out.String(), "Subnet routes via router: 10.250.0.0/24") {
		t.Fatalf("%s %v", out.String(), err)
	}
	out.Reset()
	if err := writeStatus(&out, devices, true, now); err != nil || !strings.Contains(out.String(), `"routes": [`) {
		t.Fatalf("%s %v", out.String(), err)
	}
	out.Reset()
	if err := writeRoutes(&out, entries); err != nil || strings.Contains(out.String(), "10.251.0.0/24") {
		t.Fatalf("%s %v", out.String(), err)
	}
}
