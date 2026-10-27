package main

import (
	"testing"
)

func TestResolveSSHTarget(t *testing.T) {
	devices := []meshDevice{{Name: "node", IPv4: "100.96.0.2"}, {Name: "v6", IPv6: "2606:4700:cf1:1000::2"}, {Name: "noip"}}
	for _, tc := range []struct{ target, want string }{
		{"node", "100.96.0.2"}, {"100.96.0.2", "100.96.0.2"}, {"v6", "2606:4700:cf1:1000::2"},
	} {
		ip, err := resolveSSHTarget(devices, tc.target)
		if err != nil || ip.String() != tc.want {
			t.Fatalf("%s: ip=%v err=%v", tc.target, ip, err)
		}
	}
	for _, target := range []string{"missing", "noip", "127.0.0.1", "100.96.0.99", "-oProxyCommand=bad"} {
		if _, err := resolveSSHTarget(devices, target); err == nil {
			t.Errorf("resolved invalid target %q", target)
		}
	}
	devices = append(devices, meshDevice{Name: "node", IPv4: "100.96.0.3"})
	if _, err := resolveSSHTarget(devices, "node"); err == nil {
		t.Fatal("resolved ambiguous name")
	}
	devices = append(devices, meshDevice{Name: "duplicate", IPv4: "100.96.0.2"})
	if _, err := resolveSSHTarget(devices, "100.96.0.2"); err == nil {
		t.Fatal("resolved ambiguous IP")
	}
}

func TestCloudflareSSHArgs(t *testing.T) {
	args := cloudflareSSHArgs("100.96.0.2", 22, "alice", []string{"hostname"})
	for _, want := range []string{"IdentityFile=none", "IdentityAgent=none", "PreferredAuthentications=none", "HostKeyAlias=meshscale-cloudflare-100.96.0.2", "StrictHostKeyChecking=accept-new", "PasswordAuthentication=no"} {
		found := false
		for _, arg := range args {
			if arg == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing %s", want)
		}
	}
	if args[len(args)-2] != "100.96.0.2" || args[len(args)-1] != "hostname" {
		t.Fatal(args)
	}
}
