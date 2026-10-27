package main

import "testing"

func TestResolveSSHTargetMeshDNSName(t *testing.T) {
	t.Setenv("MESHSCALE_DNS_SUFFIX", "mesh")
	devices := []meshDevice{{ID: "node", Kind: "node", Name: "Build Box", IPv4: "100.96.0.2"}}
	for _, target := range []string{"build-box.mesh", "BUILD-BOX.MESH."} {
		ip, err := resolveSSHTarget(devices, target)
		if err != nil || ip.String() != "100.96.0.2" {
			t.Errorf("resolve %q: ip=%s err=%v", target, ip, err)
		}
	}
}

func TestResolveSSHTargetRejectsNameDNSAmbiguity(t *testing.T) {
	t.Setenv("MESHSCALE_DNS_SUFFIX", "mesh")
	devices := []meshDevice{
		{ID: "one", Kind: "node", Name: "peer", IPv4: "100.96.0.2"},
		{ID: "two", Kind: "node", Name: "peer.mesh", IPv4: "100.96.0.3"},
	}
	if _, err := resolveSSHTarget(devices, "peer.mesh"); err == nil {
		t.Fatal("ambiguous raw device name and allocated DNS alias selected one peer")
	}
}
