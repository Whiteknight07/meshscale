package main

import (
	"strings"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/rules"
)

// Device names are self-reported. Another device copying this machine's
// name, or a lookalike of it, never silently becomes the SSH or rule target.
func TestDuplicateAndLookalikeNamesNeverRedirect(t *testing.T) {
	devices := []meshDevice{
		{ID: "self", Kind: "device", Name: "workstation", IPv4: "100.96.0.1", ThisMachine: true},
		{ID: "copy", Kind: "device", Name: "workstation", IPv4: "100.96.0.2"},
		{ID: "lookalike", Kind: "device", Name: "wоrkstation", IPv4: "100.96.0.3"}, // Cyrillic о
		{ID: "evil", Kind: "device", Name: "-oProxyCommand=touch /tmp/x", IPv4: "100.96.0.4"},
	}
	if _, err := resolveSSHTarget(devices, "workstation"); err == nil || !strings.Contains(err.Error(), "multiple devices") {
		t.Fatalf("duplicate name resolved: %v", err)
	}
	if ip, err := resolveSSHTarget(devices, "-oProxyCommand=touch /tmp/x"); err != nil || ip.String() != "100.96.0.4" {
		t.Fatalf("option-like name must resolve only to its Mesh IP: %v %v", ip, err)
	}
	policy, err := rules.Parse([]byte(`{"rules":[{"from":["*"],"to":["workstation:22"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var participants []rules.Participant
	for _, d := range devices {
		participants = append(participants, rules.Participant{ID: d.ID, Name: d.Name, IPv4: d.IPv4})
	}
	if _, err := rules.Compile(policy, participants); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("duplicate name compiled into a rule: %v", err)
	}
	if compiled, err := rules.Compile(policy, participants[1:]); err != nil || strings.Contains(compiled[0].Traffic, "100.96.0.3") {
		t.Fatalf("lookalike matched a rule selector: %v", err)
	}
}
