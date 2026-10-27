package sshserver

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func FuzzParsePolicy(f *testing.F) {
	for _, seed := range []string{
		`{"rules":[]}`,
		`{"rules":[{"name":"owner","from":["alice@example.com","device:abc","nas","*"],"users":["autogroup:nonroot","root","bob"]}]}`,
		`{"rules":[{"from":["device:"],"users":["x"]}]}`,
		`{"rules":[{"from":["*"],"users":["*"]}]} {}`,
		`{"rules":null}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := ParsePolicy(data)
		if err != nil {
			return
		}
		// A saved policy must reload identically.
		encoded, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		again, err := ParsePolicy(encoded)
		if err != nil || !reflect.DeepEqual(again.Rules, p.Rules) {
			t.Fatalf("round trip changed policy: %v\n%s", err, encoded)
		}
		for i, r := range p.Rules {
			if strings.ContainsAny(p.RuleName(i), "\r\n") {
				t.Fatalf("rule name breaks a log line: %q", p.RuleName(i))
			}
			for _, s := range r.Users {
				if s != "autogroup:nonroot" && strings.ContainsAny(s, "*:") {
					t.Fatalf("accepted user selector %q", s)
				}
			}
		}
		// Identities the client controls never match: an unverified device
		// name, and anything without an owner or ID.
		self := Identity{Device: "nas", DeviceID: "", Owner: "", Node: false}
		for _, user := range []string{"bob", "root"} {
			if i := p.MatchingRule(self, user, 1000); i >= 0 && !slices.Contains(p.Rules[i].From, "*") {
				t.Fatalf("self-reported device name matched %q", p.Rules[i].From)
			}
		}
		// Alternate UID 0 names never inherit access.
		for _, alias := range []string{"toor", "autogroup:nonroot", "*"} {
			if p.Allows(Identity{Owner: "alice@example.com", DeviceID: "abc", Device: "nas", Node: true}, alias, 0) {
				t.Fatalf("UID 0 alias %q allowed", alias)
			}
		}
	})
}

// Owner emails are compared ASCII case-insensitively: Unicode folding would
// let a Kelvin sign (K) or long s (ſ) address match "k" or "s" selectors.
func TestOwnerSelectorRejectsUnicodeFolding(t *testing.T) {
	p := Policy{Rules: []Rule{{From: []string{"kim@secure.example"}, Users: []string{"autogroup:nonroot"}}}}
	for _, owner := range []string{"Kim@secure.example", "kim@ſecure.example"} {
		if p.Allows(Identity{Owner: owner, DeviceID: "d"}, "kim", 1000) {
			t.Errorf("%q matched an ASCII selector", owner)
		}
	}
	if !p.Allows(Identity{Owner: "KIM@Secure.Example", DeviceID: "d"}, "kim", 1000) {
		t.Error("ASCII case-insensitive owner match failed")
	}
}
