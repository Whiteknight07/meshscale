package names

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Accounts often hold many devices whose names sanitize alike ("iPhone",
// emoji-only names); numbering them must stay linear.
func TestBuildManyDuplicateNames(t *testing.T) {
	ps := make([]Participant, 10000)
	for i := range ps {
		ps[i] = Participant{ID: fmt.Sprintf("%05d", i), Name: "💻", IPv4: "100.96.0.1"}
	}
	start := time.Now()
	records, err := Build(ps, "mesh")
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("10,000 duplicate names took %v", elapsed)
	}
	byID := map[string]string{}
	for _, r := range records {
		byID[r.ID] = r.Name
	}
	if byID["00000"] != "device.mesh" || byID["00001"] != "device-2.mesh" || byID["09999"] != "device-10000.mesh" {
		t.Fatalf("unexpected numbering: %s %s %s", byID["00000"], byID["00001"], byID["09999"])
	}
}

// Lookalikes, control characters and DNS syntax in a self-reported device
// name can only ever produce one plain label inside the suffix.
func TestBuildHostileNames(t *testing.T) {
	ps := []Participant{
		{ID: "1", Name: "nas", IPv4: "100.96.0.1"},
		{ID: "0", Name: "ｎａｓ", IPv4: "100.96.0.2"},   // fullwidth
		{ID: "2", Name: "Kiosk", IPv4: "100.96.0.3"}, // Kelvin sign lowercases to k
		{ID: "3", Name: "kiosk", IPv4: "100.96.0.4"},
		{ID: "4", Name: "a.b.evil.com.", IPv4: "100.96.0.5"},
		{ID: "5", Name: "x\" or dns.fqdn == \"bank.com", IPv4: "100.96.0.6"},
		{ID: "6", Name: "\x1b[31mred\r\nInjected: 1", IPv4: "100.96.0.7"},
		{ID: "7", Name: strings.Repeat("long", 1000), IPv4: "100.96.0.8"},
		{ID: "8", Name: "", IPv4: "100.96.0.9"},
		{ID: "9", Name: "../../etc/passwd", IPv4: "100.96.0.10"},
	}
	records, err := Build(ps, "mesh")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range records {
		label, suffix, _ := strings.Cut(r.Name, ".")
		if !dnsLabel.MatchString(label) || suffix != "mesh" || seen[r.Name] {
			t.Errorf("%s: unsafe or duplicate name %q", r.ID, r.Name)
		}
		seen[r.Name] = true
		if rule := ruleFor(r); rule.Traffic != `dns.fqdn == "`+r.Name+`"` {
			t.Errorf("%s: unexpected expression %s", r.ID, rule.Traffic)
		}
	}
	// The Kelvin-sign name folds onto "kiosk"; ID order decides who keeps it,
	// exactly as for two devices both named "kiosk".
	for _, r := range records {
		if r.ID == "2" && r.Name != "kiosk.mesh" || r.ID == "3" && r.Name != "kiosk-2.mesh" {
			t.Errorf("%s: %s", r.ID, r.Name)
		}
	}
}

func FuzzBuild(f *testing.F) {
	f.Add("laptop", "Laptop", "laptop-2", "100.96.0.1", "mesh")
	f.Add("💻", "", strings.Repeat("a-", 40), "2606:4700:cf1::1", ".MESH.")
	f.Add("x\"y", "K", "a.b", "::ffff:100.96.0.1", "corp.internal")
	f.Fuzz(func(t *testing.T, a, b, c, ip, suffix string) {
		ps := []Participant{{ID: "a", Name: a, IPv4: ip}, {ID: "b", Name: b, IPv6: ip}, {ID: "c", Name: c}, {ID: "d", Name: a}}
		records, err := Build(ps, suffix)
		if err != nil {
			return
		}
		clean, err := Suffix(suffix)
		if err != nil {
			t.Fatalf("Build accepted invalid suffix %q", suffix)
		}
		reversed, err := Build([]Participant{ps[3], ps[2], ps[1], ps[0]}, suffix)
		if err != nil || fmt.Sprint(reversed) != fmt.Sprint(records) {
			t.Fatalf("result depends on input order: %v vs %v (%v)", records, reversed, err)
		}
		seen := map[string]bool{}
		for _, r := range records {
			label, rest, _ := strings.Cut(r.Name, ".")
			if !dnsLabel.MatchString(label) || rest != clean || len(r.Name) > 253 {
				t.Fatalf("invalid DNS name %q", r.Name)
			}
			if seen[r.Name] {
				t.Fatalf("duplicate DNS name %q", r.Name)
			}
			seen[r.Name] = true
			if strings.ContainsAny(r.IP, "%\"\\ ") {
				t.Fatalf("unsafe override IP %q", r.IP)
			}
			if r.IP != "" {
				if rule := ruleFor(r); Owner(rule) != r.ID || strings.Count(rule.Traffic, `"`) != 2 {
					t.Fatalf("unsafe rule %#v", rule)
				}
			}
		}
	})
}
