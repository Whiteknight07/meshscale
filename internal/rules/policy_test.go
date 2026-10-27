package rules

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	for _, data := range []string{
		`{"rules":[]}`,
		`{"groups":{"servers":["homelab","nas"],"nested":["group:servers"]},"rules":[{"from":["*","alice@example.com","Mac Laptop"],"to":["servers:22,443","group:nested:1000-2000","[2606:4700:cf1:1000::4]:*"]}]}`,
	} {
		if _, err := Parse([]byte(data)); err != nil {
			t.Errorf("%s: %v", data, err)
		}
	}
	for _, data := range []string{
		`null`, `{}`, `{"rules":null}`, `{"rules":[],"typo":1}`, `{"rules":[]} {}`,
		`{"groups":{"x":["group:y"],"y":["group:x"]},"rules":[]}`,
		`{"groups":{"unused":["group:missing"]},"rules":[]}`,
		`{"groups":{"x":[]},"rules":[]}`,
		`{"rules":[{"from":[],"to":["*:22"]}]}`,
		`{"rules":[{"from":["group:missing"],"to":["*:22"]}]}`,
		`{"rules":[{"from":["*"],"to":["*"]}]}`,
		`{"rules":[{"from":["10.0.0.1"],"to":["*:22"]}]}`,
		`{"rules":[{"from":["*"],"to":["100.96.0.0/11:22"]}]}`,
		`{"rules":[{"from":["*"],"to":["2606:4700:cf1:1000::4:22"]}]}`,
		`{"rules":[{"from":["*"],"to":["*:0"]}]}`,
		`{"rules":[{"from":["*"],"to":["*:65536"]}]}`,
		`{"rules":[{"from":["*"],"to":["*:10-1"]}]}`,
		`{"rules":[{"from":["*"],"to":["*:1,,2"]}]}`,
		`{"rules":[{"from":["*"],"to":["*:+22"]}]}`,
		`{"rules":[{"from":["*"],"to":["*:22,*"]}]}`,
		`{"rules":[{"from":[" leading"],"to":["*:22"]}]}`,
	} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Errorf("accepted %s", data)
		}
	}
}

func TestCompile(t *testing.T) {
	p, err := Parse([]byte(`{"groups":{"servers":["homelab","nas"]},"rules":[{"from":["alice@example.com"],"to":["servers:22,443","100.96.0.20:8000-8010"]},{"from":["Mac Laptop"],"to":["*:*"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	devices := []Participant{
		{Name: "homelab", IPv4: "100.96.0.2"}, {Name: "nas", IPv4: "100.96.0.3"},
		{Name: "Mac Laptop", Email: "alice@example.com", IPv4: "100.96.0.4", IPv6: "2606:4700:cf1:1000::4"},
		{Name: "phone", Email: "alice@example.com", IPv4: "100.96.0.5"},
	}
	got, err := Compile(p, devices)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Action != "allow" || Owner(got[2]) != "default-deny" || got[2].Action != "block" {
		t.Fatalf("%+v", got)
	}
	want := `net.src.internal_src_ip in {100.96.0.4/32 100.96.0.5/32 2606:4700:cf1:1000::4/128} and ((net.dst.ip in {100.96.0.2/32 100.96.0.3/32} and (net.dst.port == 22 or net.dst.port == 443)) or (net.dst.ip in {100.96.0.20/32} and (net.dst.port >= 8000 and net.dst.port <= 8010)))`
	if got[0].Traffic != want {
		t.Fatalf("expression:\n%s\nwant:\n%s", got[0].Traffic, want)
	}
	if strings.Contains(got[1].Traffic, "port") || got[2].Traffic != ipExpression("dst", []string{MeshIPv4, MeshIPv6}) {
		t.Fatalf("wildcard/deny: %+v", got)
	}
	devices[2].IPv4 = "100.96.0.9"
	changed, err := Compile(p, devices)
	if err != nil || changed[0].Traffic == got[0].Traffic {
		t.Fatalf("device change: %v %v", changed, err)
	}
	if got, err := Compile(nil, nil); err != nil || len(got) != 0 {
		t.Fatalf("absent: %v %v", got, err)
	}
	if got, err := Compile(&Policy{Rules: []Rule{}}, nil); err != nil || len(got) != 1 || got[0].Action != "block" {
		t.Fatalf("empty: %v %v", got, err)
	}
}

func TestResolutionFailures(t *testing.T) {
	p := &Policy{Rules: []Rule{{From: []string{"laptop"}, To: []string{"*:*"}}}}
	for _, devices := range [][]Participant{
		nil,
		{{Name: "laptop"}},
		{{Name: "laptop", IPv4: "100.96.0.2"}, {Name: "laptop", IPv4: "100.96.0.3"}},
		{{Name: "laptop", IPv4: "10.0.0.1"}},
		{{Name: "laptop", IPv6: "2606:4700:cf1:1000::4%eth0"}},
	} {
		if _, err := Compile(p, devices); err == nil {
			t.Fatalf("accepted: %+v", devices)
		}
	}
}
