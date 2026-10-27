package publication

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzStateLoad loads arbitrary manifests. A loadable manifest saves and
// reloads unchanged, and its certificate paths can never direct removal
// outside the private store, whatever they name.
func FuzzStateLoad(f *testing.F) {
	for _, seed := range []string{
		`{"account":"a","zone":{"id":"z","name":"example.com"},"records":[{"zone_id":"z","record":{"id":"r","type":"A","name":"nas.mesh.example.com","content":"100.96.0.1"}}],"certificates":[{"name":"nas.mesh.example.com","ip":"100.96.0.1","directory":"x","cert_file":"cert-1/cert.pem","key_file":"cert-1/key.pem"}]}`,
		`{"certificates":[{"name":"x","cert_file":"../outside/cert.pem","key_file":"../outside/key.pem"}]}`,
		`{"certificates":[{"name":"x","cert_file":"/","key_file":"/"}]}`,
		`{"desired_addresses":{"a":"b"},"funnel":{"host":"h","origin":"o"}}`,
		`null`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		root := t.TempDir()
		dir := filepath.Join(root, "store")
		outside := filepath.Join(root, "outside")
		for _, d := range []string{dir, outside, filepath.Join(dir, "cert-1")} {
			if err := os.MkdirAll(d, 0700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "state.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		store := Store{Dir: dir}
		state, err := store.Load()
		if err != nil {
			return
		}
		if err := store.Save(state); err != nil {
			t.Fatal(err)
		}
		again, err := store.Load()
		a, _ := json.Marshal(again)
		b, _ := json.Marshal(state)
		if err != nil || string(a) != string(b) {
			t.Fatalf("manifest reloads differently: %s vs %s (%v)", a, b, err)
		}
		m := &Manager{Store: store}
		for _, cert := range state.Certificates {
			// Relative paths resolve against the working directory; anchor them
			// in the test root so a traversal attempt targets "outside".
			if !filepath.IsAbs(cert.CertFile) {
				cert.CertFile = filepath.Join(dir, cert.CertFile)
			}
			if !filepath.IsAbs(cert.KeyFile) {
				cert.KeyFile = filepath.Join(dir, cert.KeyFile)
			}
			_ = m.removeGeneration(cert)
			_ = validSavedCertificate(cert)
		}
		for _, path := range []string{outside, filepath.Join(dir, "state.json")} {
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("certificate removal escaped the generation directory: %v", err)
			}
		}
	})
}

func FuzzHostNames(f *testing.F) {
	f.Add("nas", "-funnel", "example.com")
	f.Add("NAS", "", "example.com")
	f.Add("a.b", "x", "z")
	f.Fuzz(func(t *testing.T, name, suffix, zone string) {
		if zone == "" {
			return // zones come from Cloudflare's zone list and are never empty
		}
		for _, build := range []func() (string, error){
			func() (string, error) { return Host(name, "mesh", zone) },
			func() (string, error) { return FunnelHost(name, suffix, zone) },
		} {
			host, err := build()
			if err != nil {
				continue
			}
			labels := strings.Split(host, ".")
			for _, label := range labels {
				if !labelPattern.MatchString(label) {
					t.Fatalf("unsafe publication host %q", host)
				}
			}
			if len(labels) < 2 || len(host) > 253 {
				t.Fatalf("unsafe publication host %q", host)
			}
		}
	})
}

// The zone name comes from the account and saved state; it must be a DNS name
// before it reaches records, Access domains or certificates.
func TestHostRejectsInvalidZone(t *testing.T) {
	for _, zone := range []string{"", ".", "example.com.", "a..b", "Example.com", "x\"; rm", "evil.com\r\nHost: x", "*.example.com", "-a.com"} {
		if host, err := Host("nas", "mesh", zone); err == nil {
			t.Errorf("Host accepted zone %q: %q", zone, host)
		}
		if host, err := FunnelHost("nas", "", zone); err == nil {
			t.Errorf("FunnelHost accepted zone %q: %q", zone, host)
		}
	}
	if host, err := Host("nas", "mesh", "xn--bcher-kva.example"); err != nil || host != "nas.mesh.xn--bcher-kva.example" {
		t.Fatalf("%q %v", host, err)
	}
}
