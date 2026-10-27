package publication

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

type fakeCloud struct {
	configured *cfapi.TunnelOrigin
	zones      []cfapi.Zone
	records    map[string]cfapi.DNSRecord
	events     []string
	fail       string
	calls      int
	counter    int
	tunnel     cfapi.PublicTunnel
	app        cfapi.PublicApplication
}

func (f *fakeCloud) step(s string) error {
	f.calls++
	f.events = append(f.events, s)
	if f.fail == s {
		return errors.New("injected " + s)
	}
	return nil
}
func (f *fakeCloud) PublicationZones(context.Context, string) ([]cfapi.Zone, error) {
	err := f.step("zones")
	return f.zones, err
}
func (f *fakeCloud) PublicationRecords(_ context.Context, zone string) ([]cfapi.DNSRecord, error) {
	if err := f.step("list:" + zone); err != nil {
		return nil, err
	}
	var records []cfapi.DNSRecord
	for _, r := range f.records {
		records = append(records, r)
	}
	return records, nil
}
func (f *fakeCloud) PublicationRecordsByName(ctx context.Context, zone, name string) ([]cfapi.DNSRecord, error) {
	records, err := f.PublicationRecords(ctx, zone)
	return slices.DeleteFunc(records, func(r cfapi.DNSRecord) bool { return r.Name != name }), err
}
func (f *fakeCloud) PublicationRecordCount(ctx context.Context, zone string) (int, error) {
	records, err := f.PublicationRecords(ctx, zone)
	return len(records), err
}
func (f *fakeCloud) UpdatePublicationRecord(_ context.Context, _, id string, r cfapi.DNSRecord) (cfapi.DNSRecord, error) {
	if err := f.step("update-dns"); err != nil {
		return r, err
	}
	r.ID = id
	f.records[id] = r
	return r, nil
}
func (f *fakeCloud) CreatePublicationRecord(_ context.Context, _ string, r cfapi.DNSRecord) (cfapi.DNSRecord, error) {
	if err := f.step("dns:" + r.Type); err != nil {
		return r, err
	}
	f.counter++
	r.ID = fmt.Sprint(f.counter)
	f.records[r.ID] = r
	return r, nil
}
func missing() error {
	return &cfapi.APIError{StatusCode: 404, Errors: []cfapi.APIMessage{{Code: 81044}}}
}
func (f *fakeCloud) PublicationRecord(_ context.Context, _, id string) (cfapi.DNSRecord, error) {
	if err := f.step("get-dns"); err != nil {
		return cfapi.DNSRecord{}, err
	}
	r, ok := f.records[id]
	if !ok {
		return r, missing()
	}
	return r, nil
}
func (f *fakeCloud) DeletePublicationRecord(_ context.Context, _, id string) error {
	if err := f.step("delete-dns"); err != nil {
		return err
	}
	delete(f.records, id)
	return nil
}
func (f *fakeCloud) CreatePublicTunnel(_ context.Context, _, name string) (cfapi.PublicTunnel, error) {
	if err := f.step("tunnel"); err != nil {
		return cfapi.PublicTunnel{}, err
	}
	f.tunnel = cfapi.PublicTunnel{ID: "tunnel", Name: name}
	return f.tunnel, nil
}
func (f *fakeCloud) FindPublicTunnel(_ context.Context, _, name string) (cfapi.PublicTunnel, error) {
	if f.tunnel.Name == name {
		return f.tunnel, nil
	}
	return cfapi.PublicTunnel{}, nil
}
func (f *fakeCloud) FindPublicApplication(_ context.Context, _ string, app cfapi.PublicApplication) (cfapi.PublicApplication, error) {
	if f.app.Name == app.Name {
		return f.app, nil
	}
	return cfapi.PublicApplication{}, nil
}
func (f *fakeCloud) PublicTunnel(context.Context, string, string) (cfapi.PublicTunnel, error) {
	return f.tunnel, nil
}
func (f *fakeCloud) PublicApplication(context.Context, string, string) (cfapi.PublicApplication, error) {
	return f.app, nil
}
func (f *fakeCloud) ConfigurePublicTunnel(_ context.Context, _, _, host, origin string, options *cfapi.TunnelOrigin) error {
	if host != "ashburn-funnel.example.com" || origin != "http://127.0.0.1:8000" {
		return fmt.Errorf("bad ingress")
	}
	f.configured = options
	access := options.Access
	if slices.Contains(f.events, "access") && (access == nil || !access.Required || !reflect.DeepEqual(access.AudTag, []string{"aud"}) || access.TeamName != "team") {
		return fmt.Errorf("missing connector JWT validation")
	}
	return f.step("ingress")
}
func (f *fakeCloud) PublicTunnelToken(context.Context, string, string) (string, error) {
	return "private-token", f.step("token")
}
func (f *fakeCloud) DeletePublicTunnel(context.Context, string, string) error {
	return f.step("delete-tunnel")
}
func (f *fakeCloud) CreatePublicApplication(_ context.Context, _ string, app cfapi.PublicApplication) (cfapi.PublicApplication, error) {
	if app.Type != "self_hosted" || app.Domain != "ashburn-funnel.example.com" || len(app.Policies) != 1 || app.Policies[0].Decision != "allow" || len(app.Policies[0].Include) != 1 || string(app.Policies[0].Include[0]["email"]) != `{"email":"owner@example.com"}` {
		return app, fmt.Errorf("unsafe Access policy: %#v", app)
	}
	app.ID, app.AUD = "app", "aud"
	if err := f.step("access"); err != nil {
		return cfapi.PublicApplication{}, err
	}
	f.app = app
	return app, nil
}
func (f *fakeCloud) Organization(context.Context, string) (cfapi.Organization, error) {
	return cfapi.Organization{AuthDomain: "team.cloudflareaccess.com"}, f.step("organization")
}
func (f *fakeCloud) DeletePublicApplication(context.Context, string, string) error {
	return f.step("delete-access")
}

type fakeProcess struct {
	running       bool
	fail          bool
	starts, stops int
	token         string
}

func (p *fakeProcess) Check() error {
	if p.fail {
		return errors.New("cloudflared missing")
	}
	return nil
}
func (p *fakeProcess) Start(_ context.Context, token string) error {
	p.running = true
	p.starts++
	p.token = token
	return nil
}
func (p *fakeProcess) Stop()                  { p.running = false; p.stops++ }
func (p *fakeProcess) Status() (bool, string) { return p.running, "" }

type fakeIssuer struct {
	calls  int
	fail   bool
	bundle Bundle
}

func (f *fakeIssuer) Issue(ctx context.Context, name, directory string, txt TXT) (Bundle, error) {
	f.calls++
	if f.fail {
		return Bundle{}, errors.New("ACME unavailable")
	}
	id, err := txt.Present(ctx, "_acme-challenge."+name, "validation-value")
	if err != nil {
		return Bundle{}, err
	}
	if err := txt.Cleanup(ctx, id); err != nil {
		return Bundle{}, err
	}
	return f.bundle, nil
}
func fixture(t *testing.T) (*Manager, *fakeCloud, *fakeProcess, *fakeIssuer) {
	t.Helper()
	cloud := &fakeCloud{zones: []cfapi.Zone{{ID: "zone", Name: "example.com", Status: "active"}}, records: map[string]cfapi.DNSRecord{}}
	process := &fakeProcess{}
	issuer := &fakeIssuer{}
	manager, err := New(Store{Dir: privateDir(t)}, "account", cloud, cloud, process, issuer)
	if err != nil {
		t.Fatal(err)
	}
	manager.Owner = func(context.Context) (string, error) { return "owner@example.com", nil }
	manager.parent = context.Background()
	return manager, cloud, process, issuer
}
func TestSelectZone(t *testing.T) {
	for _, test := range []struct {
		name            string
		zones           []cfapi.Zone
		preferred, want string
		wantErr         bool
	}{
		{name: "empty", wantErr: true},
		{name: "inactive", zones: []cfapi.Zone{{Name: "example.com", Status: "pending"}}, wantErr: true},
		{name: "active", zones: []cfapi.Zone{{ID: "one", Name: "example.com", Status: "active"}}, want: "example.com"},
		{name: "explicit", zones: []cfapi.Zone{{ID: "one", Name: "example.com", Status: "active"}, {ID: "two", Name: "personal.dev", Status: "active"}}, preferred: "personal.dev", want: "personal.dev"},
		{name: "missing preference", zones: []cfapi.Zone{{ID: "one", Name: "example.com", Status: "active"}}, preferred: "other.com", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cloud := &fakeCloud{zones: test.zones}
			zone, err := SelectZone(context.Background(), cloud, "account", test.preferred)
			if (err != nil) != test.wantErr || zone.Name != test.want {
				t.Fatalf("zone=%s err=%v", zone.Name, err)
			}
		})
	}
}
func TestFunnelLifecycle(t *testing.T) {
	for _, owner := range []bool{false, true} {
		t.Run(fmt.Sprint(owner), func(t *testing.T) {
			m, cloud, process, _ := fixture(t)
			request := FunnelRequest{Name: "ashburn", Port: 8000, OwnerOnly: owner}
			f, err := m.Enable(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if !f.Enabled || f.DNSID == "" || process.token != "private-token" || owner != (f.AppID != "") {
				t.Fatalf("bad Funnel: %#v", f)
			}
			for _, r := range cloud.records {
				if cfapi.CreationNonce(r.Comment) == "" || r.Content != "tunnel.cfargotunnel.com" || !r.Proxied {
					t.Fatalf("bad DNS %#v", r)
				}
			}
			if owner && slices.Index(cloud.events, "access") > slices.Index(cloud.events, "dns:CNAME") {
				t.Fatal("published before Access")
			}
			calls := cloud.calls
			if _, err := m.Enable(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 5; i++ {
				_ = m.Status()
			}
			if cloud.calls != calls {
				t.Fatal("idempotent enable/status made API calls")
			}
			if err := m.Off(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(cloud.records) != 0 || m.Status().Funnel != nil || process.running {
				t.Fatal("cleanup incomplete")
			}
			if owner && slices.Index(cloud.events, "delete-dns") > slices.Index(cloud.events, "delete-access") {
				t.Fatal("removed Access before DNS")
			}
			if err := m.Off(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestFunnelRollback(t *testing.T) {
	for _, step := range []string{"access", "tunnel", "ingress", "token", "dns:CNAME"} {
		t.Run(step, func(t *testing.T) {
			m, cloud, process, _ := fixture(t)
			cloud.fail = step
			_, err := m.Enable(context.Background(), FunnelRequest{Name: "ashburn", Port: 8000, OwnerOnly: true})
			if err == nil || !strings.Contains(err.Error(), "injected "+step) {
				t.Fatalf("lost failure: %v", err)
			}
			if m.state.Funnel != nil || len(cloud.records) != 0 || process.running {
				t.Fatalf("rollback incomplete: %#v", m.state)
			}
		})
	}
}
func TestDNSOwnership(t *testing.T) {
	for _, change := range []string{"name", "content", "comment", "proxied", "type"} {
		t.Run(change, func(t *testing.T) {
			m, cloud, _, _ := fixture(t)
			if _, err := m.Enable(context.Background(), FunnelRequest{Name: "ashburn", Port: 8000, OwnerOnly: true}); err != nil {
				t.Fatal(err)
			}
			id := m.state.Funnel.DNSID
			r := cloud.records[id]
			switch change {
			case "name":
				r.Name = "somebody.example.com"
			case "content":
				r.Content = "other.cfargotunnel.com"
			case "comment":
				r.Comment = ""
			case "proxied":
				r.Proxied = false
			case "type":
				r.Type = "TXT"
			}
			cloud.records[id] = r
			if err := m.Off(context.Background()); err == nil {
				t.Fatal("deleted changed record")
			}
			if _, ok := cloud.records[id]; !ok || slices.Contains(cloud.events, "delete-access") {
				t.Fatal("removed foreign DNS or Access protection")
			}
		})
	}
	t.Run("foreign existing", func(t *testing.T) {
		m, cloud, _, _ := fixture(t)
		cloud.records["foreign"] = cfapi.DNSRecord{ID: "foreign", Type: "CNAME", Name: "ashburn-funnel.example.com", Content: "unrelated"}
		_, err := m.Enable(context.Background(), FunnelRequest{Name: "ashburn", Port: 8000})
		if err == nil || len(cloud.records) != 1 || cloud.records["foreign"].Content != "unrelated" {
			t.Fatal("adopted foreign DNS", err)
		}
	})
	t.Run("interrupted deletion", func(t *testing.T) {
		m, _, _, _ := fixture(t)
		m.state.Funnel = &Funnel{DNSID: "already-deleted"}
		if err := m.Off(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}
func TestFunnelValidation(t *testing.T) {
	for _, request := range []FunnelRequest{{Name: "ashburn", Port: 0}, {Name: "ashburn", Port: 65536}, {Name: "../escape", Port: 8000}, {Name: "x.other.com", Port: 8000}} {
		t.Run(fmt.Sprint(request), func(t *testing.T) {
			m, cloud, _, _ := fixture(t)
			if _, err := m.Enable(context.Background(), request); err == nil || cloud.calls != 0 {
				t.Fatal("invalid request reached API")
			}
		})
	}
	m, cloud, process, _ := fixture(t)
	process.fail = true
	if _, err := m.Enable(context.Background(), FunnelRequest{Name: "ashburn", Port: 8000}); err == nil || cloud.calls != 0 {
		t.Fatal("created resources without cloudflared")
	}
}
func certificateBundle(t *testing.T, name string) Bundle {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(89 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return Bundle{Chain: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}
}
func TestCertificateLifecycle(t *testing.T) {
	for _, staging := range []bool{true, false} {
		t.Run(fmt.Sprint(staging), func(t *testing.T) {
			m, cloud, _, issuer := fixture(t)
			issuer.bundle = certificateBundle(t, "ashburn.mesh.example.com")
			request := CertRequest{Name: "ashburn", IP: "100.96.0.7", Staging: staging}
			cert, err := m.Cert(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if (cert.Directory == StagingDirectory) != staging {
				t.Fatal("wrong ACME directory")
			}
			for _, p := range []string{cert.CertFile, cert.KeyFile} {
				info, err := os.Stat(p)
				if err != nil || info.Mode().Perm() != 0600 {
					t.Fatalf("unsafe cert permissions: %v", err)
				}
			}
			if len(cloud.records) != 1 {
				t.Fatal("TXT was not removed")
			}
			for _, r := range cloud.records {
				if r.Type != "A" || r.Content != "100.96.0.7" || r.Proxied || cfapi.CreationNonce(r.Comment) == "" {
					t.Fatalf("bad mesh A: %#v", r)
				}
			}
			calls := cloud.calls
			reused, err := m.Cert(context.Background(), request)
			if err != nil || reused != cert || issuer.calls != 1 || calls != cloud.calls {
				t.Fatal("failed to reuse certificate", err)
			}
			next := m.renew(context.Background(), time.Now())
			if !next.Equal(cert.RenewAt) || cloud.calls != calls {
				t.Fatal("renewal did per-tick API work")
			}
			next = m.renew(context.Background(), cert.RenewAt.Add(time.Second))
			if issuer.calls != 2 || next.IsZero() {
				t.Fatal("expiry did not renew")
			}
		})
	}
}
func TestRenewalRetryAndFailedIssuance(t *testing.T) {
	m, cloud, _, issuer := fixture(t)
	issuer.bundle = certificateBundle(t, "ashburn.mesh.example.com")
	cert, err := m.Cert(context.Background(), CertRequest{Name: "ashburn", IP: "100.96.0.7"})
	if err != nil {
		t.Fatal(err)
	}
	issuer.fail = true
	now := cert.RenewAt.Add(time.Second)
	next := m.renew(context.Background(), now)
	if !next.Equal(now.Add(time.Hour)) || m.lastRenewalError == "" {
		t.Fatal("renewal failure not deferred")
	}
	calls := cloud.calls
	attempts := issuer.calls
	m.renew(context.Background(), now.Add(time.Minute))
	if cloud.calls != calls || issuer.calls != attempts {
		t.Fatal("renewal ignored retry deadline")
	}
	if len(m.state.Certificates) != 1 || m.state.Certificates[0] != cert {
		t.Fatal("failed renewal replaced working cert")
	}
}
func TestCertificateRejectsInvalidInput(t *testing.T) {
	for _, request := range []CertRequest{{Name: "ashburn", IP: "1.2.3.4"}, {Name: "other.example.com", IP: "100.96.0.7"}, {Name: "ashburn", IP: "100.64.0.1"}} {
		t.Run(fmt.Sprint(request), func(t *testing.T) {
			m, cloud, _, issuer := fixture(t)
			if _, err := m.Cert(context.Background(), request); err == nil || cloud.calls != 0 || issuer.calls != 0 {
				t.Fatal("invalid certificate request made API call")
			}
		})
	}
	m, _, _, issuer := fixture(t)
	issuer.bundle = certificateBundle(t, "wrong.mesh.example.com")
	if _, err := m.Cert(context.Background(), CertRequest{Name: "ashburn", IP: "100.96.0.7"}); err == nil || len(m.state.Certificates) != 0 {
		t.Fatal("published certificate for wrong hostname")
	}
}
func TestRenewalTime(t *testing.T) {
	for _, lifetime := range []time.Duration{24 * time.Hour, 6 * 24 * time.Hour, 90 * 24 * time.Hour} {
		now := time.Now()
		if got := RenewalTime(now, now.Add(lifetime)); !got.Equal(now.Add(lifetime * 2 / 3)) {
			t.Fatal("wrong expiry schedule", got)
		}
	}
}
func TestRuntimeIdleAndRestart(t *testing.T) {
	m, cloud, process, _ := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop, err := m.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var status Status
	if err := Request(ctx, m.Store.Dir, "GET", "/status", nil, &status); err != nil {
		t.Fatal(err)
	}
	stop()
	stop()
	if cloud.calls != 0 || process.starts != 0 {
		t.Fatal("idle startup called API")
	}
	if _, err := os.Stat(Socket(m.Store.Dir)); !os.IsNotExist(err) {
		t.Fatal("socket not removed")
	}
	m.state.Zone = cfapi.Zone{ID: "zone", Name: "example.com", Status: "active"}
	m.state.Funnel = &Funnel{Nonce: "0123456789abcdef0123456789abcdef", Enabled: true, TunnelID: "tunnel", Host: "ashburn-funnel.example.com", Origin: "http://127.0.0.1:8000"}
	cloud.tunnel = cfapi.PublicTunnel{ID: "tunnel", Name: tunnelName(m.state.Funnel)}
	if err := m.save(); err != nil {
		t.Fatal(err)
	}
	restored, err := New(m.Store, "account", cloud, cloud, process, nil)
	if err != nil {
		t.Fatal(err)
	}
	stop, err = restored.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if process.starts != 1 || process.running || !reflect.DeepEqual(cloud.events, []string{"ingress", "token"}) {
		t.Fatal("restart reprovisioned resources", cloud.events)
	}
	if _, err := New(m.Store, "another-account", cloud, cloud, process, nil); err == nil {
		t.Fatal("accepted another account")
	}
}
func TestRuntimeRejectsDuplicateAndNonSocket(t *testing.T) {
	m, _, _, _ := fixture(t)
	stop, err := m.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	other, err := New(m.Store, "account", m.DNS, m.Tunnels, &fakeProcess{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Start(context.Background()); err == nil {
		t.Fatal("duplicate daemon accepted")
	}
	stop()
	if err := os.WriteFile(Socket(m.Store.Dir), []byte("do not replace"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := other.Start(context.Background()); err == nil {
		t.Fatal("replaced regular file")
	}
}
func TestStrictControlRequests(t *testing.T) {
	m, _, _, _ := fixture(t)
	for _, body := range []string{`{"port":8000,"unexpected":true}`, `{"port":8000} {}`, strings.Repeat("x", 5000)} {
		request := httptest.NewRequest(http.MethodPut, "/funnel", strings.NewReader(body))
		response := httptest.NewRecorder()
		m.handler().ServeHTTP(response, request)
		if response.Code != 400 {
			t.Fatal("accepted malformed request", response.Code)
		}
	}
}
func TestPropagationCancellation(t *testing.T) {
	resolver := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("not propagated") }}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := (DNSPropagation{Resolvers: []*net.Resolver{resolver}, Interval: time.Millisecond}).Wait(ctx, "_acme-challenge.ashburn.mesh.example.com", "value")
	if !errors.Is(err, context.Canceled) {
		t.Fatal("lost propagation context error", err)
	}
}
func TestACMEAccountKeysArePersistentAndSeparate(t *testing.T) {
	issuer := &ACME{Dir: privateDir(t)}
	a, err := issuer.accountKey(StagingDirectory)
	if err != nil {
		t.Fatal(err)
	}
	b, err := issuer.accountKey(StagingDirectory)
	if err != nil {
		t.Fatal(err)
	}
	c, err := issuer.accountKey(ProductionDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a.Public(), b.Public()) || reflect.DeepEqual(a.Public(), c.Public()) {
		t.Fatal("account key isolation failed")
	}
	paths, err := filepath.Glob(filepath.Join(issuer.Dir, "account-*"))
	if err != nil || len(paths) != 2 {
		t.Fatal("missing account keys", err)
	}
}

func privateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestFunnelHostnameSuffix(t *testing.T) {
	for _, test := range []struct {
		name, suffix, want string
		bad                bool
	}{
		{name: "ashburn", want: "ashburn-funnel.example.com"},
		{name: "ashburn", suffix: "-public", want: "ashburn-public.example.com"},
		{name: "ashburn", suffix: ".share", bad: true},
		{name: strings.Repeat("a", 60), suffix: "-funnel", bad: true},
		{name: "x.other", suffix: "-funnel", bad: true},
		{name: "ashburn", suffix: "-", bad: true},
	} {
		t.Run(test.name+test.suffix, func(t *testing.T) {
			host, err := FunnelHost(test.name, test.suffix, "example.com")
			if (err != nil) != test.bad || host != test.want {
				t.Fatalf("host=%q err=%v", host, err)
			}
		})
	}
}

type blockedIssuer struct{ entered, cancelled, release chan struct{} }

func (b *blockedIssuer) Issue(ctx context.Context, _ string, _ string, _ TXT) (Bundle, error) {
	close(b.entered)
	<-ctx.Done()
	close(b.cancelled)
	<-b.release
	return Bundle{}, ctx.Err()
}
func TestShutdownJoinsCertificateHandlersBeforeUnlock(t *testing.T) {
	m, _, _, _ := fixture(t)
	issuer := &blockedIssuer{entered: make(chan struct{}), cancelled: make(chan struct{}), release: make(chan struct{})}
	m.ACME = issuer
	stop, err := m.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requestDone := make(chan error, 1)
	go func() {
		var cert Certificate
		requestDone <- Request(context.Background(), m.Store.Dir, "POST", "/cert", CertRequest{Name: "ashburn", IP: "100.96.0.7"}, &cert)
	}()
	select {
	case <-issuer.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("certificate handler did not start")
	}
	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()
	select {
	case <-issuer.cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not cancel issuance")
	}
	select {
	case <-stopped:
		t.Fatal("shutdown unlocked state before issuance cleanup completed")
	default:
	}
	close(issuer.release)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not join handler")
	}
	<-requestDone
}

type countedDNS struct {
	*fakeCloud
	counts map[string]int
}

func (d countedDNS) PublicationRecordCount(_ context.Context, zone string) (int, error) {
	return d.counts[zone], nil
}
func TestSelectZoneRequiresExplicitChoice(t *testing.T) {
	dns := countedDNS{fakeCloud: &fakeCloud{zones: []cfapi.Zone{{ID: "busy", Name: "a.example", Status: "active"}, {ID: "quiet", Name: "z.example", Status: "active"}, {ID: "inactive", Name: "inactive.example", Status: "pending"}}}, counts: map[string]int{"busy": 40, "quiet": 10, "inactive": 0}}
	zone, err := SelectZone(context.Background(), dns, "account", "")
	if err == nil || !strings.Contains(err.Error(), "--zone") {
		t.Fatal("silently selected a zone", zone, err)
	}
	zone, err = SelectZone(t.Context(), dns, "account", "z.example")
	if err != nil || zone.ID != "quiet" {
		t.Fatal("explicit zone failed", zone, err)
	}
}
func TestForeignManagedMarkerDoesNotAuthorizeAdoption(t *testing.T) {
	m, cloud, _, _ := fixture(t)
	cloud.records["foreign"] = cfapi.DNSRecord{ID: "foreign", Name: "ashburn-funnel.example.com", Type: "CNAME", Content: "tunnel.cfargotunnel.com", Proxied: true, Comment: ManagedComment}
	if _, err := m.Enable(context.Background(), FunnelRequest{Name: "ashburn", Port: 8000}); err == nil {
		t.Fatal("adopted matching marker without recorded ID")
	}
	if cloud.records["foreign"].ID != "foreign" {
		t.Fatal("changed foreign record")
	}
}
