package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/backend"
	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/exitnode"
	"github.com/Whiteknight07/meshscale/internal/secure"
	"github.com/Whiteknight07/meshscale/internal/service"
)

func doctorReady[T any](value T, err error) *doctorFuture[T] {
	f := &doctorFuture[T]{done: make(chan struct{}), result: doctorValue[T]{value, err}}
	close(f.done)
	return f
}

type doctorTestBackend struct {
	status   backend.Status
	settings string
}

func (b *doctorTestBackend) Status(context.Context) (backend.Status, error) { return b.status, nil }
func (*doctorTestBackend) Registration(context.Context) (backend.Registration, error) {
	return backend.Registration{}, nil
}
func (*doctorTestBackend) Connect(context.Context) error              { panic("doctor attempted Connect") }
func (*doctorTestBackend) Disconnect(context.Context) error           { panic("doctor attempted Disconnect") }
func (b *doctorTestBackend) Settings(context.Context) (string, error) { return b.settings, nil }

func doctorFixture(t *testing.T) (*doctorInputs, *doctorTestBackend) {
	t.Helper()
	b := &doctorTestBackend{status: backend.Status{State: "connected", Connected: true}, settings: "(network policy)\tMode: WarpWithDnsOverHttps\n(network policy)\tInclude mode, with hosts/ips:\n 100.96.0.0/12\n"}
	d := &doctorInputs{
		dir:           t.TempDir(),
		local:         doctorReady(doctorBackend{local: b, settings: config.BackendSettings{Backend: "warp"}}, nil),
		registration:  doctorReady(backend.Registration{RegistrationID: "local-reg", AccountType: "Team", Organization: "example"}, nil),
		organization:  doctorReady(cfapi.Organization{AuthDomain: "example.cloudflareaccess.com"}, nil),
		registrations: doctorReady([]cfapi.Registration{{ID: "local-reg", VirtualIPv4: "100.96.0.7", Device: cfapi.RegistrationDevice{ID: "physical"}}}, nil),
		daemon:        doctorReady(service.Status{Mode: "daemon", LastSync: time.Now()}, nil),
		inventory:     doctorReady([]meshDevice{{DNSName: "node.mesh", IPv4: "100.96.0.7", ThisMachine: true}}, nil),
		lookup: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("100.96.0.7")}, nil
		},
	}
	return d, b
}

// Seed independent failures and exercise the actual check implementations.
func TestDoctorSeededFailures(t *testing.T) {
	tests := []struct {
		name  string
		seed  func(*doctorInputs, *doctorTestBackend)
		check func(*doctorInputs, context.Context) doctorCheck
		want  string
	}{
		{"disconnected", func(_ *doctorInputs, b *doctorTestBackend) { b.status = backend.Status{State: "disconnected"} }, (*doctorInputs).checkConnection, "fail"},
		{"wrong account registration", func(d *doctorInputs, _ *doctorTestBackend) {
			d.registration = doctorReady(backend.Registration{RegistrationID: "other"}, nil)
		}, (*doctorInputs).checkRegistration, "fail"},
		{"revoked registration", func(d *doctorInputs, _ *doctorTestBackend) {
			now := time.Now()
			d.registrations.result.value[0].RevokedAt = &now
		}, (*doctorInputs).checkRegistration, "fail"},
		{"wrong team", func(d *doctorInputs, _ *doctorTestBackend) { d.registration.result.value.Organization = "other" }, (*doctorInputs).checkTeam, "fail"},
		{"unsafe profile", func(_ *doctorInputs, b *doctorTestBackend) {
			b.settings = strings.ReplaceAll(b.settings, "100.96.0.0/12", "0.0.0.0/0")
		}, (*doctorInputs).checkTeam, "fail"},
		{"sync error", func(d *doctorInputs, _ *doctorTestBackend) { d.daemon.result.value.SyncError = "permission denied" }, (*doctorInputs).checkDaemon, "fail"},
		{"no successful sync", func(d *doctorInputs, _ *doctorTestBackend) { d.daemon.result.value.LastSync = time.Time{} }, (*doctorInputs).checkDaemon, "fail"},
		{"stale sync", func(d *doctorInputs, _ *doctorTestBackend) {
			d.daemon.result.value.LastSync = time.Now().Add(-10 * time.Minute)
		}, (*doctorInputs).checkDaemon, "warn"},
		{"secure engine stopped", func(d *doctorInputs, _ *doctorTestBackend) { d.daemon.result.value.Secure.Enabled = true }, (*doctorInputs).checkSecure, "fail"},
		{"secure error", func(d *doctorInputs, _ *doctorTestBackend) {
			d.daemon.result.value.Secure.Error = "peer discovery failed"
		}, (*doctorInputs).checkSecure, "fail"},
		{"SSH off but daemon on", func(d *doctorInputs, _ *doctorTestBackend) {
			writeDoctorFixture(t, d.dir, "cloudflare-ssh/state.json", `{"mode":"off"}`)
			d.daemon.result.value.SSH = true
		}, (*doctorInputs).checkSSH, "fail"},
		{"DNS lookup failed", func(d *doctorInputs, _ *doctorTestBackend) {
			d.lookup = func(context.Context, string, string) ([]netip.Addr, error) { return nil, errors.New("NXDOMAIN") }
		}, (*doctorInputs).checkDNS, "fail"},
		{"wrong DNS address", func(d *doctorInputs, _ *doctorTestBackend) {
			d.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
			}
		}, (*doctorInputs).checkDNS, "fail"},
		{"API forbidden", func(d *doctorInputs, _ *doctorTestBackend) {
			d.organization = doctorReady(cfapi.Organization{}, &cfapi.APIError{StatusCode: 403})
		}, (*doctorInputs).checkAPI, "fail"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, b := doctorFixture(t)
			tt.seed(d, b)
			got := tt.check(d, t.Context())
			if got.Status != tt.want || got.Hint == "" {
				t.Fatalf("check=%+v, want %s and hint", got, tt.want)
			}
		})
	}
}
func writeDoctorFixture(t *testing.T, dir, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(dir, path)
	if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}
func TestDoctorHealthyAndWarnings(t *testing.T) {
	d, _ := doctorFixture(t)
	for _, check := range []func(context.Context) doctorCheck{d.checkConnection, d.checkRegistration, d.checkTeam, d.checkDaemon, d.checkSecure, d.checkSSH, d.checkDNS, d.checkAPI} {
		if got := check(t.Context()); got.Status != "ok" {
			t.Fatalf("healthy check=%+v", got)
		}
	}
	d.daemon = doctorReady(service.Status{}, os.ErrNotExist)
	if got := d.checkDaemon(t.Context()); got.Status != "warn" {
		t.Fatalf("absent daemon=%+v", got)
	}
	writeDoctorFixture(t, d.dir, "secure/config.json", `{"enabled":true}`)
	if got := d.checkSecure(t.Context()); got.Status != "fail" {
		t.Fatalf("secure without daemon=%+v", got)
	}
}
func TestDoctorConcurrentBoundedAndExitStatus(t *testing.T) {
	gate := make(chan struct{})
	defer close(gate)
	tasks := make([]doctorTask, 12)
	for i := range tasks {
		tasks[i] = doctorTask{name: "blocked", measurement: "fixture", hint: "retry", run: func(context.Context) doctorCheck { <-gate; return doctorResult("ok", "late", "retry") }}
	}
	started := time.Now()
	report := runDoctorTasks(t.Context(), tasks, 20*time.Millisecond)
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("checks ran serially or ignored timeout: %s", elapsed)
	}
	if !report.failed() {
		t.Fatal("timeouts must fail")
	}
	for _, check := range report.Checks {
		if check.Status != "fail" || check.Hint == "" {
			t.Fatalf("timeout check=%+v", check)
		}
	}
	report.Checks = []doctorCheck{{Status: "ok"}, {Status: "warn"}}
	if report.failed() {
		t.Fatal("warnings must return success")
	}
	var out bytes.Buffer
	if err := writeDoctor(&out, report, true); err != nil {
		t.Fatal(err)
	}
	var decoded doctorReport
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
}
func TestDoctorNoConfigWritesOrOAuthRefresh(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "")
	dir, _ := doctorConfigDir()
	if _, err := doctorCredentials(dir); err == nil {
		t.Fatal("missing credentials accepted")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("created config: %v", err)
	}
	if err := doctorReadJSON(filepath.Join(dir, "secure/config.json"), &secure.Config{}); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := doctorServiceRequest(t.Context(), filepath.Join(dir, "service"), "/status", &service.Status{}); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("read created config: %v", err)
	}
	data := `{"client_id":"client","access_token":"planted-access","refresh_token":"planted-refresh","expiry":"2000-01-01T00:00:00Z","account":{"id":"account"}}`
	writeDoctorFixture(t, dir, "oauth.json", data)
	if _, err := doctorCredentials(dir); err == nil {
		t.Fatal("expired OAuth token accepted")
	}
	after, err := os.ReadFile(filepath.Join(dir, "oauth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != data {
		t.Fatal("doctor refreshed or rewrote OAuth session")
	}
}
func TestDoctorOverlapEvidence(t *testing.T) {
	s := exitnode.Snapshot{Links: []exitnode.Link{{Name: "tailscale0"}, {Name: "CloudflareWARP"}}, V4: exitnode.Family{
		Routes: []exitnode.Route{{Dst: "100.96.0.0/12", Dev: "CloudflareWARP", Table: "65743"}},
		Rules:  []exitnode.Rule{{Priority: 5209, Table: "65743", Not: json.RawMessage("true"), FWMark: "0x100cf"}, {Priority: 5208, Table: "52", Dst: "100.96.0.0", DstLen: 12, Protocol: "243"}},
	}}
	if got := doctorOverlapRule(s); got.Status != "ok" {
		t.Fatalf("healthy overlap=%+v", got)
	}
	s.V4.Rules[1].Priority = 5210
	if got := doctorOverlapRule(s); got.Status != "fail" {
		t.Fatalf("late exception=%+v", got)
	}
	s.V4.Routes = append(s.V4.Routes, exitnode.Route{Dst: "default", Table: "52"})
	if got := doctorOverlapRule(s); got.Status != "warn" {
		t.Fatalf("exit conflict=%+v", got)
	}
	s.Links = nil
	if got := doctorOverlapRule(s); got.Status != "ok" {
		t.Fatalf("no tailscale=%+v", got)
	}
	rule := `-A ts-input -s 100.96.0.0/12 -i CloudflareWARP -m comment --comment "meshscale Mesh coexistence" -j RETURN`
	if !doctorFirstIngressRule("-N ts-input\n" + rule) {
		t.Fatal("missed first exception")
	}
	if doctorFirstIngressRule("-A ts-input -j DROP\n" + rule) {
		t.Fatal("accepted exception after DROP")
	}
}

func TestDoctorWarpReadOnlyAndTermsFailures(t *testing.T) {
	var calls []string
	client := doctorWarpClient("warp-cli", func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "--accept-tos" {
			args = args[1:]
		}
		calls = append(calls, strings.Join(args, " "))
		return []byte("Cloudflare One terms of service have not been accepted; use --accept-tos"), errors.New("exit status 1")
	})
	d, _ := doctorFixture(t)
	d.local = doctorReady(doctorBackend{local: client, settings: config.BackendSettings{Backend: "warp"}}, nil)
	_, regErr := client.Registration(t.Context())
	d.registration = doctorReady(backend.Registration{}, regErr)
	for _, check := range []doctorCheck{d.checkConnection(t.Context()), d.checkRegistration(t.Context()), d.checkTeam(t.Context())} {
		if check.Status != "warn" || check.Detail != "unavailable: Cloudflare One terms not accepted yet" {
			t.Fatalf("terms check=%+v", check)
		}
	}
	if _, err := client.Settings(t.Context()); !errors.Is(err, errDoctorTermsNotAccepted) {
		t.Fatal(err)
	}
	d.registration = doctorReady(backend.Registration{RegistrationID: "local-reg", AccountType: "Team", Organization: "example"}, nil)
	if check := d.checkTeam(t.Context()); check.Status != "warn" || !strings.Contains(check.Detail, "terms not accepted yet") {
		t.Fatalf("settings terms=%+v", check)
	}
	if err := client.Connect(t.Context()); err == nil {
		t.Fatal("diagnostic client allowed Connect")
	}
	if got := strings.Join(calls, ","); got != "registration show,status,settings,settings" {
		t.Fatalf("calls=%s", got)
	}
}

func TestDoctorUsesDiagnosticWarpExecutor(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir, _ := doctorConfigDir()
	writeDoctorFixture(t, dir, "backend.json", `{"backend":"warp"}`)
	bin := t.TempDir()
	// Linux warp-cli without a TTY refuses unless --accept-tos is on each call.
	script := "#!/bin/sh\n[ \"$1\" = --accept-tos ] || { printf '%s\\n' 'Please accept the WARP Terms of Service by running this command in a TTY or by passing the --accept-tos flag.'; exit 1; }\nexit 92\n"
	if err := os.WriteFile(filepath.Join(bin, "warp-cli"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	d := newDoctorInputs(t.Context())
	// The fake only gets past its terms prompt when the flag is passed, so no
	// check may report missing consent on a host already set up.
	for _, check := range []doctorCheck{d.checkConnection(t.Context()), d.checkRegistration(t.Context()), d.checkTeam(t.Context())} {
		if strings.Contains(check.Detail, "terms not accepted yet") {
			t.Fatalf("diagnostic reads omitted --accept-tos: %+v", check)
		}
	}
}

func TestDoctorFirstSyncFailureIncludesCause(t *testing.T) {
	d, _ := doctorFixture(t)
	d.daemon.result.value.LastSync = time.Time{}
	d.daemon.result.value.SyncError = "hosts: atomically replace hosts file: device or resource busy"
	check := d.checkDaemon(t.Context())
	if check.Status != "fail" || !strings.Contains(check.Detail, d.daemon.result.value.SyncError) {
		t.Fatalf("first sync failure lost its cause: %+v", check)
	}
}
