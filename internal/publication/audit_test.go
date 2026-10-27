package publication

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

type waitingIssuer struct {
	entered, release chan struct{}
	bundle           Bundle
}

func (w *waitingIssuer) Issue(context.Context, string, string, TXT) (Bundle, error) {
	close(w.entered)
	<-w.release
	return w.bundle, nil
}

func TestRenewalDoesNotBlockStatusOrFunnelOff(t *testing.T) {
	m, _, process, issuer := fixture(t)
	issuer.bundle = certificateBundle(t, "ashburn.mesh.example.com")
	cert, err := m.Cert(t.Context(), CertRequest{Name: "ashburn", IP: "100.96.0.7"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Enable(t.Context(), FunnelRequest{Name: "ashburn", Port: 8000}); err != nil {
		t.Fatal(err)
	}
	waiting := &waitingIssuer{entered: make(chan struct{}), release: make(chan struct{}), bundle: issuer.bundle}
	m.ACME = waiting
	renewed := make(chan struct{})
	go func() { defer close(renewed); m.renew(t.Context(), cert.RenewAt.Add(time.Second)) }()
	<-waiting.entered
	defer func() { close(waiting.release); <-renewed }()
	done := make(chan error, 1)
	go func() {
		if status := m.Status(); len(status.Certificates) != 1 {
			done <- fmt.Errorf("lost certificate snapshot")
			return
		}
		done <- m.Off(t.Context())
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("renewal blocked status or Funnel off")
	}
	if process.running || m.Status().Funnel != nil {
		t.Fatal("Funnel off did not finish during ACME issuance")
	}
	// Returned snapshots must not expose mutable manager state.
	snapshot := m.Status()
	snapshot.Certificates[0].Name = "changed"
	if m.Status().Certificates[0].Name != cert.Name {
		t.Fatal("status aliases certificate state")
	}
}

func TestOwnedCertificateAddressChangeAndRemoval(t *testing.T) {
	m, cloud, _, issuer := fixture(t)
	issuer.bundle = certificateBundle(t, "ashburn.mesh.example.com")
	first, err := m.Cert(t.Context(), CertRequest{Name: "ashburn", IP: "100.96.0.7"})
	if err != nil {
		t.Fatal(err)
	}
	var id string
	for key := range cloud.records {
		id = key
	}
	second, err := m.Cert(t.Context(), CertRequest{Name: "ashburn", IP: "100.96.0.8"})
	if err != nil {
		t.Fatal(err)
	}
	if second.IP != "100.96.0.8" || cloud.records[id].Content != second.IP || len(cloud.records) != 1 {
		t.Fatal("owned A record not updated in place")
	}
	if _, err := os.Stat(filepath.Dir(first.KeyFile)); !os.IsNotExist(err) {
		t.Fatal("superseded generation remains", err)
	}
	// A customer record is never included in removal.
	cloud.records["customer"] = cfapi.DNSRecord{ID: "customer", Type: "A", Name: second.Name, Content: "100.96.0.99"}
	request := httptest.NewRequest("DELETE", "/cert", strings.NewReader(`{"name":"ashburn"}`))
	response := httptest.NewRecorder()
	m.handler().ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("rm status=%d: %s", response.Code, response.Body.String())
	}
	if len(m.Status().Certificates) != 0 || len(cloud.records) != 1 || cloud.records["customer"].ID != "customer" {
		t.Fatal("rm removed foreign DNS or retained owned state")
	}
	if _, err := os.Stat(filepath.Dir(second.KeyFile)); !os.IsNotExist(err) {
		t.Fatal("removed certificate key remains", err)
	}
	if err := m.RemoveCert(t.Context(), "ashburn"); err != nil {
		t.Fatal("rm is not idempotent", err)
	}
}

func TestCertificateMutationRejectsExternallyChangedRecord(t *testing.T) {
	for _, action := range []string{"update", "remove"} {
		t.Run(action, func(t *testing.T) {
			m, cloud, _, issuer := fixture(t)
			issuer.bundle = certificateBundle(t, "ashburn.mesh.example.com")
			cert, err := m.Cert(t.Context(), CertRequest{Name: "ashburn", IP: "100.96.0.7"})
			if err != nil {
				t.Fatal(err)
			}
			for id, record := range cloud.records {
				record.Comment = "customer"
				cloud.records[id] = record
			}
			if action == "update" {
				_, err = m.Cert(t.Context(), CertRequest{Name: "ashburn", IP: "100.96.0.8"})
			} else {
				err = m.RemoveCert(t.Context(), "ashburn")
			}
			if err == nil || len(m.Status().Certificates) != 1 || len(cloud.records) != 1 {
				t.Fatal("changed externally modified DNS or certificate state", err)
			}
			if _, err := os.Stat(cert.KeyFile); err != nil {
				t.Fatal("deleted working certificate", err)
			}
		})
	}
}

func TestCertificateGenerationDeletionIsConfined(t *testing.T) {
	m, _, _, _ := fixture(t)
	outside := filepath.Join(t.TempDir(), "cert-outside")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "key.pem"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{outside, m.Store.Dir, filepath.Join(m.Store.Dir, "unrelated")} {
		if err := m.removeGeneration(Certificate{CertFile: filepath.Join(dir, "cert.pem"), KeyFile: filepath.Join(dir, "key.pem")}); err == nil {
			t.Fatalf("accepted unsafe generation %s", dir)
		}
	}
	link := filepath.Join(m.Store.Dir, "cert-link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := m.removeGeneration(Certificate{CertFile: filepath.Join(link, "cert.pem"), KeyFile: filepath.Join(link, "key.pem")}); err == nil {
		t.Fatal("followed symlink generation")
	}
	if _, err := os.Stat(filepath.Join(outside, "key.pem")); err != nil {
		t.Fatal("deleted outside private key", err)
	}
}

func TestPinnedZoneSurvivesAmbiguousDiscovery(t *testing.T) {
	m, cloud, _, _ := fixture(t)
	if err := m.zone(t.Context(), ""); err != nil {
		t.Fatal(err)
	}
	cloud.zones = append(cloud.zones, cfapi.Zone{ID: "second", Name: "second.example", Status: "active"})
	calls := cloud.calls
	if err := m.zone(t.Context(), ""); err != nil || cloud.calls != calls {
		t.Fatal("pinned zone rediscovered", err)
	}
}

func TestReconciledFunnelIDsAreRolledBack(t *testing.T) {
	for _, failedCreate := range []string{"app", "tunnel", "dns"} {
		for _, failure := range []string{"5xx", "reset", "eof", "truncated-json", "decode-result"} {
			t.Run(failedCreate+"/"+failure, func(t *testing.T) {
				m, _, _, _ := fixture(t)
				m.state.Zone = cfapi.Zone{ID: "zone", Name: "example.com", Status: "active"}
				var app cfapi.PublicApplication
				var tunnel cfapi.PublicTunnel
				var record cfapi.DNSRecord
				deleted := map[string]bool{}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					result := any(map[string]any{})
					if r.Method == "DELETE" {
						deleted[filepath.Base(r.URL.Path)] = true
						fmt.Fprint(w, `{"success":true,"result":{}}`)
						return
					}
					switch {
					case strings.HasSuffix(r.URL.Path, "/access/apps"):
						if r.Method == "POST" {
							json.NewDecoder(r.Body).Decode(&app)
							assertAttemptJournaled(t, m.Store, "app", app.Name)
							app.ID, app.AUD = "app", "aud"
							result = app
							if failedCreate == "app" {
								failCommittedCreate(t, w, failure)
								return
							}
						} else {
							result = []cfapi.PublicApplication{app}
						}
					case strings.HasSuffix(r.URL.Path, "/access/apps/app/policies"):
						result = app.Policies
					case strings.HasSuffix(r.URL.Path, "/access/apps/app"):
						result = app
					case strings.HasSuffix(r.URL.Path, "/cfd_tunnel/tunnel"):
						result = tunnel
					case strings.HasSuffix(r.URL.Path, "/access/organizations"):
						if failedCreate == "app" {
							assertIDJournaled(t, m.Store, "app")
						}
						if failedCreate == "app" {
							w.WriteHeader(400)
							return
						}
						result = cfapi.Organization{AuthDomain: "team.cloudflareaccess.com"}
					case strings.HasSuffix(r.URL.Path, "/cfd_tunnel"):
						if r.Method == "POST" {
							json.NewDecoder(r.Body).Decode(&tunnel)
							assertAttemptJournaled(t, m.Store, "tunnel", tunnel.Name)
							tunnel.ID = "tunnel"
							result = tunnel
							if failedCreate == "tunnel" {
								failCommittedCreate(t, w, failure)
								return
							}
						} else {
							result = []cfapi.PublicTunnel{tunnel}
						}
					case strings.HasSuffix(r.URL.Path, "/configurations"):
						if failedCreate == "tunnel" {
							assertIDJournaled(t, m.Store, "tunnel")
						}
						if failedCreate == "tunnel" {
							w.WriteHeader(400)
							return
						}
					case strings.HasSuffix(r.URL.Path, "/token"):
						result = "private-token"
					case strings.HasSuffix(r.URL.Path, "/dns_records"):
						if r.Method == "POST" {
							json.NewDecoder(r.Body).Decode(&record)
							assertAttemptJournaled(t, m.Store, "dns", record.Comment)
							record.ID = "dns"
							failCommittedCreate(t, w, failure)
							return
						}
						if record.ID != "" {
							result = []cfapi.DNSRecord{record}
						} else {
							result = []cfapi.DNSRecord{}
						}
					case strings.HasSuffix(r.URL.Path, "/dns_records/dns"):
						result = record
					default:
						t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					}
					json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
				}))
				defer server.Close()
				client := cfapi.New(cfapi.StaticToken("test-token"), "test")
				client.BaseURL = server.URL
				m.DNS, m.Tunnels = client, client
				_, err := m.Enable(t.Context(), FunnelRequest{Name: "ashburn", Port: 8000, OwnerOnly: true})
				if failedCreate != "dns" && err == nil {
					t.Fatal("expected downstream failure")
				}
				if failedCreate == "dns" {
					// Successful recovery must journal the reconciled DNS ID for later off.
					assertIDJournaled(t, m.Store, "dns")
					if err != nil {
						t.Fatal(err)
					}
					if m.state.Funnel.DNSID != "dns" {
						t.Fatal("DNS ID not journaled")
					}
					if err := m.Off(t.Context()); err != nil {
						t.Fatal(err)
					}
				}
				if !deleted["app"] || failedCreate != "app" && !deleted["tunnel"] || failedCreate == "dns" && !deleted["dns"] {
					t.Fatalf("reconciled resources leaked: %v", deleted)
				}
			})
		}
	}
}

func TestFailedCertificateCommitKeepsPreviousGeneration(t *testing.T) {
	m, _, _, issuer := fixture(t)
	issuer.bundle = certificateBundle(t, "ashburn.mesh.example.com")
	cert, err := m.Cert(t.Context(), CertRequest{Name: "ashburn", IP: "100.96.0.7"})
	if err != nil {
		t.Fatal(err)
	}
	waiting := &waitingIssuer{entered: make(chan struct{}), release: make(chan struct{}), bundle: issuer.bundle}
	m.ACME = waiting
	done := make(chan struct{})
	go func() { defer close(done); m.renew(t.Context(), cert.RenewAt.Add(time.Second)) }()
	<-waiting.entered
	statePath := filepath.Join(m.Store.Dir, "state.json")
	if err := os.Remove(statePath); err != nil {
		close(waiting.release)
		<-done
		t.Fatal(err)
	}
	if err := os.Mkdir(statePath, 0700); err != nil {
		close(waiting.release)
		<-done
		t.Fatal(err)
	}
	close(waiting.release)
	<-done
	if _, err := os.Stat(cert.KeyFile); err != nil {
		t.Fatal("failed commit removed previous private key", err)
	}
	if status := m.Status(); len(status.Certificates) != 1 || status.Certificates[0] != cert || status.RenewalError == "" {
		t.Fatal("failed commit published new paths", status)
	}
	dirs, err := filepath.Glob(filepath.Join(m.Store.Dir, "cert-*"))
	if err != nil || len(dirs) != 1 || dirs[0] != filepath.Dir(cert.CertFile) {
		t.Fatal("uncommitted generation leaked", dirs, err)
	}
}

// These servers consume the POST before dropping the response. The client must
// reconcile the committed resource rather than retrying its non-idempotent POST.
func failCommittedCreate(t *testing.T, w http.ResponseWriter, failure string) {
	t.Helper()
	if failure == "5xx" {
		w.WriteHeader(500)
		return
	}
	if failure == "decode-result" {
		fmt.Fprint(w, `{"success":true,"result":42}`)
		return
	}
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Error(err)
		return
	}
	if failure == "reset" {
		if tcp, ok := conn.(*net.TCPConn); ok {
			if err := tcp.SetLinger(0); err != nil {
				t.Error(err)
			}
		}
	}
	if failure == "truncated-json" {
		fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n"+`{"success":true,"result":{"id":`)
	}
	conn.Close()
}
func assertAttemptJournaled(t *testing.T, store Store, resource, marker string) {
	t.Helper()
	state, err := store.Load()
	if err != nil {
		t.Error(err)
		return
	}
	nonce := cfapi.CreationNonce(marker)
	if nonce == "" {
		t.Errorf("%s POST has no nonce", resource)
		return
	}
	if resource == "dns" {
		for _, owned := range state.Records {
			if owned.Record.ID == "" && owned.Record.Comment == marker {
				return
			}
		}
	} else if state.Funnel != nil && state.Funnel.Nonce == nonce {
		if resource == "app" && state.Funnel.OwnerEmail != "" || resource == "tunnel" && state.Funnel.TunnelAttempted {
			return
		}
	}
	t.Errorf("%s creation nonce was not persisted before POST", resource)
}
func assertIDJournaled(t *testing.T, store Store, resource string) {
	t.Helper()
	state, err := store.Load()
	if err != nil {
		t.Error(err)
		return
	}
	if state.Funnel == nil {
		t.Error("missing Funnel journal")
		return
	}
	id := map[string]string{"app": state.Funnel.AppID, "tunnel": state.Funnel.TunnelID, "dns": state.Funnel.DNSID}[resource]
	if id != resource {
		t.Errorf("%s ID not persisted: %q", resource, id)
	}
}

func TestForeignOrBroaderAccessAppNeverAdoptedOrDeleted(t *testing.T) {
	for _, kind := range []string{"same-name-no-nonce", "different-nonce", "broader-policy", "wrong-type"} {
		t.Run(kind, func(t *testing.T) {
			m, _, _, _ := fixture(t)
			m.state.Zone = cfapi.Zone{ID: "zone", Name: "example.com", Status: "active"}
			var app cfapi.PublicApplication
			deletes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "DELETE" {
					deletes++
					t.Error("deleted unrelated or unsafe Access application")
				}
				var result any
				switch {
				case r.Method == "POST":
					if err := json.NewDecoder(r.Body).Decode(&app); err != nil {
						t.Error(err)
					}
					assertAttemptJournaled(t, m.Store, "app", app.Name)
					app.ID = "customer-app"
					switch kind {
					case "same-name-no-nonce":
						app.Name = "meshscale Funnel: " + app.Domain
					case "different-nonce":
						app.Name = "meshscale Funnel: " + app.Domain + creationMarker(strings.Repeat("0", 32))
					case "broader-policy":
						app.Policies[0].Include = []cfapi.AccessRule{{"everyone": json.RawMessage(`{}`)}}
					case "wrong-type":
						app.Type = "warp"
					}
					w.WriteHeader(500)
					return
				case strings.HasSuffix(r.URL.Path, "/policies"):
					result = app.Policies
				default:
					result = []cfapi.PublicApplication{app}
				}
				json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
			}))
			defer server.Close()
			client := cfapi.New(cfapi.StaticToken("test-token"), "test")
			client.BaseURL = server.URL
			m.Tunnels = client
			_, err := m.Enable(t.Context(), FunnelRequest{Name: "ashburn", Port: 8000, OwnerOnly: true})
			if err == nil {
				t.Fatal("adopted foreign or unsafe Access app")
			}
			if kind == "broader-policy" || kind == "wrong-type" {
				if !strings.Contains(err.Error(), "policy mismatch") {
					t.Fatalf("unclear mismatch error: %v", err)
				}
			}
			_ = m.Off(t.Context())
			if deletes != 0 || m.state.Funnel != nil && m.state.Funnel.AppID != "" {
				t.Fatal("foreign ID was journaled or deleted")
			}
		})
	}
}

func TestFunnelOffRechecksResourceOwnershipAndPolicy(t *testing.T) {
	for _, change := range []string{"app-name", "app-type", "app-policy", "extra-policy", "tunnel-name", "missing-nonce"} {
		t.Run(change, func(t *testing.T) {
			m, cloud, _, _ := fixture(t)
			if _, err := m.Enable(t.Context(), FunnelRequest{Name: "ashburn", Port: 8000, OwnerOnly: true}); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "app-name":
				cloud.app.Name = "customer app"
			case "app-type":
				cloud.app.Type = "warp"
			case "app-policy":
				cloud.app.Policies[0].Include = []cfapi.AccessRule{{"everyone": json.RawMessage(`{}`)}}
			case "extra-policy":
				cloud.app.Policies = append(cloud.app.Policies, cfapi.EnrollmentPolicy{Decision: "bypass"})
			case "tunnel-name":
				cloud.tunnel.Name = "customer tunnel"
			case "missing-nonce":
				m.state.Funnel.Nonce = ""
			}
			if err := m.Off(t.Context()); err == nil {
				t.Fatal("removed resource without matching ownership/policy")
			}
			for _, event := range cloud.events {
				if event == "delete-access" || (change == "tunnel-name" || change == "missing-nonce") && event == "delete-tunnel" {
					t.Fatalf("deleted changed resource: %s", event)
				}
			}
		})
	}
}

func TestCertificateCAsShareDesiredAddressAcrossRenewalAndMigration(t *testing.T) {
	m, cloud, _, issuer := fixture(t)
	issuer.bundle = certificateBundle(t, "ashburn.mesh.example.com")
	prod, err := m.Cert(t.Context(), CertRequest{Name: "ashburn", IP: "100.96.0.7"})
	if err != nil {
		t.Fatal(err)
	}
	staging, err := m.Cert(t.Context(), CertRequest{Name: "ashburn", IP: "100.96.0.7", Staging: true})
	if err != nil {
		t.Fatal(err)
	}
	prod, err = m.Cert(t.Context(), CertRequest{Name: "ashburn", IP: "100.96.0.8"})
	if err != nil {
		t.Fatal(err)
	}
	if staging.IP != "100.96.0.7" || prod.IP != "100.96.0.8" {
		t.Fatal("bad regression setup")
	}
	// Simulate a manifest from before shared hostname addresses were introduced.
	m.state.DesiredAddresses = nil
	for i := range m.state.Records {
		if m.state.Records[i].Record.Type == "A" {
			m.state.Records[i].Record.Comment = ManagedComment
			cloud.records[m.state.Records[i].Record.ID] = m.state.Records[i].Record
		}
	}
	if err := m.save(); err != nil {
		t.Fatal(err)
	}
	restored, err := New(m.Store, "account", cloud, cloud, m.Process, issuer)
	if err != nil {
		t.Fatal(err)
	}
	if restored.state.DesiredAddresses[prod.Name] != "100.96.0.8" {
		t.Fatal("migration did not prefer the current A ledger")
	}
	// Only staging is due, so production cannot mask an obsolete staging write.
	restored.state.Certificates[0].RenewAt = staging.RenewAt.Add(time.Hour)
	restored.renew(t.Context(), staging.RenewAt.Add(time.Second))
	for _, record := range cloud.records {
		if record.Type == "A" && record.Content != "100.96.0.8" {
			t.Fatalf("staging renewal restored obsolete address: %#v", record)
		}
	}
	for _, cert := range restored.state.Certificates {
		if cert.IP != "100.96.0.8" {
			t.Fatalf("CA did not renew using shared address: %#v", cert)
		}
	}
	state, err := restored.Store.Load()
	if err != nil || state.DesiredAddresses[prod.Name] != "100.96.0.8" {
		t.Fatal("shared address not persisted", err)
	}
}

func TestInterruptedCreateJournalsRecoverOnlyTheirNonces(t *testing.T) {
	m, cloud, process, _ := fixture(t)
	if _, err := m.Enable(t.Context(), FunnelRequest{Name: "ashburn", Port: 8000, OwnerOnly: true}); err != nil {
		t.Fatal(err)
	}
	// Each remote create committed, but none of its IDs reached the journal.
	m.state.Funnel.Enabled = false
	m.state.Funnel.AppID, m.state.Funnel.TunnelID, m.state.Funnel.DNSID = "", "", ""
	for i := range m.state.Records {
		m.state.Records[i].Record.ID = ""
	}
	cloud.records["foreign"] = cfapi.DNSRecord{ID: "foreign", Name: m.state.Funnel.Host, Type: "CNAME", Content: "tunnel.cfargotunnel.com", Proxied: true, Comment: ManagedComment}
	if err := m.save(); err != nil {
		t.Fatal(err)
	}
	restored, err := New(m.Store, "account", cloud, cloud, process, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.Off(t.Context()); err != nil {
		t.Fatal(err)
	}
	if restored.state.Funnel != nil || len(restored.state.Records) != 0 || len(cloud.records) != 1 || cloud.records["foreign"].ID != "foreign" {
		t.Fatal("incomplete create recovery leaked owned resources or adopted foreign DNS")
	}
}

func TestRemoveCertRecoversPendingDNSCreate(t *testing.T) {
	m, cloud, _, _ := fixture(t)
	if err := m.zone(t.Context(), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := m.createRecord(t.Context(), cfapi.DNSRecord{Type: "A", Name: "ashburn.mesh.example.com", Content: "100.96.0.8"}); err != nil {
		t.Fatal(err)
	}
	m.state.Records[0].Record.ID = ""
	if err := m.save(); err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveCert(t.Context(), "ashburn"); err != nil {
		t.Fatal(err)
	}
	if len(m.state.Records) != 0 || len(cloud.records) != 0 {
		t.Fatal("pending certificate DNS leaked during removal")
	}
}

func TestLegacyDNSCannotAuthorizeUpdate(t *testing.T) {
	m, cloud, _, _ := fixture(t)
	m.state.Zone = cfapi.Zone{ID: "zone", Name: "example.com"}
	record := cfapi.DNSRecord{ID: "legacy", Type: "A", Name: "ashburn.mesh.example.com", Content: "100.96.0.7", Comment: ManagedComment}
	m.state.Records = []OwnedRecord{{ZoneID: "zone", Record: record}}
	cloud.records[record.ID] = record
	if _, err := m.createRecord(t.Context(), cfapi.DNSRecord{Type: "A", Name: record.Name, Content: "100.96.0.8"}); err == nil {
		t.Fatal("updated DNS without a creation nonce")
	}
	if cloud.records[record.ID].Content != record.Content {
		t.Fatal("legacy DNS was changed")
	}
}

func TestRestartRejectsChangedFunnelOwnershipAndAccess(t *testing.T) {
	for _, change := range []string{"tunnel", "access", "missing-nonce"} {
		t.Run(change, func(t *testing.T) {
			m, cloud, process, _ := fixture(t)
			stop, err := m.Start(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			_, err = m.Enable(t.Context(), FunnelRequest{Name: "ashburn", Port: 8000, OwnerOnly: true})
			if err != nil {
				stop()
				t.Fatal(err)
			}
			stop()
			switch change {
			case "tunnel":
				cloud.tunnel.Name = "someone-else"
			case "access":
				cloud.app.Policies[0].Decision = "bypass"
			case "missing-nonce":
				m.state.Funnel.Nonce = ""
				if err := m.save(); err != nil {
					t.Fatal(err)
				}
			}
			starts := process.starts
			restored, err := New(m.Store, "account", cloud, cloud, process, nil)
			if err != nil {
				t.Fatal(err)
			}
			stop, err = restored.Start(t.Context())
			if err == nil {
				stop()
				t.Fatal("restarted a funnel with unverified ownership/access")
			}
			if process.starts != starts {
				t.Fatal("connector started before verification")
			}
		})
	}
}

func TestRestartReassertsOwnerOnlyIngress(t *testing.T) {
	m, cloud, process, _ := fixture(t)
	stop, err := m.Start(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Enable(t.Context(), FunnelRequest{Name: "ashburn", Port: 8000, OwnerOnly: true}); err != nil {
		stop()
		t.Fatal(err)
	}
	stop()
	cloud.configured = nil
	restored, err := New(m.Store, "account", cloud, cloud, process, nil)
	if err != nil {
		t.Fatal(err)
	}
	stop, err = restored.Start(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if cloud.configured == nil || cloud.configured.Access == nil || !cloud.configured.Access.Required || cloud.configured.Access.TeamName != "team" || !reflect.DeepEqual(cloud.configured.Access.AudTag, []string{"aud"}) {
		t.Fatal("restart did not restore connector JWT enforcement")
	}
}

type changedDNSUpdate struct{ *fakeCloud }

func (f changedDNSUpdate) UpdatePublicationRecord(ctx context.Context, zone, id string, r cfapi.DNSRecord) (cfapi.DNSRecord, error) {
	updated, err := f.fakeCloud.UpdatePublicationRecord(ctx, zone, id, r)
	updated.Comment = "externally changed"
	return updated, err
}
func TestCertificateRejectsMismatchedDNSUpdateResponse(t *testing.T) {
	m, cloud, _, issuer := fixture(t)
	issuer.bundle = certificateBundle(t, "ashburn.mesh.example.com")
	before, err := m.Cert(t.Context(), CertRequest{Name: "ashburn", IP: "100.96.0.7"})
	if err != nil {
		t.Fatal(err)
	}
	m.DNS = changedDNSUpdate{cloud}
	if _, err := m.Cert(t.Context(), CertRequest{Name: "ashburn", IP: "100.96.0.8"}); err == nil {
		t.Fatal("accepted mismatched update payload")
	}
	if m.state.Certificates[0].CertFile != before.CertFile {
		t.Fatal("replaced certificate after failed DNS validation")
	}
}
