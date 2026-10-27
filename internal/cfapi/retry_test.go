package cfapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestIdempotentRetries(t *testing.T) {
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		for _, status := range []int{429, 503} {
			t.Run(fmt.Sprintf("%s/%d", method, status), func(t *testing.T) {
				calls := 0
				started := time.Now()
				c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
					calls++
					if calls == 1 {
						w.WriteHeader(status)
						fmt.Fprint(w, "temporary non-JSON response")
						return
					}
					fmt.Fprint(w, `{"success":true,"result":{}}`)
				})
				if _, err := c.request(t.Context(), method, "/retry", nil, map[string]string{"key": "value"}, nil); err != nil || calls != 2 {
					t.Fatalf("calls=%d error=%v", calls, err)
				}
				if time.Since(started) < 100*time.Millisecond {
					t.Fatal("retry omitted backoff")
				}
			})
		}
	}
}

func TestRetryBoundAndRetryAfterCancellation(t *testing.T) {
	calls := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(500) })
	_, err := c.request(t.Context(), "GET", "/retry", nil, nil, nil)
	if err == nil || calls != 4 {
		t.Fatalf("calls=%d error=%v", calls, err)
	}
	calls = 0
	c = testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(429)
	})
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	_, err = c.request(ctx, "GET", "/retry", nil, nil, nil)
	if !errors.Is(err, context.DeadlineExceeded) || calls != 1 {
		t.Fatalf("Retry-After ignored: calls=%d error=%v", calls, err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	for _, value := range []string{"2", now.Add(2 * time.Second).Format(http.TimeFormat)} {
		if got := retryAfter(value, now); got != 2*time.Second {
			t.Fatalf("Retry-After %q = %v", value, got)
		}
	}
}

type publicationTransport func(*http.Request) (*http.Response, error)

func (f publicationTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestUncertainPublicationCreatesReconcileExactOwnedKeys(t *testing.T) {
	for _, resource := range []string{"dns", "tunnel", "app"} {
		for _, failure := range []string{"timeout", "5xx"} {
			for _, owned := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/owned=%t", resource, failure, owned), func(t *testing.T) {
					postCalls, getCalls := 0, 0
					c := New(StaticToken("test-token"), "test")
					c.HTTPClient = &http.Client{Transport: publicationTransport(func(r *http.Request) (*http.Response, error) {
						if r.Method == "POST" {
							postCalls++
							if failure == "timeout" {
								return nil, &uncertainCreateError{context.DeadlineExceeded}
							}
							return &http.Response{StatusCode: 500, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("unknown outcome"))}, nil
						}
						if strings.HasSuffix(r.URL.Path, "/policies") {
							data, _ := json.Marshal([]EnrollmentPolicy{testOwnerPolicy()})
							return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"success":true,"result":` + string(data) + `}`))}, nil
						}
						getCalls++
						var result string
						switch resource {
						case "dns":
							if r.URL.Query().Get("name") != "device.mesh.example.com" {
								t.Error("DNS lookup omitted exact name")
							}
							marker := "customer"
							if owned {
								marker = "managed-by: meshscale meshscale-create:0123456789abcdef0123456789abcdef"
							}
							result = fmt.Sprintf(`[{"id":"created","type":"A","name":"device.mesh.example.com","content":"100.96.0.1","comment":%q},{"id":"other-content","type":"A","name":"device.mesh.example.com","content":"100.96.0.2","comment":"managed-by: meshscale meshscale-create:0123456789abcdef0123456789abcdef"}]`, marker)
						case "tunnel":
							if r.URL.Query().Get("name") != "meshscale-funnel-device meshscale-create:0123456789abcdef0123456789abcdef" {
								t.Error("tunnel lookup omitted exact name")
							}
							name := "customer-device-123456789"
							if owned {
								name = "meshscale-funnel-device meshscale-create:0123456789abcdef0123456789abcdef"
							}
							result = fmt.Sprintf(`[{"id":"created","name":%q},{"id":"other-time","name":"meshscale-funnel-device-987654321"}]`, name)
						case "app":
							name := "customer"
							if owned {
								name = "meshscale Funnel: device-funnel.example.com meshscale-create:0123456789abcdef0123456789abcdef"
							}
							result = fmt.Sprintf(`[{"id":"created","name":%q,"domain":"device-funnel.example.com","aud":"aud","type":"self_hosted"},{"id":"other-domain","name":"meshscale Funnel: device-funnel.example.com meshscale-create:fedcba9876543210fedcba9876543210","domain":"other.example.com"}]`, name)
						}
						return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"success":true,"result":` + result + `}`))}, nil
					})}
					var id string
					var err error
					switch resource {
					case "dns":
						var r DNSRecord
						r, err = c.CreatePublicationRecord(t.Context(), "zone", DNSRecord{Type: "A", Name: "device.mesh.example.com", Content: "100.96.0.1", Comment: "managed-by: meshscale meshscale-create:0123456789abcdef0123456789abcdef"})
						id = r.ID
					case "tunnel":
						var r PublicTunnel
						r, err = c.CreatePublicTunnel(t.Context(), "account", "meshscale-funnel-device meshscale-create:0123456789abcdef0123456789abcdef")
						id = r.ID
					case "app":
						var r PublicApplication
						r, err = c.CreatePublicApplication(t.Context(), "account", PublicApplication{Name: "meshscale Funnel: device-funnel.example.com meshscale-create:0123456789abcdef0123456789abcdef", Domain: "device-funnel.example.com", Type: "self_hosted", Policies: []EnrollmentPolicy{testOwnerPolicy()}})
						id = r.ID
					}
					if postCalls != 1 || getCalls != 1 || (err == nil) != owned || owned && id != "created" {
						t.Fatalf("id=%q error=%v POST=%d GET=%d", id, err, postCalls, getCalls)
					}
				})
			}
		}
	}
}

func TestPublicationQueriesAreBoundedAndFiltered(t *testing.T) {
	calls := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		q := r.URL.Query()
		switch r.URL.Path {
		case "/zones":
			if q.Get("account.id") != "account" || q.Get("status") != "active" || q.Get("per_page") != "50" {
				t.Errorf("zone query: %v", q)
			}
			fmt.Fprint(w, `{"success":true,"result":[],"result_info":{"total_count":0}}`)
		default:
			if q.Get("per_page") != "1" {
				t.Errorf("count query: %v", q)
			}
			fmt.Fprint(w, `{"success":true,"result":[],"result_info":{"total_count":123456}}`)
		}
	})
	if _, err := c.PublicationZones(t.Context(), "account"); err != nil {
		t.Fatal(err)
	}
	count, err := c.PublicationRecordCount(t.Context(), "zone")
	if err != nil || count != 123456 || calls != 2 {
		t.Fatalf("count=%d error=%v calls=%d", count, err, calls)
	}
	// Query-bearing pagination keeps the original filter on subsequent pages.
	calls = 0
	c = testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("name") != "device.mesh.example.com" {
			t.Error("lost exact name filter")
		}
		fmt.Fprintf(w, `{"success":true,"result":[{"id":%q}],"result_info":{"total_pages":2}}`, r.URL.Query().Get("page"))
	})
	records, err := c.PublicationRecordsByName(t.Context(), "zone", "device.mesh.example.com")
	if err != nil || len(records) != 2 || calls != 2 {
		t.Fatalf("records=%v error=%v calls=%d", records, err, calls)
	}
}

func testOwnerPolicy() EnrollmentPolicy {
	return EnrollmentPolicy{Decision: "allow", Include: []AccessRule{{"email": json.RawMessage(`{"email":"owner@example.com"}`)}}}
}

func TestPublicationPreSendFailuresDoNotReconcile(t *testing.T) {
	for _, failure := range []string{"dns", "dial-refused", "dial-timeout", "already-canceled"} {
		t.Run(failure, func(t *testing.T) {
			gets := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					gets++
				}
				fmt.Fprint(w, `{"success":true,"result":[]}`)
			}))
			defer server.Close()
			client := New(StaticToken("test-token"), "test")
			client.BaseURL = server.URL
			transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
				switch failure {
				case "dns":
					return nil, &net.DNSError{Name: "api.cloudflare.test", Err: "no such host", IsNotFound: true}
				case "dial-timeout":
					return nil, &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}
				default:
					return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
				}
			}}
			defer transport.CloseIdleConnections()
			client.HTTPClient = &http.Client{Transport: publicationTransport(func(r *http.Request) (*http.Response, error) {
				if r.Method == "GET" {
					gets++
				}
				return transport.RoundTrip(r)
			})}
			ctx := t.Context()
			if failure == "already-canceled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			record, err := client.CreatePublicationRecord(ctx, "zone", DNSRecord{Name: "device.mesh.example.com", Type: "A", Content: "100.96.0.7", Comment: "managed-by: meshscale meshscale-create:0123456789abcdef0123456789abcdef"})
			if err == nil || unknownOutcome(err) || record.ID != "" || gets != 0 {
				t.Fatalf("certain failure reconciled: record=%+v error=%v GETs=%d", record, err, gets)
			}
		})
	}
}
