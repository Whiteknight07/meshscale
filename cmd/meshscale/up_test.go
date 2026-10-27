package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/warpcli"
)

func TestUpEnrollmentDecisions(t *testing.T) {
	for _, tc := range []struct {
		name, registration     string
		existing               bool
		wantCreate, wantEnroll bool
		cached                 bool
		unsafe                 bool
		wantErr                string
	}{
		{name: "fresh", wantCreate: true, wantEnroll: true},
		{name: "reuse node", existing: true, wantEnroll: true},
		{name: "already enrolled", existing: true, registration: "Connector ID: node"},
		{name: "real registration", existing: true, registration: "Account type: Team\nID: reg\nDevice ID: reg"},
		{name: "remembered offline", existing: true, registration: "Account type: Team\nID: reg\nDevice ID: reg", cached: true},
		{name: "other node", existing: true, registration: "Connector ID: another", wantErr: "different WARP registration"},
		{name: "user registration", registration: "Registration ID: user", wantErr: "different WARP registration"},
		{name: "renamed", registration: "Connector ID: node", wantErr: "use that node's hostname"},
		{name: "consumer", existing: true, registration: "Account type: Free\nID: reg", wantErr: "registration must be Team"},
		{name: "unsafe profile", existing: true, registration: "Connector ID: node", unsafe: true, wantErr: "Exclude mode"},
		{name: "daemon failure", registration: "daemon failure", wantErr: "is warp-svc running"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			created, enrolled, tokens := false, false, 0
			connected := false
			client := commandAPI(t, func(w http.ResponseWriter, r *http.Request) {
				var result any
				switch r.Method + " " + r.URL.Path {
				case "GET /accounts/acc/access/organizations":
					result = cfapi.Organization{AuthDomain: "team.cloudflareaccess.com"}
				case "GET /accounts/acc/warp_connector":
					nodes := []cfapi.MeshNode{}
					if tc.existing {
						nodes = append(nodes, cfapi.MeshNode{ID: "node", Name: "meshscale-test"})
					}
					result = nodes
				case "POST /accounts/acc/warp_connector":
					created = true
					var params cfapi.CreateMeshNodeParams
					json.NewDecoder(r.Body).Decode(&params)
					if params.Name != "meshscale-test" {
						t.Errorf("wrong hostname: %q", params.Name)
					}
					result = cfapi.MeshNode{ID: "node", Name: params.Name}
				case "GET /accounts/acc/warp_connector/node/connections":
					result = []cfapi.MeshConnector{{ID: "reg"}}
					if tc.cached {
						result = []cfapi.MeshConnector{}
					}
				case "GET /accounts/acc/warp_connector/node/token":
					tokens++
					result = "secret-connector-token"
				case "GET /accounts/acc/devices/registrations":
					result = []cfapi.Registration{{ID: "reg", Device: cfapi.RegistrationDevice{ID: "reg"}, VirtualIPv4: "100.96.1.2"}}
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL)
					http.Error(w, "unexpected", 500)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
			})
			var calls [][]string
			local := warpcli.New("")
			local.Exec = func(ctx context.Context, path string, args ...string) ([]byte, error) {
				calls = append(calls, slices.Clone(args))
				if len(args) < 2 || args[0] != "--accept-tos" {
					t.Fatalf("missing accept-tos: %v", args)
				}
				switch strings.Join(args[1:], " ") {
				case "registration show":
					if enrolled {
						return []byte("Account type: Team\nOrganization: team\nConnector ID: node\nRegistration ID: reg"), nil
					}
					if tc.registration == "" {
						return []byte("Error: Registration Missing"), errors.New("exit status 1")
					}
					if tc.registration == "daemon failure" {
						return []byte("Unable to connect to daemon"), errors.New("exit status 1")
					}
					if strings.Contains(tc.registration, "Account type:") {
						return []byte(tc.registration + "\nOrganization: team"), nil
					}
					return []byte(tc.registration + "\nAccount type: Team\nOrganization: team\nRegistration ID: reg"), nil
				case "connector new secret-connector-token":
					enrolled = true
					return []byte("Success"), nil
				case "settings":
					if tc.unsafe {
						return []byte("(network policy)\tMode: Warp\n(network policy)\tExclude mode, with hosts/ips:"), nil
					}
					return []byte("(network policy)\tMode: Warp\n(network policy)\tInclude mode, with hosts/ips:\n  100.96.0.0/12"), nil
				case "connect":
					connected = true
					return []byte("Success"), nil
				case "status":
					return []byte("Status update: Connected"), nil
				default:
					return nil, fmt.Errorf("unexpected args: %v", args)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			var out bytes.Buffer
			state := &config.MeshState{}
			if tc.cached {
				state.Remember("acc", "node", "reg")
			}
			err := bringUp(ctx, &out, client, "acc", local, "meshscale-test", time.Millisecond, state)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("got %v want %s", err, tc.wantErr)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(out.String(), "Connected. Mesh IP: 100.96.1.2") {
					t.Fatalf("output: %s", out.String())
				}
			}
			if tc.wantErr != "" && connected {
				t.Fatal("connect was called after a failed enrollment or safety check")
			}
			if created != tc.wantCreate || enrolled != tc.wantEnroll || (tokens > 0) != tc.wantEnroll {
				t.Fatalf("created %v enrolled %v tokens %d, calls %v", created, enrolled, tokens, calls)
			}
		})
	}
}

func TestUpCancellation(t *testing.T) {
	client := commandAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/access/organizations") {
			fmt.Fprint(w, `{"success":true,"result":{"auth_domain":"team.cloudflareaccess.com"}}`)
			return
		}
		fmt.Fprint(w, `{"success":true,"result":[{"id":"node","name":"meshscale-test"}]}`)
	})
	local := warpcli.New("")
	local.Exec = func(ctx context.Context, path string, args ...string) ([]byte, error) {
		switch args[1] {
		case "registration":
			return []byte("Account type: Team\nOrganization: team\nConnector ID: node"), nil
		case "settings":
			return []byte("(network policy)\tMode: Warp\n(network policy)\tInclude mode, with hosts/ips:\n  100.96.0.0/12"), nil
		case "connect":
			return nil, nil
		default:
			return []byte("Status update: Connecting"), nil
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := bringUp(ctx, &bytes.Buffer{}, client, "acc", local, "meshscale-test", time.Millisecond, &config.MeshState{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

func TestInvalidUpPreservesDisconnectIntent(t *testing.T) {
	for _, args := range [][]string{{"--backend", "unknown"}, {"--socks", "127.0.0.1:1080"}, {"--service-token-file", "/unused"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			saved := &config.BackendSettings{Backend: "warp", Paused: true}
			if err := saved.Save(); err != nil {
				t.Fatal(err)
			}
			if err := runUp(t.Context(), args); err == nil {
				t.Fatal("invalid up unexpectedly succeeded")
			}
			if !config.Paused() {
				t.Fatal("rejected up resumed automatic reconnect")
			}
		})
	}
}
