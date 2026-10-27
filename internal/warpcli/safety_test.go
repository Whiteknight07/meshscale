package warpcli

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func macFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/mac-" + name + ".txt")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestCapturedMacSafety(t *testing.T) {
	registration := macFixture(t, "registration")
	settings := macFixture(t, "settings")
	info, err := ParseRegistration(registration)
	if err != nil {
		t.Fatal(err)
	}
	if info.DeviceID != "01a00000-0000-1000-8000-000000000001" || info.AccountType != "Team" || info.Organization != "example-team" {
		t.Fatalf("bad registration: %#v", info)
	}
	if status, err := ParseStatus(macFixture(t, "status")); err != nil || !status.Connected {
		t.Fatalf("%#v %v", status, err)
	}
	for _, tc := range []struct {
		name, registration, settings, team string
		safe                               bool
	}{
		{"team Mac", registration, settings, "example-team", true},
		{"consumer", strings.Replace(registration, "Team", "Free", 1), settings, "example-team", false},
		{"wrong org", registration, settings, "other", false},
		{"no expected org", registration, settings, "", false},
		{"exclude", registration, strings.Replace(settings, "Include mode", "Exclude mode", 1), "example-team", false},
		{"no mesh", registration, strings.ReplaceAll(settings, "100.96.0.0/12", "100.97.0.0/16"), "example-team", false},
		{"default v4", registration, strings.Replace(settings, "100.96.0.0/12", "100.96.0.0/12\n  0.0.0.0/0", 1), "example-team", false},
		{"default v6", registration, strings.Replace(settings, "100.96.0.0/12", "100.96.0.0/12\n  ::/0", 1), "example-team", false},
		{"paired halves", registration, strings.Replace(settings, "100.96.0.0/12", "100.96.0.0/12\n  0.0.0.0/1\n  128.0.0.0/1", 1), "example-team", false},
		{"tailscale", registration, strings.Replace(settings, "100.96.0.0/12", "100.96.0.0/12\n  100.64.0.0/10", 1), "example-team", false},
		{"wildcard", registration, strings.Replace(settings, "github.com", "*", 1), "example-team", false},
		{"default profile", registration, strings.Replace(settings, "(network policy)\tInclude", "(default)\tInclude", 1), "example-team", false},
		{"unknown format", registration, "Include mode: 100.96.0.0/12", "example-team", false},
		{"dns only", registration, strings.Replace(settings, "WarpWithDnsOverHttps", "DnsOverHttps", 1), "example-team", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info, _ := ParseRegistration(tc.registration)
			if got := ValidateSafety(info, tc.settings, tc.team); (got == nil) != tc.safe {
				t.Fatalf("guard: %v", got)
			}
			connected := false
			client := New("warp-cli")
			client.Network = nil // Keep fake-client tests independent of host networking.
			client.RequireSafeProfile = true
			client.Organization = tc.team
			client.Exec = func(_ context.Context, _ string, args ...string) ([]byte, error) {
				switch args[1] {
				case "registration":
					return []byte(tc.registration), nil
				case "settings":
					return []byte(tc.settings), nil
				case "connect":
					connected = true
					return nil, nil
				}
				t.Fatalf("unexpected command: %v", args)
				return nil, nil
			}
			if err := client.Connect(context.Background()); (err == nil) != tc.safe || connected != tc.safe {
				t.Fatalf("connect=%v err=%v", connected, err)
			}
		})
	}
}

func TestMacEnrollmentStates(t *testing.T) {
	reg := macFixture(t, "registration")
	settings := macFixture(t, "settings")
	for _, name := range []string{"registered", "unregistered", "pending", "consumer", "replace consumer", "different org", "unknown registration", "unsafe", "changed before connect", "changed after connect", "cancel after connect"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			registered := name != "unregistered" && name != "pending"
			consumer := name == "consumer" || name == "replace consumer"
			var calls, states []string
			prepared, began, connects := 0, 0, 0
			settingsReads := 0
			client := New("warp-cli")
			client.Network = nil // Keep fake-client tests independent of host networking.
			client.Exec = func(_ context.Context, _ string, args ...string) ([]byte, error) {
				call := strings.Join(args[1:], " ")
				calls = append(calls, call)
				switch call {
				case "registration show":
					if name == "unknown registration" {
						return nil, errors.New("daemon unavailable")
					}
					if !registered {
						return []byte("Registration Missing"), errors.New("unregistered")
					}
					output := reg
					if consumer {
						output = strings.Replace(output, "Team", "Free", 1)
					}
					if name == "different org" {
						output = strings.Replace(output, "Organization: example-team", "Organization: another", 1)
					}
					return []byte(output), nil
				case "settings":
					settingsReads++
					if name == "unsafe" || name == "changed before connect" && settingsReads >= 2 || name == "changed after connect" && settingsReads >= 3 {
						return []byte(strings.Replace(settings, "Include mode", "Exclude mode", 1)), nil
					}
					return []byte(settings), nil
				case "registration delete":
					registered = false
					consumer = false
				case "connect":
					connects++
				case "status":
					if name == "cancel after connect" {
						cancel()
						return nil, context.Canceled
					}
					return []byte("Status update: Connected"), nil
				case "disconnect":
				default:
					t.Fatalf("unexpected %s", call)
				}
				return nil, nil
			}
			if name == "pending" {
				registered = false
			}
			err := client.EnrollMac(ctx, EnrollmentOptions{Team: "example-team", ReplaceConsumer: name == "replace consumer", Pending: name == "pending" || name == "replace consumer", Poll: time.Millisecond,
				Prepare: func(context.Context) error { prepared++; return nil },
				Begin:   func(context.Context) error { began++; registered = true; return nil },
				Notify: func(p Progress) {
					states = append(states, p.State)
					if name == "pending" && p.State == "registration_pending" {
						registered = true
					}
				},
			})
			wantSuccess := name == "registered" || name == "unregistered" || name == "pending" || name == "replace consumer"
			if (err == nil) != wantSuccess {
				t.Fatalf("%v calls %v", err, calls)
			}
			if !wantSuccess && name != "cancel after connect" && name != "changed after connect" && connects != 0 {
				t.Fatalf("unsafe connect: %v", calls)
			}
			if wantSuccess && connects != 1 {
				t.Fatalf("connects %d", connects)
			}
			if name == "unregistered" || name == "replace consumer" {
				if prepared != 1 || began != 1 {
					t.Fatalf("prepare %d begin %d", prepared, began)
				}
			}
			if name == "pending" && began != 0 {
				t.Fatal("restarted browser enrollment")
			}
			if name == "registered" && !reflect.DeepEqual(states, []string{"checking_safety", "connecting", "connected"}) {
				t.Fatal(states)
			}
			if name == "consumer" || name == "different org" || name == "unknown registration" {
				if len(calls) != 1 {
					t.Fatalf("mutated blocked registration: %v", calls)
				}
			}
			if (name == "cancel after connect" || name == "changed after connect" || name == "changed before connect") && calls[len(calls)-1] != "disconnect" {
				t.Fatalf("connection was not cleaned up: %v", calls)
			}
		})
	}
}
