package secureroute

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestStatusReader(t *testing.T) {
	for _, tc := range []struct {
		route string
		err   error
		want  string
	}{
		{"congctl bbr", nil, "bbr (secure routes only)"},
		{"present", nil, "kernel default (per-route BBR unavailable)"},
		{"", nil, "route missing"},
		{"", errNoLink, "not applicable (no kernel secure link)"},
		{"", errors.New("netlink denied"), "unknown (secure route query unavailable)"},
	} {
		read := func(context.Context) (string, error) { return tc.route, tc.err }
		if got := status(context.Background(), read); got != tc.want {
			t.Fatalf("status(%q, %v) = %q; want %q", tc.route, tc.err, got, tc.want)
		}
	}
}

func TestInstall(t *testing.T) {
	sentinel := errors.New("route conflict")
	for _, tc := range []struct {
		name      string
		failures  []error
		wantCalls []string
		want      error
	}{
		{"BBR available", nil, []string{"tuned"}, nil},
		{"module retry succeeds", []error{sentinel, nil, nil}, []string{"tuned", "module", "tuned"}, nil},
		{"module unavailable", []error{sentinel, sentinel, nil}, []string{"tuned", "module", "plain"}, nil},
		{"retry unsupported", []error{sentinel, nil, sentinel, nil}, []string{"tuned", "module", "tuned", "plain"}, nil},
		{"route conflict preserved", []error{sentinel, sentinel, sentinel}, []string{"tuned", "module", "plain"}, sentinel},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"-6", "route", "add", "fd6d:6573:6873::/48", "dev", "meshsecure0"}
			original := append([]string(nil), args...)
			var calls []string
			err := Install(func(name string, a ...string) error {
				kind := "plain"
				switch name {
				case "modprobe":
					kind = "module"
					if !reflect.DeepEqual(a, []string{"tcp_bbr"}) {
						t.Fatal(a)
					}
				case "ip":
					if reflect.DeepEqual(a, append(append([]string(nil), args...), "congctl", "bbr")) {
						kind = "tuned"
					} else if !reflect.DeepEqual(a, args) {
						t.Fatal(a)
					}
				default:
					t.Fatal(name)
				}
				calls = append(calls, kind)
				if len(calls) <= len(tc.failures) {
					return tc.failures[len(calls)-1]
				}
				return nil
			}, args...)
			if !errors.Is(err, tc.want) || !reflect.DeepEqual(calls, tc.wantCalls) || !reflect.DeepEqual(args, original) {
				t.Fatalf("error %v calls %v args %v", err, calls, args)
			}
		})
	}
}
func TestStatusDescription(t *testing.T) {
	for _, tc := range []struct{ route, want string }{
		{"fd6d:6573:6873::/48 dev meshsecure0 congctl bbr", "bbr (secure routes only)"},
		{"fd6d:6573:6873::/48 dev meshsecure0", "kernel default (per-route BBR unavailable)"},
		{"", "route missing"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			if got := describe(tc.route); got != tc.want {
				t.Fatal(got)
			}
		})
	}
}
