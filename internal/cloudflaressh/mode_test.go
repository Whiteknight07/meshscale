package cloudflaressh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"golang.org/x/crypto/ssh"
)

type fakeCA struct {
	ca               cfapi.SSHCA
	err, errorCreate error
	creates          int
}

func (f *fakeCA) SSHCA(context.Context, string) (cfapi.SSHCA, error) { return f.ca, f.err }
func (f *fakeCA) CreateSSHCA(context.Context, string) (cfapi.SSHCA, error) {
	f.creates++
	return f.ca, f.errorCreate
}
func TestEnsureCA(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewPublicKey(public)
	ca := cfapi.SSHCA{ID: "singleton", PublicKey: string(ssh.MarshalAuthorizedKey(key))}
	denied := errors.New("permission denied")
	for _, tc := range []struct {
		name         string
		read, create error
		bad          bool
		wantCreates  int
		wantError    bool
	}{{"existing", nil, nil, false, 0, false}, {"absent", &cfapi.APIError{StatusCode: 404}, nil, false, 1, false}, {"denied", denied, nil, false, 0, true}, {"bad endpoint", &cfapi.APIError{StatusCode: 404, Errors: []cfapi.APIMessage{{Code: 7003}}}, nil, false, 0, true}, {"create denied", &cfapi.APIError{StatusCode: 404}, denied, false, 1, true}, {"malformed", nil, nil, true, 0, true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeCA{ca: ca, err: tc.read, errorCreate: tc.create}
			if tc.bad {
				f.ca.PublicKey = "invalid"
			}
			got, created, err := EnsureCA(context.Background(), f, "account")
			if (err != nil) != tc.wantError || f.creates != tc.wantCreates {
				t.Fatalf("ca=%v created=%v err=%v calls=%d", got, created, err, f.creates)
			}
			if tc.read == denied && !errors.Is(err, denied) {
				t.Fatal("lost wrapped error")
			}
		})
	}
}

type fakeWorld struct {
	assignedNetwork string
	events          []string
	fail            string
	states          []State
	target          cfapi.InfrastructureTarget
	app             cfapi.InfrastructureApplication
}

func (f *fakeWorld) event(e string) error {
	f.events = append(f.events, e)
	if e == f.fail {
		return fmt.Errorf("injected %s", e)
	}
	return nil
}
func (f *fakeWorld) Save(s State) error { f.states = append(f.states, s); return f.event("save") }
func (f *fakeWorld) PutInfrastructureTarget(_ context.Context, _ string, t cfapi.InfrastructureTarget) (cfapi.InfrastructureTarget, error) {
	t.ID = "target"
	if t.IP.IPv4 != nil && f.assignedNetwork != "" {
		t.IP.IPv4 = &cfapi.TargetIP{Address: t.IP.IPv4.Address, VirtualNetworkID: f.assignedNetwork}
	}
	f.target = t
	return t, f.event("target")
}
func (f *fakeWorld) DeleteInfrastructureTarget(_ context.Context, _ string, id string) error {
	if id != "target" {
		panic("unowned target")
	}
	return f.event("delete target")
}
func (f *fakeWorld) PutInfrastructureApplication(_ context.Context, _ string, a cfapi.InfrastructureApplication) (cfapi.InfrastructureApplication, error) {
	a.ID = "app"
	a.Policies[0].ID = "policy"
	f.app = a
	return a, f.event("app")
}
func (f *fakeWorld) DeleteInfrastructureApplication(_ context.Context, _ string, id string) error {
	if id != "app" {
		panic("unowned app")
	}
	return f.event("delete app")
}
func (f *fakeWorld) Enable(context.Context, *State, string) error { return f.event("enable host") }
func (f *fakeWorld) Disable(_ context.Context, _ *State, mode string) error {
	return f.event("host " + mode)
}
func testState() State {
	return State{Account: "account", IP: "100.96.0.2", Name: "meshscale-test-server", Owner: "owner@example.com", Users: []string{"alice"}}
}
func TestLifecycle(t *testing.T) {
	for _, fail := range []string{"", "target", "app", "enable host"} {
		t.Run(fail, func(t *testing.T) {
			f := &fakeWorld{fail: fail}
			m := Manager{Resources: f, Store: f, Host: f}
			s := testState()
			err := m.Enable(context.Background(), &s, cfapi.SSHCA{ID: "retained", PublicKey: "public key"})
			if (err != nil) != (fail != "") {
				t.Fatalf("%v", err)
			}
			if fail == "app" && s.TargetID != "target" {
				t.Fatal("target ownership lost")
			}
			if fail == "enable host" && (s.AppID != "app" || s.PolicyIDs[0] != "policy") {
				t.Fatal("application ownership lost")
			}
			if fail != "" {
				return
			}
			if s.Mode != "cloudflare" {
				t.Fatal(s)
			}
			if got := f.app.Policies[0]; got.Decision != "allow" || !reflect.DeepEqual(got.Include, []map[string]any{{"email": map[string]string{"email": "owner@example.com"}}}) || !reflect.DeepEqual(got.ConnectionRules.SSH.Usernames, []string{"alice"}) {
				t.Fatalf("unsafe policy: %+v", got)
			}
			if f.app.TargetCriteria[0].Port != 22 || f.app.TargetCriteria[0].Protocol != "SSH" {
				t.Fatal("wrong interception")
			}
			f.events = nil
			if err = m.Disable(context.Background(), &s, "own"); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(f.events, []string{"delete app", "save", "delete target", "save", "host own", "save"}) {
				t.Fatal(f.events)
			}
			if s.CAID != "retained" || s.AppID != "" || s.TargetID != "" {
				t.Fatal(s)
			}
			f.events = nil
			if err = m.Disable(context.Background(), &s, "off"); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(strings.Join(f.events, ","), "delete") {
				t.Fatal("deleted untracked resources")
			}
		})
	}
}
func TestDeletionFailurePreservesCertificateOnlyHost(t *testing.T) {
	for _, fail := range []string{"delete app", "delete target"} {
		t.Run(fail, func(t *testing.T) {
			f := &fakeWorld{fail: fail}
			s := testState()
			manager := Manager{Resources: f, Store: f, Host: f}
			if err := manager.Enable(t.Context(), &s, cfapi.SSHCA{ID: "ca", PublicKey: "key"}); err != nil {
				t.Fatal(err)
			}
			f.events = nil
			err := manager.Disable(context.Background(), &s, "own")
			if err == nil {
				t.Fatal("expected failure")
			}
			for _, e := range f.events {
				if e == "host own" {
					t.Fatal("origin exposed before deleting interception")
				}
			}
		})
	}
}
func TestValidateExplicitMapping(t *testing.T) {
	for _, tc := range []struct {
		users     []string
		owner, ip string
		valid     bool
	}{{[]string{"alice"}, "owner@example.com", "100.96.0.2", true}, {[]string{"root"}, "owner@example.com", "100.96.0.2", true}, {[]string{"*"}, "owner@example.com", "100.96.0.2", false}, {[]string{"alice\nMatch all"}, "owner@example.com", "100.96.0.2", false}, {nil, "owner@example.com", "100.96.0.2", false}, {[]string{"alice"}, "bad\nemail", "100.96.0.2", false}, {[]string{"alice"}, "owner@example.com", "invalid", false}} {
		s := testState()
		s.Users, s.Owner, s.IP = tc.users, tc.owner, tc.ip
		if err := Validate(s); (err == nil) != tc.valid {
			t.Errorf("%+v: %v", tc, err)
		}
	}
}

func TestSSHMutationRechecksRemoteOwnership(t *testing.T) {
	for _, operation := range []string{"enable", "disable"} {
		for _, change := range []string{"target-name", "target-ip", "app-name", "app-policy", "app-type", "legacy"} {
			t.Run(operation+"/"+change, func(t *testing.T) {
				f := &fakeWorld{}
				m := Manager{Resources: f, Store: f, Host: f}
				s := testState()
				if err := m.Enable(t.Context(), &s, cfapi.SSHCA{ID: "ca", PublicKey: "key"}); err != nil {
					t.Fatal(err)
				}
				switch change {
				case "target-name":
					f.target.Hostname = "foreign"
				case "target-ip":
					f.target.IP.IPv4 = &cfapi.TargetIP{Address: "100.96.0.99"}
				case "app-name":
					f.app.Name = "foreign"
				case "app-type":
					f.app.Type = "self_hosted"
				case "app-policy":
					f.app.Policies[0].Include = []map[string]any{{"everyone": map[string]any{}}}
				case "legacy":
					s.Nonce = ""
				}
				f.events = nil
				var err error
				if operation == "enable" {
					err = m.Enable(t.Context(), &s, cfapi.SSHCA{ID: "ca", PublicKey: "key"})
				} else {
					err = m.Disable(t.Context(), &s, "own")
				}
				if err == nil {
					t.Fatal("accepted changed or unproven SSH resource ownership")
				}
				for _, event := range f.events {
					if event != "save" {
						t.Fatalf("mutation before ownership verification: %s", event)
					}
				}
			})
		}
	}
}

func (f *fakeWorld) InfrastructureTarget(context.Context, string, string) (cfapi.InfrastructureTarget, error) {
	return f.target, nil
}
func (f *fakeWorld) InfrastructureApplication(context.Context, string, string) (cfapi.InfrastructureApplication, error) {
	return f.app, nil
}
func (f *fakeWorld) ListInfrastructureTargets(context.Context, string) ([]cfapi.InfrastructureTarget, error) {
	if f.target.ID == "" {
		return nil, nil
	}
	return []cfapi.InfrastructureTarget{f.target}, nil
}
func (f *fakeWorld) ListInfrastructureApplications(context.Context, string) ([]cfapi.InfrastructureApplication, error) {
	if f.app.ID == "" {
		return nil, nil
	}
	return []cfapi.InfrastructureApplication{f.app}, nil
}

func TestInterruptedSSHCreateRecoversExactNonce(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(fmt.Sprint(foreign), func(t *testing.T) {
			f := &fakeWorld{}
			m := Manager{Resources: f, Store: f, Host: f}
			s := testState()
			if err := m.Enable(t.Context(), &s, cfapi.SSHCA{ID: "ca", PublicKey: "key"}); err != nil {
				t.Fatal(err)
			}
			// A crash left the pre-POST journal but neither returned ID.
			s.AppID = ""
			s.TargetID = ""
			s.PolicyIDs = nil
			if foreign {
				f.app.Name = "same-server-unrelated"
				f.target.Hostname = s.Name
			}
			f.events = nil
			if err := m.Disable(t.Context(), &s, "own"); err != nil {
				t.Fatal(err)
			}
			var deletions int
			for _, event := range f.events {
				if strings.HasPrefix(event, "delete ") {
					deletions++
				}
			}
			if foreign && deletions != 0 || !foreign && deletions != 2 {
				t.Fatalf("unsafe recovery events: %v", f.events)
			}
		})
	}
}
func TestSSHRejectsMalformedSavedStateWithoutPanic(t *testing.T) {
	f := &fakeWorld{}
	s := testState()
	s.Nonce = "0123456789abcdef0123456789abcdef"
	s.IP = "not-an-ip"
	if err := (Manager{Resources: f, Store: f, Host: f}).Disable(t.Context(), &s, "own"); err == nil {
		t.Fatal("accepted malformed state")
	}
}

func TestPinsAssignedDefaultVirtualNetwork(t *testing.T) {
	f := &fakeWorld{assignedNetwork: "default-network"}
	m := Manager{Resources: f, Store: f, Host: f}
	s := testState()
	if err := m.Enable(t.Context(), &s, cfapi.SSHCA{ID: "ca", PublicKey: "key"}); err != nil {
		t.Fatal(err)
	}
	if s.TargetVirtualNetwork != "default-network" {
		t.Fatal("did not pin API-assigned network")
	}
	if err := m.Enable(t.Context(), &s, cfapi.SSHCA{ID: "ca", PublicKey: "key"}); err != nil {
		t.Fatal(err)
	}
	f.target.IP.IPv4 = &cfapi.TargetIP{Address: s.IP, VirtualNetworkID: "different-network"}
	f.events = nil
	if err := m.Disable(t.Context(), &s, "own"); err == nil {
		t.Fatal("accepted changed virtual network")
	}
	if len(f.events) != 0 {
		t.Fatal("mutated before checking pinned network", f.events)
	}
}
