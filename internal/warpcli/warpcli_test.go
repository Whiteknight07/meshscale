package warpcli

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/backend"
)

func TestParseStatus(t *testing.T) {
	for _, tc := range []struct {
		name, output, state, reason string
		connected                   bool
	}{
		{"connected", "Status update: Connected\n", "connected", "", true},
		{"disconnected", "Status update: Disconnected\nReason: Manual Disconnection\n", "disconnected", "Manual Disconnection", false},
		{"inline reason", "Status update: Disconnected. Reason: Registration Missing\n", "disconnected", "Registration Missing", false},
		{"connecting", "Status update: Connecting\n", "connecting", "", false},
		{"last update wins", "Status update: Connecting\nStatus update: Connected\n", "connected", "", true},
		{"reason cleared on reconnect", "Status update: Disconnected\nReason: Manual Disconnection\nStatus update: Connected\n", "connected", "", true},
		{"CRLF", "\r\nStatus update: Disconnected\r\nReason: Network unavailable\r\n", "disconnected", "Network unavailable", false},
		{"plain status", "Disconnected. Reason: Connectivity check failed. Retry later.\n", "disconnected", "Connectivity check failed. Retry later.", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseStatus(tc.output)
			if err != nil || got.State != tc.state || got.Connected != tc.connected || got.Reason != tc.reason {
				t.Fatalf("got %#v, %v", got, err)
			}
		})
	}
	if _, err := ParseStatus("Unable to connect to WARP daemon"); err == nil {
		t.Fatal("unknown status must fail")
	}
}

func TestWatchStatusReadsStreamUsingFake(t *testing.T) {
	updates := make(chan backend.Status, 2)
	client := &Client{Path: "/fake/warp-cli", Stream: func(_ context.Context, path string, args ...string) (io.ReadCloser, error) {
		if path != "/fake/warp-cli" || !reflect.DeepEqual(args, []string{"--accept-tos", "--listen", "status"}) {
			t.Fatalf("stream command %q %v", path, args)
		}
		return io.NopCloser(strings.NewReader("Status update: Connected\nNetwork: healthy\nStatus update: Disconnected\n")), nil
	}}
	err := client.WatchStatus(t.Context(), updates)
	if err == nil || err.Error() != "warp-cli status listener closed" {
		t.Fatalf("stream error=%v", err)
	}
	first, second := <-updates, <-updates
	if first.State != "connected" || !first.Connected || second.State != "disconnected" || second.Connected {
		t.Fatalf("statuses: %+v then %+v", first, second)
	}
}

func TestParseRegistration(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		want         RegistrationInfo
	}{
		{"legacy", "Registration information:\nID: 72abc-123\nAccount type: Team\nOrganization: example\n", RegistrationInfo{ID: "72abc-123", AccountType: "Team", Organization: "example"}},
		{"explicit", "Registration ID: reg-123\nDevice ID: dev-123\nOrganization: example\n", RegistrationInfo{RegistrationID: "reg-123", DeviceID: "dev-123", Organization: "example"}},
		{"connector", "Tunnel ID: node-123\n", RegistrationInfo{ConnectorID: "node-123"}},
		{"underscores", "device_id: dev-123\r\nregistration_id: reg-123\r\n", RegistrationInfo{DeviceID: "dev-123", RegistrationID: "reg-123"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRegistration(tc.output)
			if err != nil || got != tc.want {
				t.Fatalf("got %#v, %v; want %#v", got, err, tc.want)
			}
		})
	}
	for _, output := range []string{"", "No registration found", "Account ID: unrelated-account-id\n", "ID: \n"} {
		if _, err := ParseRegistration(output); err == nil {
			t.Errorf("expected failure for %q", output)
		}
	}
}

func TestInvocations(t *testing.T) {
	ctx := context.Background()
	var invocations [][]string
	c := New("/custom/warp-cli")
	c.Network = nil // Keep fake-client tests independent of host networking.
	c.Exec = func(gotCtx context.Context, path string, args ...string) ([]byte, error) {
		if gotCtx != ctx || path != "/custom/warp-cli" {
			t.Errorf("wrong context or path: %s", path)
		}
		invocations = append(invocations, args)
		switch args[1] {
		case "status":
			return []byte("Status update: Connected"), nil
		case "registration":
			return []byte("Device ID: dev-123"), nil
		default:
			return []byte("Success"), nil
		}
	}
	if _, err := c.Status(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Registration(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.ConnectorNew(ctx, "node-token"); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"--accept-tos", "status"}, {"--accept-tos", "registration", "show"}, {"--accept-tos", "connect"}, {"--accept-tos", "disconnect"}, {"--accept-tos", "connector", "new", "node-token"}}
	if !reflect.DeepEqual(invocations, want) {
		t.Fatalf("got %#v", invocations)
	}
	if err := c.ConnectorNew(ctx, " "); err == nil || len(invocations) != len(want) {
		t.Fatal("empty token invoked command")
	}
}

func TestExecutionErrors(t *testing.T) {
	c := New("")
	c.Network = nil // Keep fake-client tests independent of host networking.
	c.Exec = func(ctx context.Context, path string, args ...string) ([]byte, error) {
		return []byte("invalid sensitive-token"), errors.New("rejected sensitive-token")
	}
	err := c.ConnectorNew(context.Background(), "sensitive-token")
	if err == nil || strings.Contains(err.Error(), "sensitive-token") || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("secret not redacted: %v", err)
	}
	for cause := errors.Unwrap(err); cause != nil; cause = errors.Unwrap(cause) {
		if strings.Contains(cause.Error(), "sensitive-token") {
			t.Fatalf("secret reachable through Unwrap: %v", cause)
		}
	}
	c.Exec = func(context.Context, string, ...string) ([]byte, error) { return nil, exec.ErrNotFound }
	if _, err := c.Status(context.Background()); !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("lost cause: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Connect(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestRealLinuxRegistration(t *testing.T) {
	info, err := ParseRegistration("Account type: Team\nID: 01a00000-0000-1000-8000-000000000002\nDevice ID: 01a00000-0000-1000-8000-000000000002\nPublic key: omitted\nAccount ID: account\nOrganization: example-team\n")
	if err != nil || info.DeviceID != "01a00000-0000-1000-8000-000000000002" || info.ID != info.DeviceID || info.ConnectorID != "" {
		t.Fatalf("got %#v %v", info, err)
	}
}

func TestRealLinuxUnableStatus(t *testing.T) {
	s, err := ParseStatus("Status update: Unable\nReason: Registration Missing due to: Daemon Startup\n")
	if err != nil || s.Connected || s.State != "unable" || s.Reason != "Registration Missing due to: Daemon Startup" {
		t.Fatalf("got %#v %v", s, err)
	}
}

type fakeNetwork struct {
	cleanups int
	err      error
}

func (n *fakeNetwork) Reconcile(context.Context) error { return n.err }
func (n *fakeNetwork) Cleanup(context.Context) error   { n.cleanups++; return n.err }

func TestDisconnectCleansNetwork(t *testing.T) {
	for _, failDisconnect := range []bool{false, true} {
		network := &fakeNetwork{err: errors.New("cleanup failure")}
		c := New("warp-cli")
		c.Network = network
		c.Exec = func(context.Context, string, ...string) ([]byte, error) {
			if failDisconnect {
				return nil, errors.New("disconnect failure")
			}
			return nil, nil
		}
		err := c.Disconnect(context.Background())
		if network.cleanups != 1 || !errors.Is(err, network.err) {
			t.Fatalf("cleanups=%d err=%v", network.cleanups, err)
		}
	}
}
