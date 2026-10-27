package warpcli

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/backend"
)

func addFixtureSeeds(f *testing.F, names ...string) {
	f.Helper()
	for _, name := range names {
		data, err := os.ReadFile("testdata/mac-" + name + ".txt")
		if err != nil {
			f.Fatal(err)
		}
		f.Add(string(data))
	}
}

func FuzzParseStatus(f *testing.F) {
	addFixtureSeeds(f, "status")
	for _, seed := range []string{"Status update: Connected", "Status update: Disconnected. Reason: Manual", "status:", ".", "Unable. Reason: x:y", "Reason: a\nConnecting"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, output string) {
		status, err := ParseStatus(output)
		if err != nil {
			return
		}
		switch status.State {
		case "connected", "disconnected", "connecting", "disconnecting", "unable", "disabled":
		default:
			t.Fatalf("unknown state %q", status.State)
		}
		if strings.ContainsAny(status.Reason, "\r\n") {
			t.Fatalf("reason spans lines: %q", status.Reason)
		}
		if status.Connected != (status.State == "connected") {
			t.Fatalf("connected=%v for state %q", status.Connected, status.State)
		}
	})
}

func FuzzParseRegistration(f *testing.F) {
	addFixtureSeeds(f, "registration")
	f.Add("ID: x\nDevice ID:\nAccount type: Team")
	f.Fuzz(func(t *testing.T, output string) {
		info, err := ParseRegistration(output)
		if err != nil {
			return
		}
		if info.ID == "" && info.DeviceID == "" && info.RegistrationID == "" && info.ConnectorID == "" {
			t.Fatal("accepted registration without an ID")
		}
		for _, value := range []string{info.ID, info.DeviceID, info.RegistrationID, info.ConnectorID, info.AccountType, info.Organization} {
			if strings.ContainsAny(value, "\r\n") || value != strings.TrimSpace(value) {
				t.Fatalf("field not trimmed to one line: %q", value)
			}
		}
	})
}

// FuzzValidateSettings checks that no input makes a default route acceptable:
// once a wide prefix sits in the Include entries the profile must be refused.
func FuzzValidateSettings(f *testing.F) {
	addFixtureSeeds(f, "settings")
	f.Add("(network policy)\tMode: Warp\n(network policy)\tInclude mode, with hosts/ips:\n  100.96.0.0/12\n")
	f.Fuzz(func(t *testing.T, settings string) {
		err := ValidateSettings(settings, "example-team")
		if err != nil {
			return
		}
		if strings.Contains(strings.ToLower(settings), "exclude mode") {
			t.Fatal("accepted an Exclude profile")
		}
		const header = "(network policy)\tInclude mode, with hosts/ips:"
		for _, wide := range []string{"0.0.0.0/1", "::/0", "100.64.0.0/10"} {
			lines := strings.Split(settings, "\n")
			for i, line := range lines {
				if strings.TrimSpace(line) != header {
					continue
				}
				widened := strings.Join(append(lines[:i+1:i+1], append([]string{"  " + wide}, lines[i+1:]...)...), "\n")
				if ValidateSettings(widened, "example-team") == nil {
					t.Fatalf("accepted %s in the Include entries:\n%s", wide, widened)
				}
			}
		}
	})
}

// FuzzWatchStatus feeds arbitrary listener output through the stream reader.
func FuzzWatchStatus(f *testing.F) {
	f.Add("Status update: Connected\nDNS log\nStatus update: Disconnected. Reason: x\n")
	f.Add(strings.Repeat("x", 70<<10))
	f.Fuzz(func(t *testing.T, stream string) {
		updates := make(chan backend.Status, 1)
		client := &Client{Path: "warp-cli", Stream: func(context.Context, string, ...string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(stream)), nil
		}}
		done := make(chan error, 1)
		go func() { done <- client.WatchStatus(context.Background(), updates) }()
		for {
			select {
			case status := <-updates:
				if status.State == "" {
					t.Fatal("empty status delivered")
				}
			case err := <-done:
				if err == nil {
					t.Fatal("listener returned nil after the stream closed")
				}
				return
			}
		}
	})
}
