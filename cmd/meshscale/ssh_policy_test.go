package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/Whiteknight07/meshscale/internal/cloudflaressh"
	"github.com/Whiteknight07/meshscale/internal/config"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/service"
	"github.com/Whiteknight07/meshscale/internal/sshserver"
)

func fakePolicyLocalUser(name string) (string, uint32, error) {
	switch name {
	case "root", "alias":
		return name, 0, nil
	case "alice":
		return name, 1000, nil
	case "bob":
		return name, 1001, nil
	default:
		return "", 0, fmt.Errorf("unknown or disabled login user")
	}
}

func TestSSHPolicyCLI(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		args       []string
		uid        int
		want       string
		success    bool
	}{
		{name: "missing show", args: []string{"show"}, want: "\"rules\": []", success: true},
		{name: "empty show", data: `{"rules":[]}`, args: []string{"show"}, want: "\"rules\": []", success: true},
		{name: "malformed show", data: `broken`, args: []string{"show"}},
		{name: "missing test", args: []string{"test", "alice@example.com", "alice"}, want: "no policy (denying all)"},
		{name: "empty test", data: `{"rules":[]}`, args: []string{"test", "alice@example.com", "alice"}, want: "no rule matched"},
		{name: "allow owner", data: `{"rules":[{"name":"owner","from":["alice@example.com"],"users":["autogroup:nonroot"]}]}`, args: []string{"test", "ALICE@example.com", "alice"}, want: `matched rule 1 ("owner")`, success: true},
		{name: "deny root", data: `{"rules":[{"from":["alice@example.com"],"users":["autogroup:nonroot"]}]}`, args: []string{"test", "alice@example.com", "root"}, want: "rule 1 matched the identity"},
		{name: "root explicit", data: `{"rules":[{"from":["alice@example.com"],"users":["root"]}]}`, args: []string{"test", "alice@example.com", "root"}, want: "ALLOW", success: true},
		{name: "uid zero alias", data: `{"rules":[{"from":["*"],"users":["alias","root","autogroup:nonroot"]}]}`, args: []string{"test", "alice@example.com", "alias"}, want: "UID 0"},
		{name: "other identity", data: `{"rules":[{"from":["alice@example.com"],"users":["alice"]}]}`, args: []string{"test", "mallory@example.com", "alice"}, want: "no rule matched"},
		{name: "unusable user", data: `{"rules":[{"from":["*"],"users":["autogroup:nonroot"]}]}`, args: []string{"test", "alice@example.com", "missing"}, want: "local user unavailable"},
		{name: "device source", data: `{"rules":[{"from":["device:dev-1"],"users":["alice"]}]}`, args: []string{"test", "alice@example.com", "alice", "--from", "device:dev-1"}, want: "matched rule 1", success: true},
		{name: "node source", data: `{"rules":[{"from":["build-box"],"users":["alice"]}]}`, args: []string{"test", "alice@example.com", "alice", "--from", "build-box"}, want: "ALLOW", success: true},
		{name: "mesh source", data: `{"rules":[{"from":["alice@example.com"],"users":["alice"]}]}`, args: []string{"test", "alice@example.com", "alice", "--from", "100.96.0.2"}, want: "source IP does not establish", success: true},
		{name: "public source", data: `{"rules":[]}`, args: []string{"test", "alice@example.com", "alice", "--from", "203.0.113.1"}},
		{name: "device identity", data: `{"rules":[{"from":["device:dev-1"],"users":["alice"]}]}`, args: []string{"test", "device:dev-1", "alice"}, want: "ALLOW", success: true},
		{name: "rootless self", uid: 1000, data: `{"rules":[{"from":["*"],"users":["autogroup:nonroot"]}]}`, args: []string{"test", "alice@example.com", "alice"}, want: "ALLOW", success: true},
		{name: "rootless other", uid: 1000, data: `{"rules":[{"from":["*"],"users":["autogroup:nonroot"]}]}`, args: []string{"test", "alice@example.com", "bob"}, want: "only serve its own"},
		{name: "init", args: []string{"init"}, want: "root denied", success: true},
		{name: "init root", args: []string{"init", "--allow-root"}, want: "root explicitly allowed", success: true},
		{name: "rootless init", uid: 1000, args: []string{"init"}, want: "this server's non-root local user only", success: true},
		{name: "rootless root init", uid: 1000, args: []string{"init", "--allow-root"}},
		{name: "init existing", data: `{"rules":[]}`, args: []string{"init"}},
		{name: "init force", data: `{"rules":[]}`, args: []string{"init", "--force"}, want: "Created SSH policy", success: true},
		{name: "bad operation", args: []string{"other"}},
		{name: "bad test arity", args: []string{"test", "alice@example.com"}},
		{name: "unknown flag", args: []string{"show", "--force"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ssh.json")
			if tc.data != "" {
				if err := os.WriteFile(path, []byte(tc.data), 0644); err != nil {
					t.Fatal(err)
				}
			}
			var out, diagnostics bytes.Buffer
			calls := 0
			c := sshPolicyCommand{path, &out, &diagnostics, func(context.Context) (string, error) { calls++; return "alice@example.com", nil }, fakePolicyLocalUser, tc.uid}
			err := c.run(context.Background(), tc.args)
			if (err == nil) != tc.success || !strings.Contains(out.String(), tc.want) {
				t.Fatalf("output=%s error=%v", out.String(), err)
			}
			if tc.args[0] != "init" && calls != 0 {
				t.Fatal("offline command resolved credentials")
			}
			if tc.name == "missing show" && !strings.Contains(diagnostics.String(), "no policy (denying all)") {
				t.Fatal("missing-policy warning absent")
			}
			if tc.args[0] == "init" && tc.success {
				p, err := sshserver.LoadPolicy(path)
				if err != nil || p.Allows(sshserver.Identity{Owner: "mallory@example.com"}, "alice", 1000) {
					t.Fatal("unsafe init", err)
				}
			}
		})
	}
}

func TestSSHPolicySymlinkCLI(t *testing.T) {
	for _, operation := range [][]string{{"show"}, {"test", "alice@example.com", "alice"}, {"init"}, {"init", "--force"}} {
		t.Run(strings.Join(operation, " "), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "ssh.json")
			target := filepath.Join(dir, "target")
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			c := sshPolicyCommand{path, &out, &out, func(context.Context) (string, error) { return "alice@example.com", nil }, fakePolicyLocalUser, 0}
			if err := c.run(context.Background(), operation); err == nil {
				t.Fatal("accepted symlink")
			}
			if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Fatal("wrote target")
			}
		})
	}
}

func TestOfferSSHPolicyInit(t *testing.T) {
	for _, tc := range []struct {
		name, answer                             string
		initialize, interactive, exists, success bool
	}{
		{name: "noninteractive"},
		{name: "declined", interactive: true, answer: "n\n"},
		{name: "accepted", interactive: true, answer: "yes\n", success: true},
		{name: "flag", initialize: true, success: true},
		{name: "empty existing", exists: true, initialize: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ssh.json")
			if tc.exists {
				if err := os.WriteFile(path, []byte(`{"rules":[]}`), 0644); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			err := offerOwnSSHPolicy(context.Background(), path, tc.initialize, tc.interactive, strings.NewReader(tc.answer), &out, func(context.Context) (string, error) { return "alice@example.com", nil })
			success := tc.success
			if tc.success {
				p, loadErr := sshserver.LoadPolicy(path)
				if loadErr != nil || p.Missing() {
					t.Fatalf("policy was not initialized: %v", loadErr)
				}
				success = policyHasLocalUsers(p, os.Geteuid())
			}
			if (err == nil) != success {
				t.Fatalf("output=%s error=%v", out.String(), err)
			}

		})
	}
}

func TestSSHPolicyRuntimeStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh.json")
	ctrl := &service.Control{SSHPolicyStatus: func() string { return sshPolicyState(path) }}
	ctrl.Update(func(s *service.Status) { s.SSH = true })
	for _, tc := range []struct{ data, want string }{{"", "no policy (denying all)"}, {`{"rules":[]}`, "empty policy (denying all)"}, {`broken`, "invalid (denying all)"}, {`{"rules":[{"from":["*"],"users":["alice"]}]}`, "configured"}} {
		if tc.data != "" {
			if err := os.WriteFile(path, []byte(tc.data), 0644); err != nil {
				t.Fatal(err)
			}
		}
		status := ctrl.Status()
		if status.SSHPolicy != tc.want {
			t.Fatalf("%+v", status)
		}
		devices := []meshDevice{{ThisMachine: true}, {}}
		applyRuntimeStatus(devices, status)
		if devices[0].SSHPolicy != tc.want || devices[1].SSHPolicy != "" {
			t.Fatalf("%+v", devices)
		}
		if tc.data == "" && deviceSSHStatus(devices[0]) != "SSH: no policy (denying all)" {
			t.Fatal("wrong status text")
		}
	}
}

func TestSSHPolicyOwnerFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh.json")
	var out bytes.Buffer
	c := sshPolicyCommand{path, &out, &out, func(context.Context) (string, error) { return "", fmt.Errorf("owner lookup unavailable") }, fakePolicyLocalUser, 0}
	if err := c.run(context.Background(), []string{"init"}); err == nil {
		t.Fatal("accepted missing owner")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("wrote unverified policy")
	}
}

func TestSSHPolicyExplicitPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "selected.json")
	var out bytes.Buffer
	c := sshPolicyCommand{filepath.Join(dir, "default.json"), &out, &out, func(context.Context) (string, error) { return "alice@example.com", nil }, fakePolicyLocalUser, 0}
	for _, args := range [][]string{{"init", "--policy", path}, {"show", "--policy=" + path}, {"test", "alice@example.com", "alice", "--policy", path}} {
		if err := c.run(context.Background(), args); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(c.path); !os.IsNotExist(err) {
		t.Fatal("ignored explicit path")
	}
}

func TestSSHPolicyTranscripts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh.json")
	// Exercise the real CLI parser/writer with a verified-owner fixture and local
	// account fixture. This test never needs account credentials or edits /etc.
	var out bytes.Buffer
	c := sshPolicyCommand{path, &out, &out, func(context.Context) (string, error) { return "alice@example.com", nil }, fakePolicyLocalUser, 0}
	for _, args := range [][]string{{"init"}, {"show"}, {"test", "alice@example.com", "alice"}, {"test", "alice@example.com", "root"}, {"test", "mallory@example.com", "alice"}, {"test", "alice@example.com", "alice", "--from", "device:dev-1"}} {
		out.Reset()
		err := c.run(context.Background(), args)
		t.Logf("$ meshscale ssh policy %s --policy %s\n%s", strings.Join(args, " "), path, out.String())
		if err != nil {
			t.Logf("exit: %v", err)
		}
	}
}

func TestOwnSSHPolicyPaths(t *testing.T) {
	options := &config.ServiceSettings{SSHPolicy: "/default/ssh.json"}
	for _, tc := range []struct {
		name string
		host *cloudflaressh.HostState
		want []string
	}{
		{name: "default", want: []string{options.SSHPolicy}},
		{name: "service", host: &cloudflaressh.HostState{ServiceSSH: true}, want: []string{options.SSHPolicy}},
		{name: "standalone", host: &cloudflaressh.HostState{Own: []cloudflaressh.Process{{Args: []string{"sshd", "--policy", "/custom/ssh.json"}}, {Args: []string{"sshd", "--policy=/other/ssh.json"}}, {Args: []string{"sshd", "-policy=/other/ssh.json"}}}}, want: []string{"/custom/ssh.json", "/other/ssh.json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ownSSHPolicyPaths(cloudflaressh.State{Host: tc.host}, options); !slices.Equal(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestSSHPolicyWarning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh.json")
	var out bytes.Buffer
	logger := log.New(&out, "", 0)
	warnMissingSSHPolicy(logger, path)
	if strings.Count(out.String(), "\n") != 1 || !strings.Contains(out.String(), "WARNING:") || !strings.Contains(out.String(), "meshscale ssh policy init") || !strings.Contains(out.String(), "former account-wide non-root default has been removed") {
		t.Fatal(out.String())
	}
	if err := os.WriteFile(path, []byte(`{"rules":[]}`), 0644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	warnMissingSSHPolicy(logger, path)
	if out.Len() != 0 {
		t.Fatal("warned for an explicit deny policy")
	}
}
