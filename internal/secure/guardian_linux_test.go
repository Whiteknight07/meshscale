//go:build linux

package secure

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Execute the actual guardian with fake network commands. It must remove the
// dedicated carrier chains even after it deletes the guarded interface.
func TestKernelGuardianRemovesCarrierChains(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "commands")
	for _, name := range []string{"ip", "iptables", "ip6tables", "nft", "cat", "grep"} {
		body := "#!/bin/sh\n"
		switch name {
		case "cat":
			body += "printf '123\\n'\n"
		case "nft", "grep":
			body += "exit 1\n"
		default:
			body += "printf '%s\\n' \"" + name + " $*\" >> \"$MESHSCALE_GUARD_TEST_LOG\"\n"
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("sh", "-c", kernelGuardian, "guardian-test", "123", "100.96.0.1", "100.96.0.0/12", "51821", "1200")
	cmd.Env = append(os.Environ(), "PATH="+dir, "MESHSCALE_GUARD_TEST_LOG="+log)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("guardian: %v: %s", err, out)
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	for _, binary := range []string{"iptables", "ip6tables"} {
		for _, args := range []string{"-D INPUT -p udp --dport 51821 -j MESHSCALE-SECURE", "-F MESHSCALE-SECURE", "-X MESHSCALE-SECURE"} {
			if !strings.Contains(string(data), binary+" -w 2 "+args+"\n") {
				t.Errorf("guardian did not remove carrier chain: %s %s", binary, args)
			}
		}
	}
}

// A late guardian whose interface generation is gone (a replacement daemon may
// own the shared chains now) must not run any cleanup command. A guardian that
// still owns its link removes the chains first and deletes the link last.
func TestKernelGuardianOwnershipAndOrder(t *testing.T) {
	for _, tc := range []struct {
		name, ifindex string
		owned         bool
	}{{"owned", "123", true}, {"replaced", "456", false}, {"gone", "", false}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "commands")
			for _, name := range []string{"ip", "iptables", "ip6tables", "nft", "cat", "grep"} {
				body := "#!/bin/sh\n"
				switch name {
				case "cat":
					if tc.ifindex == "" {
						body += "exit 1\n"
					} else {
						body += "printf '" + tc.ifindex + "\\n'\n"
					}
				case "nft", "grep":
					body += "exit 1\n"
				default:
					body += "printf '%s\\n' \"" + name + " $*\" >> \"$MESHSCALE_GUARD_TEST_LOG\"\n"
				}
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("sh", "-c", kernelGuardian, "guardian-test", "123", "100.96.0.1", "100.96.0.0/12", "51821", "1200")
			cmd.Env = append(os.Environ(), "PATH="+dir, "MESHSCALE_GUARD_TEST_LOG="+log)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("guardian: %v: %s", err, out)
			}
			data, _ := os.ReadFile(log)
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if !tc.owned {
				if len(data) != 0 {
					t.Fatalf("guardian without its link ran cleanup: %s", data)
				}
				return
			}
			if last := lines[len(lines)-1]; last != "ip link delete dev meshsecure0" {
				t.Fatalf("link must be deleted last, got order:\n%s", data)
			}
		})
	}
}

// Run only inside disposable network and mount namespaces with /sys remounted
// as sysfs for that network namespace. The guardian checks its interface index
// through sysfs. No key or actual WireGuard interface is necessary.
func TestKernelGuardianLive(t *testing.T) {
	if os.Getenv("MESHSCALE_LIVE_CARRIER") != "1" {
		t.Skip("requires an isolated network namespace")
	}
	if out, err := exec.CommandContext(t.Context(), "ip", "link", "add", "meshsecure0", "type", "dummy").CombinedOutput(); err != nil {
		t.Fatalf("create isolated link: %v: %s", err, out)
	}
	defer exec.Command("ip", "link", "delete", "meshsecure0").Run()
	link, err := net.InterfaceByName("meshsecure0")
	if err != nil {
		t.Fatal(err)
	}
	index, err := os.ReadFile("/sys/class/net/meshsecure0/ifindex")
	if err != nil || strings.TrimSpace(string(index)) != strconv.Itoa(link.Index) {
		t.Skip("remount sysfs inside a private mount namespace to match the network namespace")
	}
	local := netip.MustParseAddr("100.96.0.9")
	cleanup, err := installCarrierRules(t.Context(), runIPTables, local)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	guard, err := startKernelGuard(local, 1172)
	if err != nil {
		t.Fatal(err)
	}
	guard.Close()
	if _, err := net.InterfaceByName("meshsecure0"); err == nil {
		t.Fatal("guardian retained its interface")
	}
	for _, binary := range []string{"iptables", "ip6tables"} {
		out, err := runIPTables(t.Context(), binary, "-S")
		if err != nil {
			t.Fatalf("inspect carrier: %v: %s", err, out)
		}
		if strings.Contains(string(out), carrierChain) {
			t.Fatalf("guardian retained %s carrier chain", binary)
		}
	}
}
