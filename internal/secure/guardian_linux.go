//go:build linux

package secure

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"sync"

	"github.com/Whiteknight07/meshscale/internal/meshaddr"
)

// A kernel interface outlives its creating process. An independent pipe reader
// removes this exact interface generation and its scoped rules if the daemon
// exits, including a daemon-only SIGKILL. No private key enters the child.
// Killing the daemon AND guardian with SIGKILL defeats userspace cleanup; service
// operators must remove the orphan in that exceptional case before restarting.
const kernelGuardian = `
secure_index=$1
secure_local=$2
secure_range=$3
secure_port=$4
secure_mss=$5
cleanup() {
 # Act only while this generation's interface still exists. startKernel refuses
 # to run while meshsecure0 exists, so no replacement daemon can own the shared
 # chains until the link is deleted, which is therefore the final step.
 if [ "$(cat /sys/class/net/meshsecure0/ifindex 2>/dev/null)" != "$secure_index" ]; then
  return 0
 fi
 if nft list table inet meshscale_exit_v2 2>/dev/null | grep -Fq 'comment "meshscale exit v2"'; then
  nft delete table inet meshscale_exit_v2 2>/dev/null
 fi
 iptables -w 2 -D INPUT -p udp --dport "$secure_port" -j MESHSCALE-SECURE 2>/dev/null
 iptables -w 2 -F MESHSCALE-SECURE 2>/dev/null
 iptables -w 2 -X MESHSCALE-SECURE 2>/dev/null
 ip6tables -w 2 -D INPUT -p udp --dport "$secure_port" -j MESHSCALE-SECURE 2>/dev/null
 ip6tables -w 2 -F MESHSCALE-SECURE 2>/dev/null
 ip6tables -w 2 -X MESHSCALE-SECURE 2>/dev/null
 # Legacy rules inserted directly into INPUT by older releases.
 iptables -w 2 -D INPUT -p udp --dport "$secure_port" ! -d "$secure_local" -m comment --comment 'meshscale secure carrier' -j DROP 2>/dev/null
 iptables -w 2 -D INPUT -p udp --dport "$secure_port" ! -s "$secure_range" -m comment --comment 'meshscale secure carrier' -j DROP 2>/dev/null
 ip6tables -w 2 -D INPUT -p udp --dport "$secure_port" -m comment --comment 'meshscale secure carrier' -j DROP 2>/dev/null
 ip6tables -w 2 -t mangle -D OUTPUT -o meshsecure0 -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss "$((secure_mss + 1)):65535" -m comment --comment 'meshscale secure MSS' -j TCPMSS --set-mss "$secure_mss" 2>/dev/null
 ip link delete dev meshsecure0
}
trap cleanup EXIT
trap 'exit 0' HUP INT TERM
read -r secure_unused
exit 0
`

type kernelGuard struct {
	writer *os.File
	done   chan struct{}
	once   sync.Once
	index  int // ifindex of the meshsecure0 generation it guards
}

func startKernelGuard(local netip.Addr, mss int) (*kernelGuard, error) {
	link, err := net.InterfaceByName("meshsecure0")
	if err != nil {
		return nil, err
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("sh", "-c", kernelGuardian, "meshscale-kernel-guardian", strconv.Itoa(link.Index), local.String(), meshaddr.IPv4Range.String(), strconv.Itoa(Port), strconv.Itoa(mss))
	cmd.Stdin = reader
	if err := cmd.Start(); err != nil {
		reader.Close()
		writer.Close()
		return nil, fmt.Errorf("start kernel lifetime guardian: %w", err)
	}
	reader.Close()
	guard := &kernelGuard{writer: writer, done: make(chan struct{}), index: link.Index}
	go func() { _ = cmd.Wait(); close(guard.done) }()
	return guard, nil
}
func (g *kernelGuard) Close() { g.once.Do(func() { g.writer.Close(); <-g.done }) }
func (g *kernelGuard) Health() error {
	select {
	case <-g.done:
		return fmt.Errorf("kernel lifetime guardian stopped")
	default:
		return nil
	}
}
