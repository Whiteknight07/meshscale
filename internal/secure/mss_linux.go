//go:build linux

package secure

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"time"
)

// Advertise our MSS on locally originated SYN/SYN-ACKs. Both Mesh endpoints
// install this rule, bounding TCP traffic in both directions. No
// forwarding, default routes, or unrelated firewall chains are changed.
func clampMSS(ctx context.Context, mss int) (func(), error) {
	var installed [][]string
	cleanup := func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, rule := range installed {
			args := append([]string{"-w", "-t", "mangle", "-D"}, rule...)
			_ = exec.CommandContext(c, "ip6tables", args...).Run()
		}
	}
	for _, chain := range []string{"OUTPUT"} {
		dir := "-o"
		rule := []string{chain, dir, "meshsecure0", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "tcpmss", "--mss", fmt.Sprintf("%d:65535", mss+1), "-m", "comment", "--comment", "meshscale secure MSS", "-j", "TCPMSS", "--set-mss", strconv.Itoa(mss)}
		args := append([]string{"-w", "-t", "mangle", "-A"}, rule...)
		if out, err := exec.CommandContext(ctx, "ip6tables", args...).CombinedOutput(); err != nil {
			cleanup()
			return nil, fmt.Errorf("secure MSS clamp: %w: %s", err, out)
		}
		installed = append(installed, rule)
	}
	return cleanup, nil
}
