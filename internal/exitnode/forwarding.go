package exitnode

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// Forwarding is a checked host prerequisite. Avoid rewriting enabled global
// sysctls: Linux resets unrelated IPv4 knobs when ip_forward changes.
type Forwarding interface {
	Check(context.Context) error
	IPv6(context.Context) bool
}
type SysctlForwarding struct{ Read func(string) ([]byte, error) }

func (s SysctlForwarding) read(path string) ([]byte, error) {
	if s.Read != nil {
		return s.Read(path)
	}
	return os.ReadFile(path)
}
func (s SysctlForwarding) Check(context.Context) error {
	data, err := s.read("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return fmt.Errorf("read IPv4 forwarding: %w", err)
	}
	if strings.TrimSpace(string(data)) != "1" {
		return fmt.Errorf("exit requires net.ipv4.ip_forward=1; enable forwarding explicitly with sysctl before advertising")
	}
	return nil
}
func (s SysctlForwarding) IPv6(context.Context) bool {
	data, err := s.read("/proc/sys/net/ipv6/conf/all/forwarding")
	return err == nil && strings.TrimSpace(string(data)) == "1"
}
func CheckForwarding() error { return (SysctlForwarding{}).Check(context.Background()) }
