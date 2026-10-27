package linuxnetwork

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type kernelRouting struct {
	handle *netlink.Handle
	watch  int
}

func newRoutingRunner() routingRunner { return &kernelRouting{watch: -1} }

func (k *kernelRouting) open() error {
	if k.handle != nil {
		return nil
	}
	handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	if err := handle.SetSocketTimeout(time.Second); err != nil {
		handle.Close()
		return err
	}
	watch, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		handle.Close()
		return err
	}
	groups := uint32(unix.RTMGRP_LINK | unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV4_RULE)
	if err := unix.Bind(watch, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		unix.Close(watch)
		handle.Close()
		return err
	}
	k.handle, k.watch = handle, watch
	return nil
}
func (k *kernelRouting) Close() {
	if k.handle != nil {
		k.handle.Close()
		k.handle = nil
	}
	if k.watch >= 0 {
		unix.Close(k.watch)
		k.watch = -1
	}
}
func (k *kernelRouting) Changed() (bool, error) {
	fresh := k.handle == nil
	if err := k.open(); err != nil {
		return false, err
	}
	changed := fresh
	var buffer [32768]byte
	for {
		_, _, err := unix.Recvfrom(k.watch, buffer[:], unix.MSG_DONTWAIT)
		switch {
		case errors.Is(err, unix.EAGAIN):
			return changed, nil
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.ENOBUFS):
			changed = true // Lost notifications require a full resnapshot.
		case err != nil:
			k.Close()
			return false, err
		default:
			changed = true
		}
	}
}
func (k *kernelRouting) Snapshot(enabled bool) (routingSnapshot, error) {
	snapshot := routingSnapshot{WARPTables: map[int]bool{}}
	rules, err := k.handle.RuleList(unix.AF_INET)
	if err != nil {
		return snapshot, fmt.Errorf("list IPv4 policy rules: %w", err)
	}
	for _, r := range rules {
		snapshot.Rules = append(snapshot.Rules, policyRule{Priority: r.Priority, Table: r.Table, Protocol: int(r.Protocol), Destination: ipPrefix(r.Dst), Mark: r.Mark, Invert: r.Invert})
	}
	if !enabled {
		return snapshot, nil
	}
	link, err := k.handle.LinkByName("CloudflareWARP")
	if err != nil {
		return snapshot, fmt.Errorf("find WARP interface: %w", err)
	}
	routes, err := k.handle.RouteListFiltered(unix.AF_INET, &netlink.Route{LinkIndex: link.Attrs().Index}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
	if err != nil {
		return snapshot, fmt.Errorf("list WARP routes: %w", err)
	}
	for _, route := range routes {
		snapshot.WARPTables[route.Table] = true
	}
	routes, err = k.handle.RouteListFiltered(unix.AF_INET, &netlink.Route{Table: 52}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return snapshot, fmt.Errorf("list Tailscale routes: %w", err)
	}
	for _, route := range routes {
		if route.Dst == nil || ipPrefix(route.Dst).Bits() == 0 {
			snapshot.TailscaleDefault = true
		}
	}
	return snapshot, nil
}
func ipPrefix(network *net.IPNet) netip.Prefix {
	if network == nil {
		return netip.Prefix{}
	}
	addr, ok := netip.AddrFromSlice(network.IP)
	if !ok {
		return netip.Prefix{}
	}
	bits, _ := network.Mask.Size()
	return netip.PrefixFrom(addr.Unmap(), bits).Masked()
}
func netlinkRule(rule policyRule) *netlink.Rule {
	r := netlink.NewRule()
	r.Family, r.Priority, r.Table, r.Protocol = unix.AF_INET, rule.Priority, rule.Table, uint8(rule.Protocol)
	r.Dst = &net.IPNet{IP: net.IP(rule.Destination.Addr().AsSlice()), Mask: net.CIDRMask(rule.Destination.Bits(), 32)}
	return r
}
func (k *kernelRouting) Add(rule policyRule) error    { return k.handle.RuleAdd(netlinkRule(rule)) }
func (k *kernelRouting) Delete(rule policyRule) error { return k.handle.RuleDel(netlinkRule(rule)) }
