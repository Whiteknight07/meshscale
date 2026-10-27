//go:build linux

package exitnode

import (
	"context"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// WatchNetwork reports route, rule, link and address changes, debounced. The
// channel closes if a kernel subscription fails, so callers keep a periodic
// fallback.
func WatchNetwork(ctx context.Context) (<-chan struct{}, error) {
	raw, err := watchNetlink(ctx)
	if err != nil {
		return nil, err
	}
	return debounceEvents(ctx, raw, networkEventDebounce), nil
}

// Watch adds firewalld changes to WatchNetwork's events. Without firewalld
// signals, firewall lookups simply stay uncached.
func (m *Manager) Watch(ctx context.Context) (<-chan struct{}, error) {
	network, err := watchNetlink(ctx)
	if err != nil {
		return nil, err
	}
	firewall, err := m.Firewall.Watch(ctx)
	if err != nil {
		firewall = nil
	}
	return debounceEvents(ctx, mergeEvents(ctx, network, firewall), networkEventDebounce), nil
}

// watchNetlink reports rtnetlink changes until ctx ends. A subscription that
// dies (for example on ENOBUFS when the host churns routes) is re-established
// with backoff, and recovery counts as a change because events may be lost.
func watchNetlink(ctx context.Context) (<-chan struct{}, error) {
	events, err := subscribeNetlink(ctx)
	if err != nil {
		return nil, err
	}
	out := make(chan struct{}, 1)
	go func() {
		defer close(out)
		for delay := time.Second; ; {
			for range events {
				queueEvent(out)
				delay = time.Second
			}
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(delay):
				}
				delay = min(2*delay, 30*time.Second)
				if events, err = subscribeNetlink(ctx); err == nil {
					queueEvent(out)
					break
				}
			}
		}
	}()
	return out, nil
}

// subscribeNetlink returns one channel for route, link, address and rule
// changes. It closes, releasing every subscription, when ctx ends or any
// subscription dies. Rules come straight from the kernel's rule multicast
// groups because netlink has no RuleSubscribe helper.
func subscribeNetlink(ctx context.Context) (<-chan struct{}, error) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	routes := make(chan netlink.RouteUpdate, 64)
	links := make(chan netlink.LinkUpdate, 64)
	addrs := make(chan netlink.AddrUpdate, 64)
	subscribe := []func() error{
		func() error { return netlink.RouteSubscribe(routes, done) },
		func() error { return netlink.LinkSubscribe(links, done) },
		func() error { return netlink.AddrSubscribe(addrs, done) },
	}
	for _, s := range subscribe {
		if err := s(); err != nil {
			close(done)
			cancel()
			return nil, err
		}
	}
	rules, err := subscribeRules()
	if err != nil {
		close(done)
		cancel()
		return nil, err
	}
	merged := mergeEvents(ctx, signals(routes), signals(links), signals(addrs), rules.Events)
	out := make(chan struct{}, 1)
	go func() {
		defer close(out)
		defer rules.Close()
		defer close(done)
		defer cancel()
		for range merged {
			queueEvent(out)
		}
	}()
	return out, nil
}

// signals drops the payload of a netlink update channel.
func signals[T any](updates <-chan T) <-chan struct{} {
	out := make(chan struct{}, 1)
	go func() {
		defer close(out)
		for range updates {
			queueEvent(out)
		}
	}()
	return out
}

type ruleSubscription struct {
	Events <-chan struct{}
	Close  func()
}

func subscribeRules() (ruleSubscription, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return ruleSubscription{}, err
	}
	groups := uint32(1<<(unix.RTNLGRP_IPV4_RULE-1) | 1<<(unix.RTNLGRP_IPV6_RULE-1))
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		_ = unix.Close(fd)
		return ruleSubscription{}, err
	}
	// Closing an fd does not wake a blocked recvfrom, so the reader polls for
	// shutdown with a receive timeout.
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})
	closed := make(chan struct{})
	var once sync.Once
	events := make(chan struct{}, 1)
	go func() {
		defer close(events)
		defer unix.Close(fd)
		var buffer [16384]byte
		for {
			_, _, err := unix.Recvfrom(fd, buffer[:], 0)
			select {
			case <-closed:
				return
			default:
			}
			switch err {
			case nil, unix.ENOBUFS: // an overrun still means rules changed
				queueEvent(events)
			case unix.EINTR, unix.EAGAIN:
			default:
				return
			}
		}
	}()
	return ruleSubscription{Events: events, Close: func() { once.Do(func() { close(closed) }) }}, nil
}
