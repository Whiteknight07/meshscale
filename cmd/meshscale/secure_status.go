package main

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/secure"
	"github.com/Whiteknight07/meshscale/internal/service"
)

func assignSecureStatus(ctx context.Context, client *cfapi.Client, account string, devices []meshDevice) error {
	peers, err := loadSecurePeers(ctx, client, account)
	if err != nil {
		return err
	}
	var status service.Status
	if dir, err := config.ServiceDir(); err == nil {
		_ = service.Request(ctx, dir, "GET", "/status", nil, &status)
	}
	byKey := map[string]secure.PeerStatus{}
	for _, p := range status.Secure.Peers {
		byKey[p.PublicKey] = p
	}
	for i := range devices {
		d := &devices[i]
		if d.ThisMachine {
			d.SecureTCP = status.Secure.CongestionControl
			d.ExitNode, d.ExitState, d.ExitAllowLAN = status.Secure.ExitNode, status.Secure.ExitState, status.Secure.AllowLAN
			if dir, err := secureDir(); err == nil {
				if settings, err := secure.LoadConfig(dir); err == nil && settings.ExitID != "" && d.ExitNode == "" {
					d.ExitNode = settings.ExitName
					d.ExitState = "blocked: daemon unavailable"
					d.ExitAllowLAN = settings.AllowLAN
				}
			}
		}
		for _, p := range peers {
			if p.RegistrationID != d.ID && p.RegistrationID != d.RegistrationID {
				continue
			}
			d.OffersExit = p.OffersExit
			s := secure.PeerStatus{Peer: p, Enabled: true}
			if runtime, ok := byKey[p.PublicKey]; ok {
				s.LastHandshake = runtime.LastHandshake
				s.HandshakeAge = runtime.HandshakeAge
			}
			d.Secure = &s
		}
	}
	if status.Secure.Enabled && !status.Secure.Running {
		return fmt.Errorf("secure engine stopped: %s", status.Secure.Error)
	}
	return nil
}

// resolveSecureTarget deliberately requires .secure or a numeric overlay IP.
// Once requested, errors never fall back to a plain Mesh connection.
func resolveSecureTarget(ctx context.Context, target string) (netip.Addr, bool, error) {
	ip, err := netip.ParseAddr(target)
	if !strings.HasSuffix(target, ".secure") && (err != nil || !secure.IsIP(ip)) {
		return netip.Addr{}, false, nil
	}
	dir, err := config.ServiceDir()
	if err != nil {
		return netip.Addr{}, true, err
	}
	var status service.Status
	if err := service.Request(ctx, dir, "GET", "/status", nil, &status); err != nil {
		return netip.Addr{}, true, fmt.Errorf("secure daemon unavailable: %w", err)
	}
	if !status.Secure.Running {
		return netip.Addr{}, true, fmt.Errorf("secure mode is not running: %s", status.Secure.Error)
	}
	var found netip.Addr
	for _, p := range status.Secure.Peers {
		if p.DNSName != target && p.IP != ip {
			continue
		}
		if found.IsValid() {
			return netip.Addr{}, true, fmt.Errorf("ambiguous secure target")
		}
		found = p.IP
	}
	if !found.IsValid() {
		return netip.Addr{}, true, fmt.Errorf("no active secure peer %q", target)
	}
	return found, true, nil
}

func secureState(s *secure.PeerStatus) string {
	if s == nil {
		return "plain"
	}
	if s.LastHandshake == nil {
		return s.IP.String() + " (no handshake)"
	}
	age := max(int64(0), int64(time.Since(*s.LastHandshake)/time.Second))
	return fmt.Sprintf("%s (handshake %ds ago)", s.IP, age)
}

func exitState(d meshDevice) string {
	if d.ExitNode != "" {
		return d.ExitNode + " (" + d.ExitState + ")"
	}
	if d.OffersExit {
		return "offers exit node"
	}
	return ""
}
