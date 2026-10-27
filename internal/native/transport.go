package native

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/Whiteknight07/meshscale/internal/wgtransport"
)

type Network = wgtransport.Network
type osNetwork = wgtransport.OSNetwork

type Transport struct {
	Network      Network
	wg           *device.Device
	registration Registration
	cleanup      func()
	health       func() bool
	target       func(netip.Addr) bool
}

func Start(ctx context.Context, s *State, userspace bool) (*Transport, error) {
	if err := s.Registration.Validate(); err != nil {
		return nil, err
	}
	ips, err := s.Registration.IPs()
	if err != nil {
		return nil, err
	}
	var t tun.Device
	var network Network
	cleanup := func() {}
	if userspace {
		t, network, err = wgtransport.NewNetstack(ips, MTU)
	} else {
		t, cleanup, err = createSystemTUN(ctx, ips)
		network = osNetwork{}
	}
	if err != nil {
		return nil, err
	}
	cfg, err := configuration(s.PrivateKey, s.Registration)
	if err != nil {
		t.Close()
		cleanup()
		return nil, err
	}
	wg, err := wgtransport.Start(t, conn.NewDefaultBind(), cfg, "meshscale native: ")
	if err != nil {
		cleanup()
		return nil, err
	}
	return &Transport{Network: network, wg: wg, registration: s.Registration, cleanup: cleanup}, nil
}

func configuration(private string, r Registration) (string, error) {
	key, err := keyBytes(private)
	if err != nil {
		return "", err
	}
	peer, err := keyBytes(r.Config.Peers[0].PublicKey)
	if err != nil {
		return "", err
	}
	endpoint, err := r.Config.Peers[0].Endpoint.Address()
	if err != nil {
		return "", err
	}
	cfg := fmt.Sprintf("private_key=%s\nreplace_peers=true\npublic_key=%s\nendpoint=%s\nreplace_allowed_ips=true\n", hex.EncodeToString(key), hex.EncodeToString(peer), endpoint)
	for _, p := range tunnelRoutes {
		cfg += "allowed_ip=" + p + "\n"
	}
	return cfg + "persistent_keepalive_interval=25\n", nil
}
func (t *Transport) configure(private string, r Registration) error {
	cfg, err := configuration(private, r)
	if err != nil {
		return err
	}
	if err := t.wg.IpcSet(cfg); err != nil {
		return fmt.Errorf("apply native WireGuard config: %w", err)
	}
	return nil
}

func (t *Transport) Refresh(s *State, fresh Registration) error {
	if !reflect.DeepEqual(t.registration.Config.Interface.Addresses, fresh.Config.Interface.Addresses) {
		return fmt.Errorf("addresses on Mesh changed; restart native up to apply safely")
	}
	if !reflect.DeepEqual(t.registration.Config.Peers, fresh.Config.Peers) {
		if err := t.configure(s.PrivateKey, fresh); err != nil {
			return err
		}
	}
	t.registration = fresh
	return nil
}
func (t *Transport) Close() { t.wg.Close(); t.cleanup() }

// Healthy distinguishes an initialized engine from an actual edge handshake.
func (t *Transport) Healthy() bool {
	if t.health != nil {
		return t.health()
	}
	dump, err := t.wg.IpcGet()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(dump, "\n") {
		if seconds, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
			value, err := strconv.ParseInt(seconds, 10, 64)
			age := time.Since(time.Unix(value, 0))
			return err == nil && value > 0 && age >= 0 && age < 3*time.Minute
		}
	}
	return false
}

// ServeNetwork exposes TCP dial/listener leases over the same private, bounded
// control protocol as the native backend. It does not own network lifetime.
func ServeNetwork(ctx context.Context, listener net.Listener, network Network, ips []netip.Addr, healthy func() bool, target func(netip.Addr) bool) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c := &control{transport: &Transport{Network: network, health: healthy, target: target}, ips: ips, cancel: cancel, listeners: map[uint64]net.Listener{}}
	defer c.finishStop()
	defer c.close()
	return c.serve(ctx, listener)
}
