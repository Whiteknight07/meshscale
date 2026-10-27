package secure

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Whiteknight07/meshscale/internal/meshaddr"
	"github.com/Whiteknight07/meshscale/internal/secureroute"
	"github.com/Whiteknight07/meshscale/internal/wgtransport"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"
)

type PeerStatus struct {
	Peer
	Enabled       bool       `json:"enabled"`
	LastHandshake *time.Time `json:"last_handshake,omitempty"`
	HandshakeAge  *int64     `json:"handshake_age_seconds,omitempty"`
}
type Status struct {
	CongestionControl string       `json:"tcp_congestion_control,omitempty"`
	ExitExceptions    []string     `json:"exit_node_exceptions,omitempty"`
	ExitNode          string       `json:"exit_node,omitempty"`
	ExitNodeID        string       `json:"exit_node_id,omitempty"`
	ExitState         string       `json:"exit_state,omitempty"`
	OffersExit        bool         `json:"offers_exit_node"`
	AllowLAN          bool         `json:"exit_node_allow_lan_access"`
	DNS               string       `json:"exit_node_dns,omitempty"`
	IPv4              string       `json:"ipv4,omitempty"`
	Mode              string       `json:"mode,omitempty"`
	MTU               int          `json:"mtu,omitempty"`
	MSS               int          `json:"tcp_mss,omitempty"`
	Warnings          []string     `json:"warnings,omitempty"`
	Enabled           bool         `json:"enabled"`
	Running           bool         `json:"running"`
	Userspace         bool         `json:"userspace"`
	IP                string       `json:"ip,omitempty"`
	Error             string       `json:"error,omitempty"`
	Peers             []PeerStatus `json:"peers,omitempty"`
}
type wireGuardDevice interface {
	IpcSet(string) error
	IpcGet() (string, error)
	Close()
}

// OSBind retains upstream batched I/O and validates the Mesh source range and
// available local packet-info. Root TUN mode also scopes the destination with
// host filters because upstream GRO can omit packet-info. No packet is wrapped.
type OSBind struct {
	conn.Bind
	LocalIP netip.Addr
}

func NewOSBind(ip netip.Addr) conn.Bind { return &OSBind{Bind: conn.NewStdNetBind(), LocalIP: ip} }
func (b *OSBind) ParseEndpoint(text string) (conn.Endpoint, error) {
	addr, err := netip.ParseAddrPort(text)
	if err != nil || !meshaddr.IsIPv4(addr.Addr()) || addr.Port() == 0 {
		return nil, fmt.Errorf("secure carrier requires a Mesh IPv4 endpoint")
	}
	return b.Bind.ParseEndpoint(text)
}
func (b *OSBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	if !meshaddr.IsIPv4(b.LocalIP) {
		return nil, 0, fmt.Errorf("secure carrier requires a local Mesh IPv4 address")
	}
	receives, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	for i, receive := range receives {
		receives[i] = func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
			n, err := receive(packets, sizes, endpoints)
			return filterMeshPackets(b.LocalIP, packets, sizes, endpoints, n), err
		}
	}
	return receives, actual, nil
}
func filterMeshPackets(local netip.Addr, packets [][]byte, sizes []int, endpoints []conn.Endpoint, n int) int {
	kept := 0
	for i := 0; i < n; i++ {
		endpoint := endpoints[i]
		if endpoint == nil {
			continue
		}
		source := endpoint.SrcIP().Unmap()
		// Upstream's UDP-GRO splitter can omit packet-info on split messages.
		// Preserve batching; privileged TUN carriers also enforce destination scope
		// with INPUT rules, while private stacks authenticate every inner key/IP.
		if (source.IsValid() && source != local) || !meshaddr.IsIPv4(endpoint.DstIP().Unmap()) {
			continue
		}
		if kept != i {
			copy(packets[kept], packets[i][:sizes[i]])
		}
		sizes[kept], endpoints[kept] = sizes[i], endpoint
		kept++
	}
	return kept
}

type Transport struct {
	Mode           string
	MTU            int
	MSS            int
	Network        wgtransport.Network
	wg             wireGuardDevice
	mu             sync.Mutex
	peers          []Peer
	exitKey        string
	sourceBindings map[string]netip.Addr
	public         string
	ip             netip.Addr
	forwardCleanup func()
	cleanup        func()
	once           sync.Once
}

// Start brings up the secure engine over a UDP carrier bind. mode is "auto",
// "kernel" or "go". Peer discovery restricts endpoints to Mesh; the engine
// itself accepts numeric endpoints so isolated loopback tests can reuse it.
func Start(ctx context.Context, key Key, ip netip.Addr, userspace bool, bind conn.Bind, mode string) (*Transport, error) {
	if mode != "" && mode != "auto" && mode != "kernel" && mode != "go" {
		return nil, fmt.Errorf("invalid secure engine %q", mode)
	}
	if !IsIP(ip) {
		return nil, fmt.Errorf("invalid secure address")
	}
	public, err := key.Public()
	if err != nil {
		return nil, err
	}
	mtu, mss := PathMTU(carrierMTU())
	carrier, osBind := bind.(*OSBind)
	if osBind && !meshaddr.IsIPv4(carrier.LocalIP) {
		return nil, fmt.Errorf("secure carrier requires a local Mesh IPv4 address")
	}
	if mode == "kernel" && !userspace && !osBind {
		return nil, fmt.Errorf("kernel WireGuard needs an OS Mesh carrier")
	}
	if !userspace && osBind && mode != "go" {
		wg, cleanup, err := startKernel(ctx, key, ip, carrier.LocalIP, mtu)
		if err == nil {
			removeMSS, err := clampMSS(ctx, mss)
			if err != nil {
				wg.Close()
				cleanup()
				return nil, err
			}
			return &Transport{Network: systemNetwork{}, wg: wg, public: public, ip: ip, Mode: "kernel", MTU: mtu, MSS: mss, cleanup: func() { removeMSS(); cleanup() }}, nil
		}
		if mode == "kernel" {
			return nil, err
		}
	}

	var t tun.Device
	var network wgtransport.Network
	cleanup := func() {}
	if userspace {
		t, network, err = wgtransport.NewNetstack([]netip.Addr{ip}, mtu)
		if err == nil {
			t = &mssTUN{Device: t, mss: uint16(mss)}
		}
	} else {
		t, cleanup, err = wgtransport.CreateTUN(ctx, "meshsecure0", []netip.Addr{ip}, []string{OverlayRange}, mtu)
		network = systemNetwork{}
	}
	if err != nil {
		return nil, err
	}
	if !userspace {
		removeMSS, err := clampMSS(ctx, mss)
		if err != nil {
			t.Close()
			cleanup()
			return nil, err
		}
		removeLink := cleanup
		cleanup = func() { removeMSS(); removeLink() }
	}
	private, _ := decodeKey(key.Private)
	wg, err := wgtransport.Start(t, bind, "private_key="+hex.EncodeToString(private)+"\nlisten_port="+strconv.Itoa(Port)+"\n", "meshscale secure: ")
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("start secure WireGuard: %w", err)
	}
	engineMode := "go"
	if userspace {
		engineMode = "gvisor"
	}
	if osBind && !userspace {
		removeCarrier, err := restrictCarrier(ctx, carrier.LocalIP)
		if err != nil {
			wg.Close()
			cleanup()
			return nil, err
		}
		previousCleanup := cleanup
		cleanup = func() { previousCleanup(); removeCarrier() }
	}
	tr := &Transport{Mode: engineMode, MTU: mtu, MSS: mss, Network: network, wg: wg, public: public, ip: ip, cleanup: cleanup}
	return tr, nil
}

// Reconcile retains unchanged WG peers (and their handshake state). AllowedIPs
// are explicit per peer; part 1 permits only its cryptographically bound /128.
// An exit-node implementation must add an explicit route/policy opt-in here.
func (t *Transport) Reconcile(peers []Peer) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	// Revalidate role authorization even when the serialized peer set is unchanged.
	for _, p := range peers {
		if p.PublicKey != t.public && !t.validAllowedIPs(p) {
			return fmt.Errorf("peer routes lack local exit authorization")
		}
	}
	if samePeerConfigs(t.peers, peers, t.public) {
		for i, old := range t.peers {
			for _, p := range peers {
				if p.PublicKey == old.PublicKey {
					p.AllowedIPs = old.AllowedIPs
					t.peers[i] = p
					break
				}
			}
		}
		return nil
	}
	var cfg strings.Builder
	want := map[string]Peer{}
	ips := map[netip.Addr]bool{}
	for _, p := range peers {
		if p.PublicKey == t.public {
			continue
		}
		if _, err := decodeKey(p.PublicKey); err != nil {
			return err
		}
		if _, exists := want[p.PublicKey]; exists || !IsIP(p.IP) || p.IP == t.ip || ips[p.IP] || !t.validAllowedIPs(p) || !p.Endpoint.IsValid() || p.Endpoint.Port() == 0 {
			return fmt.Errorf("invalid/duplicate peer or AllowedIPs")
		}
		want[p.PublicKey] = p
		ips[p.IP] = true
	}
	for _, old := range t.peers {
		if _, ok := want[old.PublicKey]; !ok {
			key, _ := decodeKey(old.PublicKey)
			fmt.Fprintf(&cfg, "public_key=%s\nremove=true\n", hex.EncodeToString(key))
		}
	}
	for _, p := range peers {
		if p.PublicKey == t.public {
			continue
		}
		unchanged := false
		for _, old := range t.peers {
			if samePeerConfig(old, p) {
				unchanged = true
				break
			}
		}
		if unchanged {
			continue
		}
		key, _ := decodeKey(p.PublicKey)
		// Mesh endpoints are directly routed; no NAT keepalive is needed.
		keepalive := 0
		fmt.Fprintf(&cfg, "public_key=%s\nendpoint=%s\nreplace_allowed_ips=true\n", hex.EncodeToString(key), p.Endpoint)
		for _, prefix := range p.AllowedIPs {
			fmt.Fprintf(&cfg, "allowed_ip=%s\n", prefix)
		}
		fmt.Fprintf(&cfg, "persistent_keepalive_interval=%d\n", keepalive)
	}
	if err := t.wg.IpcSet(cfg.String()); err != nil {
		return fmt.Errorf("apply secure peers: %w", err)
	}
	t.peers = cloneRemotePeers(peers, t.public)
	return nil
}
func (t *Transport) Close() {
	t.once.Do(func() {
		if t.forwardCleanup != nil {
			t.forwardCleanup()
		}
		t.wg.Close()
		t.cleanup()
	})
}
func (t *Transport) Peers() []PeerStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	dump, err := t.wg.IpcGet()
	handshakes := map[string]time.Time{}
	if err == nil {
		key := ""
		for _, line := range strings.Split(dump, "\n") {
			if s, ok := strings.CutPrefix(line, "public_key="); ok {
				key = s
			}
			if s, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
				if n, e := strconv.ParseInt(s, 10, 64); e == nil && n > 0 {
					handshakes[key] = time.Unix(n, 0).UTC()
				}
			}
		}
	}
	result := make([]PeerStatus, 0, len(t.peers))
	for _, p := range t.peers {
		s := PeerStatus{Peer: p, Enabled: true}
		key, _ := decodeKey(p.PublicKey)
		if h, ok := handshakes[hex.EncodeToString(key)]; ok {
			age := max(int64(0), int64(time.Since(h)/time.Second))
			s.LastHandshake = &h
			s.HandshakeAge = &age
		}
		result = append(result, s)
	}
	return result
}

type systemNetwork struct{}

func (systemNetwork) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}
func (systemNetwork) ListenTCP(a netip.AddrPort) (net.Listener, error) { return listenSecureTCP(a) }

// ForwardingHook is reserved for an explicitly selected exit-node role. Secure
// mode never enables forwarding/NAT itself. The returned cleanup must restore
// only resources installed by the hook.
type ForwardingHook func(context.Context, string, []Peer) (cleanup func(), err error)

func (t *Transport) SecureNetwork() wgtransport.Network { return t.Network }

func samePeerConfig(a, b Peer) bool {
	return a.PublicKey == b.PublicKey && a.IP == b.IP && a.Endpoint == b.Endpoint && slices.Equal(a.AllowedIPs, b.AllowedIPs)
}
func samePeerConfigs(old, peers []Peer, public string) bool {
	count := 0
	for _, peer := range peers {
		if peer.PublicKey != public {
			count++
		}
	}
	if count != len(old) {
		return false
	}
	for _, prev := range old {
		matches := 0
		for _, peer := range peers {
			if peer.PublicKey != public && samePeerConfig(prev, peer) {
				matches++
			}
		}
		if matches != 1 {
			return false
		}
	}
	return true
}

func cloneRemotePeers(peers []Peer, public string) []Peer {
	var result []Peer
	for _, peer := range peers {
		if peer.PublicKey != public {
			peer.AllowedIPs = slices.Clone(peer.AllowedIPs)
			result = append(result, peer)
		}
	}
	return result
}

func (t *Transport) Details() (string, int, int) { return t.Mode, t.MTU, t.MSS }

func (t *Transport) Health() error {
	if h, ok := t.wg.(interface{ Health() error }); ok {
		return h.Health()
	}
	return nil
}

// AuthorizeExit binds validated source hosts and the one locally selected key.
// Call before Reconcile, from the same supervisor goroutine.
func (t *Transport) AuthorizeExit(peers []Peer, selected string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.exitKey = selected
	t.sourceBindings = make(map[string]netip.Addr)
	for _, p := range peers {
		if p.ExitVersion == 2 && p.IPv4.Is4() {
			t.sourceBindings[p.PublicKey] = p.IPv4
		}
	}
}

// validAllowedIPs accepts exactly ExitAllowedIPs for the peer's authorized
// binding, so a caller cannot widen what the directory and local selection allow.
func (t *Transport) validAllowedIPs(p Peer) bool {
	authorized := Peer{IP: p.IP, PublicKey: p.PublicKey}
	if ip, ok := t.sourceBindings[p.PublicKey]; ok {
		authorized.ExitVersion, authorized.IPv4 = 2, ip
	}
	return slices.Equal(p.AllowedIPs, ExitAllowedIPs(authorized, t.exitKey))
}

// SetForwarding reconciles only an explicitly requested exit role. Cleanup is
// attached once to transport lifetime; the hook itself updates authenticated sets.
func (t *Transport) SetForwarding(ctx context.Context, hook ForwardingHook, peers []Peer) error {
	cleanup, err := hook(ctx, "meshsecure0", peers)
	if err != nil {
		return fmt.Errorf("configure exit forwarding: %w", err)
	}
	t.forwardCleanup = cleanup
	return nil
}

func (t *Transport) CongestionControl() string { return secureroute.Status() }
