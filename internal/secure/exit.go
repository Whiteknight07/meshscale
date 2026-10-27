package secure

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
)

// IPv4Address binds an account-scoped source /32 to a key. Discovery rejects
// collisions; the Linux planner also rejects overlap with existing host routes.
// This range is never installed as a subnet route.
func IPv4Address(account, public string) (netip.Addr, error) {
	if _, err := Address(account, public); err != nil {
		return netip.Addr{}, err
	}
	sum := sha256.Sum256([]byte("meshscale-exit-v2\x00" + account + "\x00" + public))
	return netip.AddrFrom4([4]byte{10, 192 | (sum[0] & 63), sum[1], 1 + sum[2]%254}), nil
}

func SameOwner(a, b Peer) bool {
	return a.Owner != "" && b.Owner != "" && SameEmail(a.Owner, b.Owner)
}

// SameEmail folds ASCII case only. Unicode folding would equate distinct
// addresses, such as "ſ" (U+017F) with "s" or the Kelvin sign with "k".
func SameEmail(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// SelectExit resolves a name only once. Persisted selections use both immutable
// registration and key, so rename/key rotation cannot silently change the exit.
func SelectExit(peers []Peer, self Peer, target string) (Peer, error) {
	var found *Peer
	for _, p := range peers {
		if p.Name != target && p.DNSName != target && p.IP.String() != target {
			continue
		}
		if found != nil {
			return Peer{}, fmt.Errorf("ambiguous exit node %q", target)
		}
		v := p
		found = &v
	}
	if found == nil {
		return Peer{}, fmt.Errorf("no secure exit node %q", target)
	}
	if found.PublicKey == self.PublicKey || !found.OffersExit || found.ExitVersion != 2 || !SameOwner(*found, self) {
		return Peer{}, fmt.Errorf("exit must be another ready v2 device owned by this account identity")
	}
	return *found, nil
}

// ExitAllowedIPs is the one AllowedIPs policy: the peer's overlay identity,
// its v2 source binding, and defaults only for the locally selected exit. A
// remote advertisement can never grant itself defaults: selection is local
// consent.
func ExitAllowedIPs(p Peer, selected string) []netip.Prefix {
	ips := []netip.Prefix{netip.PrefixFrom(p.IP, 128)}
	if p.ExitVersion == 2 && p.IPv4.Is4() {
		ips = append(ips, netip.PrefixFrom(p.IPv4, 32))
	}
	if selected != "" && p.PublicKey == selected {
		ips = append(ips, netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"))
	}
	return ips
}
