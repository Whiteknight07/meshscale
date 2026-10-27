// Package exitnode owns Linux exit routing, separately from secure engine lifetime.
package exitnode

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

const ForwardTable = "meshscale_exit_v2"
const GuardTable = "meshscale_exit_guard_v2"
const ownership = "meshscale exit v2"

type Runner interface {
	Run(context.Context, string, string, ...string) ([]byte, error)
}
type Commands struct{}

func (Commands) Run(ctx context.Context, input, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

type Route struct {
	Dst      string `json:"dst"`
	Dev      string `json:"dev"`
	Gateway  string `json:"gateway"`
	Table    any    `json:"table"`
	Type     string `json:"type"`
	Protocol string `json:"protocol"`
	Scope    string `json:"scope"`
	PrefSrc  string `json:"prefsrc"`
	Metric   int    `json:"metric"`
}

func (r Route) table() string {
	if r.Table == nil {
		return "main"
	}
	return fmt.Sprint(r.Table)
}
func (r Route) prefix(v6 bool) (netip.Prefix, error) {
	if r.Dst == "default" {
		if v6 {
			return netip.ParsePrefix("::/0")
		}
		return netip.ParsePrefix("0.0.0.0/0")
	}
	if ip, err := netip.ParseAddr(r.Dst); err == nil {
		return netip.PrefixFrom(ip, ip.BitLen()), nil
	}
	return netip.ParsePrefix(r.Dst)
}

type Rule struct {
	Priority int             `json:"priority"`
	Table    any             `json:"table"`
	FWMark   string          `json:"fwmark"`
	FWMask   string          `json:"fwmask"`
	Protocol string          `json:"protocol"`
	Not      json.RawMessage `json:"not"`
	Dst      string          `json:"dst"`
	DstLen   int             `json:"dstlen"`
	IPProto  string          `json:"ipproto"`
	DPort    uint16          `json:"dport"`
	Action   string          `json:"action"`
}
type Family struct {
	Routes []Route
	Rules  []Rule
}
type Snapshot struct {
	V4, V6   Family
	DNS, SSH []netip.Addr
	Links    []Link
}

type SnapshotReader interface {
	Inspect(context.Context) (Snapshot, error)
}

func inspect(ctx context.Context, reader SnapshotReader, run Runner) (Snapshot, error) {
	if reader != nil {
		return reader.Inspect(ctx)
	}
	return Inspect(ctx, run)
}

// Nftables commits only an owned table in one atomic transaction.
type Nftables interface {
	Apply(ctx context.Context, table, body string) error
	Remove(ctx context.Context, table string) error
	// Installed reports, without running nft, whether our table is present.
	Installed(ctx context.Context, table string) (bool, error)
}

// NFTTableReader probes nf_tables directly for a table and its marker sets.
type NFTTableReader interface {
	Table(context.Context, string) (exists, owned bool, err error)
}

// NFT refuses to replace or delete a table without meshscale's comment. That
// ownership check reads the comment through the nft CLI, which only mutations
// pay for; the idle Installed probe uses netlink.
type NFT struct {
	Run    Runner
	Reader NFTTableReader // nil uses nf_tables netlink
}

func (n NFT) Installed(ctx context.Context, table string) (bool, error) {
	reader := n.Reader
	if reader == nil {
		reader = GoogleNFTReader{}
	}
	exists, owned, err := reader.Table(ctx, table)
	return exists && owned, err
}

func (n NFT) owner(ctx context.Context, table string) (exists, owned bool, err error) {
	out, err := n.Run.Run(ctx, "", "nft", "list", "table", "inet", table)
	if err != nil {
		if strings.Contains(string(out), "No such file") || strings.Contains(string(out), "does not exist") {
			return false, false, nil
		}
		return false, false, fmt.Errorf("inspect nft table %s: %w", table, err)
	}
	return true, strings.Contains(string(out), `comment "`+ownership+`"`), nil
}

func (n NFT) Apply(ctx context.Context, table, body string) error {
	exists, owned, err := n.owner(ctx, table)
	if err != nil {
		return err
	}
	if exists && !owned {
		return fmt.Errorf("nft table %s is not owned by meshscale", table)
	}
	text := ""
	if exists {
		text = "delete table inet " + table + "\n"
	}
	text += "table inet " + table + " {\n comment \"" + ownership + "\"\n" + body + "\n}\n"
	_, err = n.Run.Run(ctx, text, "nft", "-f", "-")
	return err
}

func (n NFT) Remove(ctx context.Context, table string) error {
	exists, owned, err := n.owner(ctx, table)
	if err != nil || !exists {
		return err
	}
	if !owned {
		return fmt.Errorf("refusing to delete unowned nft table %s", table)
	}
	_, err = n.Run.Run(ctx, "", "nft", "delete", "table", "inet", table)
	return err
}

type Link struct {
	Name string `json:"ifname"`
	Info struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
}

func (s Snapshot) tunnelDefault(dev string) bool {
	for _, link := range s.Links {
		if link.Name == dev {
			switch link.Info.Kind {
			case "wireguard", "tun", "tap", "gre", "gretap", "ip6gre", "ip6gretap", "ipip", "ip6tnl", "sit", "vti", "vti6":
				return true
			}
		}
	}
	return false
}
