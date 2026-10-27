//go:build linux

package exitnode

import (
	"context"
	"fmt"

	"github.com/google/nftables"
)

// GoogleNFTReader probes nf_tables over netlink, without running nft. The
// library cannot read table comments, so "owned" means the table has
// meshscale's marker sets: good enough to confirm our table is still
// installed, but mutations verify the comment through NFT.owner instead.
type GoogleNFTReader struct {
	Open func() (nftTableAPI, error)
}

type nftTableAPI interface {
	ListTablesOfFamily(nftables.TableFamily) ([]*nftables.Table, error)
	GetSets(*nftables.Table) ([]*nftables.Set, error)
}

func (r GoogleNFTReader) Table(ctx context.Context, name string) (exists, owned bool, err error) {
	if err := ctx.Err(); err != nil {
		return false, false, err
	}
	open := r.Open
	if open == nil {
		open = func() (nftTableAPI, error) { return nftables.New() }
	}
	conn, err := open()
	if err != nil {
		return false, false, err
	}
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return false, false, err
	}
	var table *nftables.Table
	for _, candidate := range tables {
		if candidate.Name == name {
			table = candidate
			break
		}
	}
	if table == nil {
		return false, false, nil
	}
	sets, err := conn.GetSets(table)
	if err != nil {
		return true, false, err
	}
	markers := map[string]bool{}
	for _, set := range sets {
		markers[set.Name] = true
	}
	switch name {
	case ForwardTable:
		owned = markers["clients4"] && markers["clients6"]
	case GuardTable:
		owned = markers["identities4"] && markers["identities6"]
	default:
		return true, false, fmt.Errorf("unknown meshscale table %s", name)
	}
	return true, owned, nil
}
