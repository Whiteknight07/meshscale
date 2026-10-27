//go:build linux

package exitnode

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/nftables"
)

type fakeNFTAPI struct {
	tables []*nftables.Table
	sets   map[string][]*nftables.Set
	err    error
}

func (f fakeNFTAPI) ListTablesOfFamily(nftables.TableFamily) ([]*nftables.Table, error) {
	return f.tables, f.err
}
func (f fakeNFTAPI) GetSets(table *nftables.Table) ([]*nftables.Set, error) {
	return f.sets[table.Name], f.err
}

func TestGoogleNFTReaderUsesMarkerSets(t *testing.T) {
	for _, tc := range []struct {
		name  string
		sets  []string
		exist bool
		owned bool
	}{
		{name: ForwardTable, sets: []string{"clients4", "clients6"}, exist: true, owned: true},
		{name: GuardTable, sets: []string{"identities4", "identities6"}, exist: true, owned: true},
		{name: ForwardTable, sets: []string{"other"}, exist: true},
		{name: ForwardTable},
	} {
		t.Run(tc.name+"/"+strings.Join(tc.sets, ","), func(t *testing.T) {
			table := &nftables.Table{Name: tc.name, Family: nftables.TableFamilyINet}
			sets := make([]*nftables.Set, 0, len(tc.sets))
			for _, name := range tc.sets {
				sets = append(sets, &nftables.Set{Name: name})
			}
			api := fakeNFTAPI{sets: map[string][]*nftables.Set{tc.name: sets}}
			if tc.exist {
				api.tables = []*nftables.Table{table}
			}
			reader := GoogleNFTReader{Open: func() (nftTableAPI, error) { return api, nil }}
			exists, owned, err := reader.Table(context.Background(), tc.name)
			if err != nil || exists != tc.exist || owned != tc.owned {
				t.Fatalf("Table() = %t, %t, %v", exists, owned, err)
			}
		})
	}
}

func TestGoogleNFTReaderPropagatesReadErrors(t *testing.T) {
	want := errors.New("nft netlink failed")
	reader := GoogleNFTReader{Open: func() (nftTableAPI, error) {
		return fakeNFTAPI{err: want}, nil
	}}
	_, _, err := reader.Table(context.Background(), ForwardTable)
	if !errors.Is(err, want) {
		t.Fatalf("error=%v", err)
	}
}
