package exitnode

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeNFT emulates the nft CLI for one table: missing, foreign or owned.
type fakeNFT struct {
	state   string
	commits []string
}

func (f *fakeNFT) Run(_ context.Context, input, _ string, args ...string) ([]byte, error) {
	if len(args) > 0 && args[0] == "list" {
		switch f.state {
		case "owned":
			return []byte("table inet t {\n\tcomment \"" + ownership + "\"\n}\n"), nil
		case "foreign":
			return []byte("table inet t {\n}\n"), nil
		}
		return []byte("Error: No such file or directory"), errors.New("exit status 1")
	}
	f.commits = append(f.commits, strings.Join(args, " ")+"\n"+input)
	return nil, nil
}

func TestNFTOwnership(t *testing.T) {
	for _, tc := range []struct {
		state                 string
		applyFails, rmFails   bool
		applyDeletes, removes bool
	}{
		{state: "missing"},
		{state: "owned", applyDeletes: true, removes: true},
		{state: "foreign", applyFails: true, rmFails: true},
	} {
		t.Run(tc.state, func(t *testing.T) {
			run := &fakeNFT{state: tc.state}
			err := NFT{Run: run}.Apply(t.Context(), ForwardTable, "chain x {}")
			if (err != nil) != tc.applyFails {
				t.Fatalf("apply: %v", err)
			}
			if tc.applyFails {
				if len(run.commits) > 0 {
					t.Fatal("modified a foreign table")
				}
			} else if len(run.commits) != 1 || strings.Contains(run.commits[0], "delete table inet "+ForwardTable) != tc.applyDeletes {
				t.Fatalf("not one atomic transaction: %q", run.commits)
			}
			run.commits = nil
			err = NFT{Run: run}.Remove(t.Context(), ForwardTable)
			if (err != nil) != tc.rmFails || (len(run.commits) == 1) != tc.removes {
				t.Fatalf("remove: err=%v commits=%q", err, run.commits)
			}
		})
	}
}

func TestNFTInstalledNeverRunsNFT(t *testing.T) {
	run := &fakeNFT{state: "owned"}
	for _, tc := range []struct {
		reader fakeNFTTableReader
		want   bool
	}{{fakeNFTTableReader{}, false}, {fakeNFTTableReader{exists: true}, false}, {fakeNFTTableReader{exists: true, owned: true}, true}} {
		if got, err := (NFT{Run: run, Reader: tc.reader}).Installed(t.Context(), ForwardTable); err != nil || got != tc.want {
			t.Fatalf("Installed(%+v) = %v, %v", tc.reader, got, err)
		}
	}
	if len(run.commits) > 0 {
		t.Fatal("Installed ran nft")
	}
}

type fakeNFTTableReader struct {
	exists bool
	owned  bool
	err    error
}

func (f fakeNFTTableReader) Table(context.Context, string) (bool, bool, error) {
	return f.exists, f.owned, f.err
}
