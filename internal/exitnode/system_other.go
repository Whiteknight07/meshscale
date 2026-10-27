//go:build !linux

package exitnode

import (
	"context"
	"errors"
	"net/netip"

	"github.com/Whiteknight07/meshscale/internal/secure"
)

// Exit nodes need Linux netlink and nf_tables. These stubs keep the package
// building elsewhere and fail closed if they are ever reached.

func Inspect(context.Context, Runner) (Snapshot, error) { return Snapshot{}, errors.ErrUnsupported }

func configureSourceAddress(secure.Peer) error { return errors.ErrUnsupported }

func systemPeerRoute() (func(netip.Addr) error, error) { return nil, errors.ErrUnsupported }

// GoogleNFTReader reads nf_tables over netlink, which only Linux has.
type GoogleNFTReader struct{}

func (GoogleNFTReader) Table(context.Context, string) (exists, owned bool, err error) {
	return false, false, errors.ErrUnsupported
}
