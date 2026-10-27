//go:build !linux

package secure

import (
	"context"
	"fmt"
	"net/netip"
)

func startKernel(context.Context, Key, netip.Addr, netip.Addr, int) (wireGuardDevice, func(), error) {
	return nil, nil, fmt.Errorf("kernel WireGuard requires Linux")
}

func restrictCarrier(context.Context, netip.Addr) (func(), error) {
	return nil, fmt.Errorf("secure system carrier requires Linux")
}
