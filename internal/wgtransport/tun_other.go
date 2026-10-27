//go:build !linux

package wgtransport

import (
	"context"
	"fmt"
	"net/netip"

	"golang.zx2c4.com/wireguard/tun"
)

func CreateTUN(context.Context, string, []netip.Addr, []string, int) (tun.Device, func(), error) {
	return nil, nil, fmt.Errorf("system TUN requires Linux")
}
