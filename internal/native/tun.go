package native

import (
	"context"
	"net/netip"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/Whiteknight07/meshscale/internal/wgtransport"
)

func createSystemTUN(ctx context.Context, ips []netip.Addr) (tun.Device, func(), error) {
	return wgtransport.CreateTUN(ctx, "meshscale0", ips, tunnelRoutes, MTU)
}
