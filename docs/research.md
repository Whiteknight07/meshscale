# Research notes (October 2026)

Historical design inputs, not a current vendor support or pricing reference. Verify the linked primary documentation before depending on plan limits, platform behavior, or API availability. Maintained meshscale behavior is described in the [documentation index](README.md).

## How Tailscale works

1. **Control server**: SSO login, gives each device a key, a `100.x.y.z` IP and
   a name, and distributes the peer list and access rules. Never carries traffic.
2. **Data plane**: devices connect directly with WireGuard using NAT traversal;
   if that fails, traffic goes through DERP relays, still end-to-end encrypted.
3. **The feel**: `tailscale up` + browser login, MagicDNS names, `tailscale
   status`, one rules file, one-command subnet routers / exit nodes / Serve /
   Funnel, keyless Tailscale SSH.

## Cloudflare Mesh (formerly WARP Connector), launched 2026-04-14

- Every participant gets a Mesh IP from `100.96.0.0/12`.
- All traffic goes through the nearest Cloudflare data center; no direct
  peer-to-peer. Gateway policies, posture checks and access rules apply to every
  connection, so Cloudflare can see traffic that isn't already encrypted.
- Linux nodes: `sudo warp-cli --accept-tos connector new <TOKEN> && sudo warp-cli --accept-tos connect`.
  User devices: Cloudflare One app + identity provider login.
- Must use MASQUE (not WireGuard) for hostname routes, IPv6 routes and HA.
- Free: 50 users and 50 nodes. Dashboard: Networking > Mesh.
- Vendor capabilities evolve independently; do not treat the original vendor roadmap as an implementation contract.

## Useful API endpoints

| Purpose | Endpoint |
|---|---|
| Create node | `POST /accounts/{id}/warp_connector` |
| Node token | `GET /accounts/{id}/warp_connector/{node_id}/token` |
| Device list with Mesh IPs | `GET /accounts/{id}/devices/registrations` (`virtual_ipv4`, `virtual_ipv6`, `last_seen_at`, `user.email`) |
| Device details (OS etc.) | `GET /accounts/{id}/devices/physical-devices` |
| CIDR routes | `POST/PATCH/DELETE /accounts/{id}/teamnet/routes` |
| Hostname routes | `POST /accounts/{id}/zerotrust/routes/hostname` |
| Device settings | `GET/PUT/PATCH /accounts/{id}/devices/settings` (`use_zt_virtual_ip`) |

## Sources

- https://blog.cloudflare.com/mesh/
- https://developers.cloudflare.com/changelog/post/2026-04-14-cloudflare-mesh/
- https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/get-started/
- https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/concepts/
- https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/features/routes/
- https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/tips/
- https://developers.cloudflare.com/api/resources/zero_trust/subresources/devices/
- https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/use-cases/ssh/ssh-infrastructure-access
- https://tailscale.com/compare/cloudflare-mesh (competitor source)
- https://netbird.io/knowledge-hub/cloudflare-mesh-vs-netbird-vs-tailscale (competitor source)
