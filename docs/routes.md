# Subnet routes

A Mesh node can advertise a subnet through Cloudflare's teamnet routes API.
This makes hosts behind that node reachable without enrolling each host.

```sh
meshscale routes advertise 10.0.0.0/24
meshscale routes advertise 10.0.0.0/24,192.168.10.0/24 --node homelab
meshscale routes advertise 10.0.0.0/24 --node homelab --dry-run
meshscale routes list
meshscale status
meshscale routes remove 10.0.0.0/24 --dry-run
meshscale routes remove 10.0.0.0/24
```

Omit `--node` to use this machine's verified Mesh node registration. Otherwise
use a unique node name from `status`; ordinary client devices are not subnet
routers. Host bits are canonicalized (`10.0.0.9/24` becomes `10.0.0.0/24`).
Default routes, IPv4-mapped IPv6, duplicates and CIDRs overlapping Mesh ranges
are rejected. `list` shows all active routes, including customer routes and a
managed flag. `status` shows subnet routes beneath the device table and in each
node's JSON `routes` array.

meshscale labels created routes with `meshscale route: <canonical-cidr>` in the
comment. Advertising an already owned route on the same node is a no-op; exact
collisions on other nodes/virtual networks or unowned routes fail. More-specific
and less-specific routes are permitted; inspect overlaps before advertising.
`remove` accepts one unambiguous owned route and refuses customer routes. A
multi-CIDR advertisement can partially succeed if an API call fails; use
`routes list` and remove the successful creates if necessary.

## Forwarding and return traffic

Use a Linux subnet router. For a local node, meshscale reads forwarding state
and prints the exact fix if forwarding is disabled; it never changes sysctl:

```sh
sudo sysctl -w net.ipv4.ip_forward=1
# For an IPv6 subnet, on a MASQUE node:
sudo sysctl -w net.ipv6.conf.all.forwarding=1
```

For a remote `--node`, run the printed checks on that node. These commands are
for the intended subnet router, never an unrelated workstation or test host.
Configure persistence using your router/OS administration process. Native
userspace mode cannot route subnets. Native TUN uses WireGuard; Cloudflare
requires MASQUE for IPv6 CIDR routes, so use an official MASQUE node for IPv6.
The native backend's own client routes are limited to Mesh IP ranges and do
not automatically gain arbitrary advertised subnets.

**The subnet needs a return route.** If the Mesh node is already the subnet's
default gateway, responses naturally return through it. Otherwise, configure a
static route on the subnet's router (or each destination host):

```text
Destination: 100.96.0.0/12
Next hop:    the Mesh node's LAN/subnet IP, for example 10.0.0.1
```

The route belongs on the subnet gateway and points **to the Mesh node**, whose
own forwarding must also be enabled. Adding it only on the Mesh node does not
teach other subnet hosts where to send replies. Site-to-site routing also needs
return routes for the remote site's subnet.

Both the Mesh node's and clients' device profiles must send the advertised
CIDR through Cloudflare Split Tunnels (Include mode: add the CIDR; Exclude mode:
remove it from exclusions). Check Gateway policies and the subnet's firewall.
Creating an API route alone does not establish end-to-end connectivity.
meshscale does not edit profiles, host routes, forwarding, NAT or firewalls.
Access rules in [rules.md](rules.md) currently govern Mesh device IPs, not
advertised subnet IPs; use separate Gateway network policies for subnet access.

Cloudflare documents the API payload as `network`, `tunnel_id` (Mesh node ID),
and optional `comment`/`virtual_network_id`. Required write permissions include
Cloudflare One Networks Write or Cloudflare Tunnel Write. Published account
limits are 50 Mesh nodes and 50,000 routes shared with Cloudflare Tunnel; no
separate lower Free-plan route limit is listed.

References: [Mesh routes and return routing](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/features/routes/),
[account limits](https://developers.cloudflare.com/cloudflare-one/account-limits/).
