# Linux exit nodes

An exit node forwards selected clients' Internet traffic through an authenticated
WireGuard tunnel over Cloudflare Mesh. Selection is explicit per Linux client.
The selected exit can see traffic without application encryption; the account
and its API remain the public-key trust root described in [secure mode](secure.md).

## Commands and prerequisites

Linux root clients and exits use kernel WireGuard. The private netstack and the
explicit Go engine are rejected for exit roles; ordinary secure mode retains
both. macOS remains gated. Selection does not change other devices' profiles or create account-wide public
CIDR routes. Administrator-managed Mesh public-CIDR
routes remain a possible future Mac/phone path, subject to the account/profile
limitations below.

```sh
# Exit prerequisites (administrator action, only if not already enabled):
sysctl -w net.ipv4.ip_forward=1
# IPv6 egress additionally requires a working physical IPv6 default and:
sysctl -w net.ipv6.conf.all.forwarding=1
# Preserve accept_ra=2 where the IPv6 uplink depends on RA.
meshscale up --advertise-exit-node
# On an already running secure daemon:
meshscale set --advertise-exit-node=true
meshscale set --advertise-exit-node=false

# Client; this also enables secure mode:
meshscale set --exit-node=my-exit
meshscale set --exit-node-allow-lan-access=true
meshscale set --exit-node=                  # explicit return to direct Internet
meshscale status
meshscale service status                  # local desired/active/error JSON
```

Forwarding sysctls are checked prerequisites. meshscale does not rewrite already
enabled global settings or restore them over another forwarder's requirements.
Use `--userspace=false` if a previous configuration requested the private stack.
Selection and advertisement on the same host are rejected.

## Identity and authorization

The directory extends existing records with exit version 2, a capability, and an
account/key-derived IPv4 `/32` in `10.192.0.0/10`. Discovery checks the binding and
collisions; host setup rejects overlaps rather than stealing an existing route.
This is a host address, never a subnet claim. The existing ULA identity remains
mandatory. Default AllowedIPs need local selection pinned to registration ID and
public key; client ingress rejects the local or unknown secure identity sources; name reuse, changed keys, withdrawal or discovery failure cannot
select a replacement. Forwarded sources come only from authenticated secure
peers whose authoritative registration owner matches the exit's owner.

## Routing, leak guard and recovery

`internal/exitnode` separates route planning, command execution, nftables and
forwarding prerequisites. It allocates unused table pairs and policy priorities,
records ownership in private state, and tags rules with protocol 242. It copies
existing Mesh/WARP and Tailscale destinations, preserves their carrier marks,
pins active SSH management paths, and adds connected LAN prefixes only when
requested. The main default is preserved. Terminal unreachable defaults and
independent owned nft output and forward guards remain when the selected peer
or engine is lost. Exact API/auth HTTPS destinations and existing resolver DNS
traffic are compatibility exceptions; the complete current exception list appears in local
status JSON. With systemd-resolved's stub, upstream resolver addresses are read
from `/run/systemd/resolve/resolv.conf`; DNS routing exceptions match only those
allowed resolver destinations. Resolver configuration is never rewritten.
Unchanged selections recheck owned policy rules, terminal/exception routes and
the guard table over netlink, restoring resources lost during network changes.

The recovery unit is written before its dependency drop-ins; owned drop-ins are
removed on deselection even if the unit is missing. A systemd recovery unit
atomically restores the persisted nft guard before normal network startup. Owned
dependency drop-ins require successful guard startup for NetworkManager, systemd-networkd, WARP, Tailscale and meshscale, so a failed
restore cannot silently start those network services. In a container without systemd, the runtime guard survives daemon loss;
its network-namespace lifecycle owner must load `secure/exit-guard.nft` **before
networking** on recreation. Automatic Docker recreation/early-boot behavior has
not been validated. Explicit deselection removes owned capture, guard and
recovery state. Client daemon shutdown intentionally retains the guard.

## Exit forwarding and firewall

The client forward guard also protects container/VM egress; established replies
arriving through `meshsecure0` may return to those clients. The guard applies only
to the client role. The exit chooses the lowest-metric physical default per IP
family and owns `inet meshscale_exit_v2`: authenticated source sets, source/uplink
scoped IPv4 masquerade and NAT66 where IPv6 forwarding/uplink are ready, private/
metadata/LAN destination rejection, established returns, counters and two-way
MSS caps that only lower MSS. Input protection also prevents the exit role from
exposing the host’s private interface addresses through the tunnel. MTU/MSS reuse secure mode's carrier calculation;
there is no userspace packet or connection forwarding, and no packet/connection
API lookup. If IPv6 forwarding/uplink is unavailable, client IPv6 stays blocked.
An active firewalld is checked for matching tunnel/uplink zones with intra-zone
forwarding. meshscale does not reload firewalld, create permanent policies, or
modify administrator zones. Unsupported zone layouts require explicit operator
configuration; unrelated tables/zones are preserved. Transport close removes forwarding/NAT; the existing interface-
generation guardian also removes exit resources on daemon-only death. `down`
withdraws an exit and disables its secure engine; service stop/uninstall uses
transport/guardian cleanup. Whole-group SIGKILL remains the existing guardian
limitation described in `docs/secure.md`.

## Status

Status adds `offers_exit_node`, `exit_node`, `exit_state`, LAN policy and resolver
fields to JSON and an EXIT NODE column to text. A recent WireGuard handshake is
explicitly labelled **egress not probed**, not evidence of public egress. macOS clients do not route through these Linux exit nodes.

## Verification and limits

Normal Go tests cover owner/selection consent, versioned IPv4 bindings,
AllowedIPs, resource conflicts, WARP/Tailscale coexistence, LAN behavior,
firewall ownership, forwarding prerequisites and status. The opt-in kernel test
creates anonymous client, exit and Internet network namespaces before changing
any routes or firewall rules:

```sh
MESHSCALE_EXIT_NETNS_TEST=1 go test -run '^TestLinuxExitDataPath$' ./internal/exitnode
```

Run privileged network checks only in a disposable environment. The test uses
kernel WireGuard and nftables to check IPv4 masquerade, IPv6 NAT66, authenticated
identity, rejection of forged inner identities, loss of either tunnel interface,
independent guard enforcement after policy-route removal, and explicit
deselection restoring direct traffic. Historical Linux live tests also exercised
advertisement withdrawal and daemon restarts. No privileged host-network test
was run during this OSS hardening review. Reboot recovery and arbitrary
network-manager/firewall combinations remain target-environment checks.

DNS keeps the existing resolver and its routing exception, so resolver traffic
can leave outside the selected exit. API/auth HTTPS, WARP carrier/probe traffic,
existing SSH management peers, essential DHCP/IPv6 neighbor discovery and
explicitly permitted Mesh/Tailscale/LAN paths are also exceptions. The guard is
not intended to hide these flows. `exit_node_exceptions` exposes the planned
destination exceptions; read it before relying on exit selection.

Cloudflare public-CIDR routes are a separate account-level routing facility.
They need client Split Tunnel capture and Linux forwarding/return routing; they
do not provide this per-client pinned selection or its local guard. End-to-end
`0.0.0.0/0` / `::/0` Mesh route support is unverified. This implementation creates
no such account-wide default. See [subnet routes](routes.md) for route management.
