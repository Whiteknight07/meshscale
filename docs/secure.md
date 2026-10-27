# Secure mode: WireGuard over Mesh

Secure mode adds device-to-device WireGuard encryption inside Cloudflare Mesh.
Cloudflare carries UDP ciphertext between Mesh IPv4 addresses; it can still see
endpoints, timing, packet sizes and the public-key directory. Traffic to ordinary
Mesh addresses remains ordinary Mesh traffic. Use secure addresses or `.secure`
names when encryption is required. Phones retain plain Mesh.

## Commands and platform support

Use the same user and configuration for enrollment, the daemon and all commands.
Linux with the official Cloudflare One backend is the default:

```sh
meshscale up --secure                 # enroll/connect, then foreground daemon
# Or enable it in an already running daemon:
meshscale set --secure=true
meshscale set --secure=true --userspace
meshscale set --secure=true --userspace=false --secure-engine=go # force wireguard-go
meshscale set --secure=true --userspace=false --secure-engine=auto # prefer kernel
meshscale daemon --ssh --ssh-port 2222

meshscale status
meshscale status --json
meshscale ping --port 2222 server.secure
meshscale ssh --port 2222 alice@server.secure hostname
meshscale set --secure=false          # preserve the local key and address
```

`up --secure` stays in the foreground until stopped. An existing systemd service
can instead apply `set --secure=true` without another daemon. Settings changes
are checked every five seconds. Peers refresh at `--poll-interval` (one minute by
default), independently of ordinary device-change fingerprints. `down` records the disconnected preference, so a managed
service stays disconnected until the next explicit `up`.
Disabling withdraws this registration's enabled key record, including when the
daemon is stopped; withdrawal failures are reported after saving the local
setting and can be retried. Stopping a daemon preserves its published capability
for its next start; it does not claim that the device is online.

Root on Linux creates an exclusive `meshsecure0` TUN and adds only
`fd6d:6573:6873::/48`. Root prefers the Linux kernel WireGuard module, configured through
wgctrl/netlink. If unavailable it falls back to wireguard-go with a real TUN.
`--secure-engine=kernel` requires the kernel; `go` forces the fallback for testing.
The native userspace Mesh carrier uses wireguard-go, since a kernel device cannot
send through that private stack. Existing interface/route conflicts fail without replacing
anything. There are no default-route, DNS, forwarding or NAT changes. A scoped IPv6
OUTPUT TCPMSS rule advertises the computed MSS on `meshsecure0`; cleanup removes
only that rule. Kernel/TUN mode therefore also requires `ip6tables`; both modes also require
`iptables` to restrict its UDP carrier to the local Mesh IPv4 destination and
Mesh IPv4 sources, dropping IPv6 carrier datagrams on this exclusive port. The
kernel lifetime guardian removes its dedicated carrier chains and then its
interface on daemon exit. It acts only while its own interface generation still
exists: a new daemon cannot start until that link is gone, so a late guardian can
never remove a replacement daemon's chains. Any chain left by a failed cleanup is
rebuilt on the next start. Addresses
use `noprefixroute`: only the explicit overlay `/48` is added to the main table,
alongside the unavoidable local-table address entry. Ordinary
applications can use the numeric secure IPv6 addresses shown by `status`.
The underlying official/native Mesh connection retains its own routing behavior.

Non-root automatically uses a private gVisor netstack. Root can explicitly choose
`--userspace` (also supported by `up --secure --userspace`) when TUN privileges or
iproute2 are unavailable. This mode adds no host interfaces/routes. Its TCP dial
and listener leases are available to `meshscale ssh`, `ping`, and `sshd`; arbitrary
host applications do not automatically enter that stack. Rootless SSH serves
only the daemon user's UID/GID; choose an unprivileged port when required by the
system. Native userspace Mesh also carries secure UDP inside its existing stack;
`up --backend native --secure --userspace` retains native's experimental status.

macOS secure mode is explicitly gated: the current app/helper does not own a
secure tunnel lifecycle or authenticated packet listener. Plain macOS Connect
is unchanged. Swift's optional `secure` peer field reads Linux peer status;
there is no Mac secure toggle. Windows and phones are unsupported for secure
mode. A future Mac helper/Network Extension must provide interface-bound
listeners and preserve VPN coexistence before removing the gate.

## Keys, account directory and trust

`<config>/meshscale/secure/wireguard.json` stores a locally generated X25519
private key with mode `0600` inside an owner-only `0700` directory. Standard Go
X25519 and wireguard-go implement the cryptography. Atomic persistence, private
path checks and a separate key lock prevent accidental replacement or symlink
adoption. Invalid/insecure existing keys fail rather than regenerate. Only the
public key leaves the device; key replacement changes the secure address.

Distribution uses the user's own Cloudflare Gateway lists, accessed directly by
Go REST with the existing `teams.write` OAuth grant (or equivalent API token
permissions). No Worker, third-party server, KV/D1 resource, additional OAuth
scope or control-plane deployment is needed. The
[Gateway list API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/gateway/subresources/lists/)
provides list names/descriptions and account-scoped create/update/list operations.
API-token checks on 2026-10-26 verified write/readback/idempotency and real peer
discovery. OAuth-specific live access remains unverified; API-token success does
not verify that grant. An operator can run the opt-in OAuth check after signing
in, using the live-check variables described below.

Each registration owns one IP-type list named
`meshscale-secure-v1-<registration-id>`. Its description has a version marker and
JSON `{registration_id, public_key, enabled}`. Its illustrative Mesh-IP item is
never trusted for identity or routing. Different registrations update different
resources; similarly named unowned lists are never adopted during publication. Discovery
skips malformed records with warnings. All entries sharing a duplicate name are
excluded, so ordering cannot select one key and one broken registration cannot
disable unrelated registrations. A conflicted local registration still cannot
publish or run. Warnings appear in daemon secure status and CLI status output. Lists are not referenced by traffic rules. They consume the account's
Gateway-list quota; disabled records are retained to preserve auditability and
may be removed by the owner once no longer needed.

Discovery joins enabled records to active, non-revoked/non-deleted account device
registrations. Mesh endpoints, names, owners and device identity come from live
registration/node APIs, not from editable list items. Duplicate keys, addresses,
registrations and ambiguous Mesh endpoints are rejected. Authorization failures
and a missing local record close the secure engine/listener leases. Transient
control-plane failures retain the last known peers with a warning; revocation is
enforced on the next successful refresh. The daemon retries with bounded
contexts. It never silently dials a plain address for a `.secure` target.

The account owner and Cloudflare's authenticated API are the trust root for
public keys. An account administrator or compromised account token can replace
keys; this does not provide Tailnet Lock or protection against a malicious key
service. Revoking the underlying registration removes it from discovery. An
`enabled:false` record is a capability withdrawal, not permanent revocation: a
device still locally configured as enabled may publish again on restart. Stop
or disable that device, revoke its registration/account access, or later add
signed enrollment controls when permanent exclusion is needed.

## Addresses, names and MTU

The IPv6 ULA prefix is `fd6d:6573:6873::/48`. The remaining 80 bits are derived
from SHA-256 over a domain separator, account ID and public key. This is stable
across restarts and Mesh-IP changes, account-separated, and disjoint from
Tailscale's `100.64.0.0/10`, Mesh's `100.96.0.0/12`, and their public IPv6 ranges.
Collisions are rejected rather than assigned ambiguous identities. Each peer
has exactly its own `/128` in WireGuard AllowedIPs; peers cannot choose source
addresses belonging to other keys.

Deterministic device names use the existing name allocator with suffix
`.secure` (including its collision disambiguation). `meshscale ssh` and `ping`
resolve these through the running daemon's peer snapshot. These are CLI names,
not system DNS records; use numeric secure IPs in other applications. `.mesh`
continues to mean the plain Mesh address. `ping` is a timed TCP connection probe,
defaulting to port 22, not an ICMP echo. The destination must have that port open.

WireGuard listens on UDP **51821**. Peers' numeric IPv4 endpoints are restricted
to the Mesh range. OS carriers use the kernel socket or upstream `StdNetBind`
(wildcard UDP listeners, with the Mesh route selecting egress/source), retaining
batched recvmmsg/sendmmsg and supported UDP GSO/GRO. The Go receive wrapper
checks the Mesh source range and available local-destination packet info before
WireGuard processes a datagram, normalizing IPv4-mapped socket addresses without
allocation. This upstream version's UDP-GRO splitter omits packet info on split
messages, so kernel/TUN modes also enforce destination scope using the INPUT
drops described above. Private stacks retain their authenticated WireGuard
key/AllowedIPs identity boundary without requiring privileged host firewall changes. Native userspace carriers use
`PacketBind`, caching configured endpoint objects and avoiding address-to-string
conversion on the receive path. Unknown unauthenticated sources are not cached.
TUN creation uses upstream wireguard-go's VNET_HDR path, enabling TCP GSO/GRO and
UDP segmentation/GRO where supported. Live `ethtool -k meshsecure0` confirmed
TCP/IPv6 segmentation, generic segmentation/receive offload, and UDP segmentation.

MTU is computed from `CloudflareWARP` (or native `meshscale0`); an inaccessible
private carrier conservatively assumes 1280. WireGuard-over-IPv4 adds **60 bytes**:
20 IPv4 + 8 UDP + 16 WireGuard data header + 16 authentication tag. The often
quoted 80-byte overhead applies to an IPv6 *outer* carrier; the inner IPv6 header
is already inside the inner packet size. Budget is rounded down to 16 bytes for
WireGuard padding. In the measured Linux test environment the carrier MTU was **1300**, giving
`floor16(1300 - 60) = 1232`. IPv6 requires an interface MTU of at least **1280**,
so the interface retains 1280 and TCP MSS is clamped to **1172** (`1232 - 40 - 20`).
TCP timestamps reduce application payload further. Kernel/TUN endpoints advertise
this MSS with a scoped OUTPUT rule; the private netstack clamps SYN options in
both directions with an allocation-free incremental checksum update.

This avoids fragmentation for the measured TCP traffic: a 162,436-packet live
capture had zero IPv4 fragments and a maximum outer IP size of **1292**. It cannot
guarantee fragmentation-free arbitrary large UDP/ICMP on a 1300-byte carrier:
1280 + 60 exceeds 1300. Raising the underlay MTU or changing the address family
would be necessary for that guarantee; secure mode does neither.

Persistent keepalive is **off**: Mesh endpoints are directly routed and require
no additional NAT mapping. Traffic initiates the handshake. Peer refresh diffs
keys/endpoints/AllowedIPs and applies only changes, retaining the existing device
and unchanged peer handshake state. Metadata-only changes do not rewrite WG.
Status reports each peer's last-handshake age; no handshake means no successful
handshake has yet been observed, rather than proof of a failed peer.

## Gateway and local access policy

When an explicit meshscale access-rules file is synced, its compiler places an
allow rule for UDP/51821 **between enabled active secure peers' Mesh /32s** ahead
of meshscale's default deny. It leaves customer policies untouched. At least two
secure participants are required. With no rules file the existing Gateway
configuration is left alone; default-allow accounts need no extra rule. If
another administrator installed a restrictive policy, that administrator must
sync the secure-aware rules or explicitly allow this carrier. Gateway changes
can take time to propagate. No live traffic policies were changed for validation.

Cloudflare cannot inspect or enforce inner ports in encrypted packets. The
carrier rule therefore permits all overlay traffic between secure participants,
subject to endpoint firewall/application authorization; it does not translate
per-port Gateway ACLs into an encrypted local firewall. Deploy local policy
before exposing sensitive services. `serve` continues to bind plain Mesh.

Secure SSH accepts key identity only on a trusted WireGuard listener. Source
secure IP maps to the installed key's account-derived `/128`, then to a live
device registration. Linux system listeners use `SO_BINDTODEVICE=meshsecure0`;
userspace listener leases preserve addresses through the private same-UID Unix
socket. A secure-looking source on a plain listener cannot claim key identity.
On a secure server, peers advertising secure mode cannot downgrade to Mesh-IP
identity; non-secure phones/peers retain the existing plain fallback. SSH policy
is still enforced locally, with a 15-second identity cache and rechecks on new
session channels. Secure identity loads use the daemon's installed in-memory peer
snapshot over its private local socket; they make no Cloudflare API calls.
Concurrent cache misses share one bounded refresh outside the mutex; waiting
callers can cancel independently. Failed loads never reuse expired peers.
Account edits are observed on the next peer refresh (one minute by default,
with a bounded 45-second refresh context), then authentication metadata can lag
by the local 15-second cache. Removing a WG peer immediately removes its data
path key when that refresh is applied; the cache is not an independent
15-second Cloudflare revocation poll. Existing running sessions are not terminated by account edits.

`GET /status` on the private service socket includes `secure` with `enabled`,
`running`, `userspace`, `mode` (kernel/go/gvisor), `mtu`, `tcp_mss`, `ip`, `error`,
`warnings`, and peer key/address/handshake details.
Private keys are excluded from all status responses and logs.

## Verification and extension points

`go vet ./...` and `go test -race ./...` cover key persistence/permissions,
addressing, directory pagination/idempotency, discovery/revocation, carrier rules,
SSH identity/downgrade rejection, daemon failure/recovery/disable, listener
cancellation, and real WireGuard TCP/IPv6 traffic across independent netstacks.
An authenticated key sending another peer's source address is rejected by
WireGuard. A nested native-Mesh simulation tests double encapsulation.

Secure and native userspace transports share a locally patched, MIT-licensed
WireGuard netstack adapter. Its TUN reads directly from gVisor's synchronized
packet queue, so background TCP/UDP output cannot send to a channel being closed
during shutdown. Late inbound TUN writes are rejected after close. The patch's
origin and maintenance notes are in
[`internal/wgtransport/netstack/README.md`](../internal/wgtransport/netstack/README.md).
The shutdown regressions and nested transport can be stressed without host
network changes:

```sh
go test -race -run '^TestNetstack' -count=10 ./internal/wgtransport
go test -race -run '^TestWireGuardOverUserspaceMesh$' -count=200 ./internal/secure
```

The opt-in Linux TUN check was run in a disposable Docker container with a
separate network namespace, `--network none`, `CAP_NET_ADMIN`, and `/dev/net/tun`.
It verifies encrypted userspace-to-TUN TCP, interface-bound listening, preserved
source identity and cleanup. Run **only in an isolated namespace**:

```sh
CGO_ENABLED=0 go test -c -o /tmp/meshscale-secure-test ./internal/secure
# In a disposable Linux container with iproute2 and the above capabilities:
MESHSCALE_TEST_SECURE_TUN=1 /secure.test -test.run TestSecureLinuxTUN -test.v
```

Carrier-chain and guardian cleanup can also be checked without connecting a
carrier or changing host networking. Run in private network and mount namespaces;
the sysfs mount makes the guardian's interface-index check refer to the test
namespace. This requires Linux namespace/mount privileges and iptables/nft:

```sh
MESHSCALE_LIVE_CARRIER=1 unshare --mount --net --propagation private sh -c \
  'mount -t sysfs sysfs /sys && exec go test -race -run "^(TestCarrierRulesLive|TestKernelGuardianLive)$" ./internal/secure'
```

The opt-in `MESHSCALE_LIVE_SECURE_CHECK=1 go test -run TestLiveSecureDirectory -v
./cmd/meshscale` permits only a disabled test Gateway-list record to be written.
It does not enroll devices, sync policies, change routes, or modify host
networking. Cloudflare peer-to-peer secure traffic was live-tested on 2026-10-26 as below.
The Mac was used only for the explicitly requested SSH `hostname` safety check.

## Performance and explicit tuning

Linux host routes owned by meshscale now prefer `congctl bbr`: the secure
`fd6d:6573:6873::/48` route on each host, secure IPv4 peer routes, and the
selecting client's IPv4/IPv6 exit defaults in its owned policy table. This
changes locally originated TCP whose route matches. It does **not** change
congestion control for packets forwarded by the exit. The code attempts to load
`tcp_bbr` if the route request fails, then falls back without preventing secure
startup. `meshscale status` and local service JSON report the installed secure
route algorithm or `kernel default (per-route BBR unavailable)`. The global TCP
default stays cubic; route removal removes the preference. No qdisc changes are
shipped: the earlier fq measurements did not establish a reliable improvement.

`meshscale tune --warp-buffers` is an explicit Linux-root operation that uses
`pidfd_getfd` and SO_RCVBUFFORCE only on existing connected warp-svc UDP/443
sockets. It records PID/start-time, FD, inode and original kernel readback sizes
before mutation in the private `tuning/warp-buffers.json`. Defaults only discover
warp-svc in the caller's network namespace; `--warp-pid PID` explicitly chooses
another visible WARP process. It needs CAP_SYS_PTRACE and CAP_NET_ADMIN.

```sh
# Arm an independent rollback before any live tuning:
systemd-run --unit=meshscale-buffer-rollback --on-active=4min \
  /usr/local/bin/meshscale tune --warp-buffers --undo
meshscale tune --warp-buffers
# After measuring and checking Internet / Tailscale / Mesh SSH:
meshscale tune --warp-buffers --undo
systemctl stop meshscale-buffer-rollback.timer
```

The target is **8 MiB kernel readback** (a 4 MiB setsockopt request). Apply is
transactional, refuses to overwrite recorded originals, and restores on failure.
Undo is idempotent and ignores closed/replaced sockets; failed restoration keeps
the recovery record. WARP reconnect/restart discards tuning and is not followed
automatically. No rmem/wmem ceiling/default, TCP default or another process's
socket is changed by normal daemon startup or service installation.

Live Linux checks on 2026-10-26 exercised kernel WireGuard, wireguard-go TUN and
gVisor, verified encrypted TCP/SSH and source identity, and checked the carrier
for the absence of a known plaintext marker. The endpoints shared physical
hardware and a Cloudflare hairpin; those measurements do not establish a
universal throughput target. Background load, TCP proxying on ordinary Mesh,
MTU/MSS and WARP receive buffers affect comparisons.

The guardian removes its interface and carrier/MSS rules after daemon-only
exit, including SIGKILL. Killing both daemon and guardian with SIGKILL defeats
that userspace cleanup; an orphaned interface requires explicit operator cleanup
before restart. Existing interfaces are conflicts and are never silently adopted.
System reboot recovery and arbitrary network-manager/firewall configurations need
validation in the target environment. See [exit nodes](exit-nodes.md) for the
separate selected-exit guard and its recovery behavior.
