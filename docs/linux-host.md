# Linux host enrollment alongside Tailscale

Historical verification record; personal account, host and resource identifiers in examples are anonymized.

The official Cloudflare One backend is the default. `up` and daemon startup
resolve the selected account's organization and require Team registration in
that organization, WARP mode, and the effective safe Include profile before
connecting. Consumer, Exclude, and broader Tailscale/default-route profiles are
refused. `up --hostname linux-peer` sets the Mesh node name without changing the
host's system hostname.

## Firewall ownership and routing

`internal/linuxnetwork.Manager` owns Linux firewall reconciliation and cleanup.
Its implementation contains all firewall command execution and has injectable
command/interface checks for tests. If both `tailscale0` and `CloudflareWARP`
exist and Tailscale has an iptables `ts-input` chain, it ensures this exact rule
is first in that chain:

```sh
iptables -I ts-input 1 -i CloudflareWARP -s 100.96.0.0/12 \
  -m comment --comment 'meshscale Mesh coexistence' -j RETURN
```

RETURN skips Tailscale's CGNAT anti-spoof drop for this specific ingress and
continues the rest of the host's INPUT processing. It does not accept arbitrary
CGNAT traffic, modify forwarding, create Tailscale's chain/jump, flush rules,
change `tailscale set` preferences, or manage native nftables Tailscale chains.
A missing chain requires no change. Other inspection/mutation failures retain
the underlying error and are reported, including in daemon connection status.

The daemon checks every five seconds and restores a missing owned rule after
Tailscale recreates its iptables chain. `meshscale down` removes the rule through
the official backend's disconnect; daemon shutdown also cleans up. The service
can restore both connection and rule after a later explicit `up`. A saved `down`
prevents reconnect even across daemon restarts. `meshscale service uninstall`
stops the daemon and explicitly cleans the rule even if the daemon had already
exited. Both reconciliation and cleanup
are idempotent. Only the exact tagged rule is removed; unrelated rules remain.

WARP owns its interface, policy rules, and routes. meshscale adds no competing
routes, but it does own one narrow policy-routing exception for overlapping
Tailscale destinations. Both `tailscale0` and `CloudflareWARP` must exist.

Mesh's `100.96.0.0/12` is inside Tailscale's `100.64.0.0/10`. On linux-peer, WARP's
inverted fwmark lookup ran at priority 5209, before Tailscale's table-52 lookup
at 5270. A more specific Tailscale `/32` in another table does not override an
earlier successful policy lookup. WARP therefore captured `100.100.100.100`
(MagicDNS, the first resolver in resolv.conf) and `100.100.0.2`. The lead
observed five-second DNS stalls and temporarily added a priority-5200 rule.

The manager derives the prefix from `meshaddr.IPv4Range`, finds the inverted
marked rule targeting WARP's interface routing table, and installs the equivalent
of:

```sh
ip -4 rule add to 100.96.0.0/12 lookup 52 priority <WARP-priority-minus-one> protocol 243
```

Table 52's peer `/32`s, including MagicDNS, then win. A Mesh destination with no
Tailscale route falls through to WARP. A table-52 default route would capture
Mesh traffic, so reconciliation warns, skips installation, and removes an
existing owned exception when a Tailscale exit node is selected. This is not
support for simultaneous exit-node configurations. An identical address used
by peers in both networks remains ambiguous: this rule prefers Tailscale.

Routing inspection and mutations use an instance-owned netlink handle, with a
nonblocking subscription to link, IPv4 route, and policy-rule notifications.
Unchanged daemon ticks drain notifications without another routing dump or
subprocess; only startup, changes, failed reconciliation, or cleanup require
inspection. Protocol 243 plus the exact prefix/table identifies ownership.
Unrelated operator rules are preserved. `down`, daemon shutdown, and service
uninstall remove the owned rule even after interface removal. Fake-runner table
tests cover lifecycle, priority changes, exit defaults, errors and unchanged
snapshots. An isolated real-kernel namespace verifies route selection and
removal after a default-route event.

Inspect actual selection rather than assuming WARP's priority is fixed:

```sh
ip -details -4 rule show
ip route get 100.100.100.100
ip route get 100.100.0.2
ip route get 100.96.0.6
ip route get 1.1.1.1
```

### macOS overlap assessment (read-only research, 2026-10-26)

The address overlap also exists on macOS, but Linux policy priorities/table 52
do not apply there. WARP Include mode supplies routes for the Mesh prefix;
see [Cloudflare's routing documentation](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/route-traffic/split-tunnels/).
Tailscale's [route-selection code](https://github.com/tailscale/tailscale/blob/main/ipn/ipnlocal/local.go)
prefers a CGNAT aggregate on macOS to avoid costly Network Extension updates,
but normally switches to per-peer routes when another interface uses CGNAT.
Control overrides can change that choice. Its
[route manager](https://github.com/tailscale/tailscale/blob/main/net/routemanager/routemanager.go)
derives the resulting OS route set.

Inference: ordinary longest-prefix selection lets a Tailscale `/32` beat WARP's
`/12`; a remaining Tailscale `/10` would lose inside the Mesh range. Interface
scope, client variant and reconnection order also matter. This is not proof
that the installed Mac has selected the expected routes or that MagicDNS has
its own winning host route. No Mac route, resolver, client, or profile was
changed or inspected during this follow-up. A future attended check should
read `netstat -rn -f inet`, `route -n get 100.100.100.100`,
`route -n get <overlapping-Tailscale-peer>`, and `scutil --dns` with both clients
running. Existing successful SSH to the Mac's Mesh IP proves that path only.

## Remote-host rollback

Before installing, connecting, or changing the service on a remote host, arm a
short systemd timer that stops meshscale, disconnects WARP, and stops warp-svc.
Keep Tailscale enabled and running. Cancel the timer only after an outbound
Internet request, `tailscale status`, and SSH to a known Tailscale peer succeed.
Do not connect an unregistered client to retrieve its profile.

To undo this enrollment's host networking while preserving credentials:

```sh
meshscale service uninstall
meshscale down
```

For emergency recovery, `/root/meshscale-host-rollback.sh` on the tested host
performs the same disconnect and stops warp-svc. To remove the client entirely,
after disconnecting, use `dnf remove cloudflare-warp`; the Cloudflare repository
file is `/etc/yum.repos.d/cloudflare-warp.repo`. Do not remove or stop Tailscale.

## Oracle Linux ARM64 verification, 2026-10-26

Host: `linux-node`, Oracle Linux 9.6 aarch64; Tailscale name `linux-peer`.
Cloudflare's EL9 repository advertised
`cloudflare-warp-2026.8.2115.0-1.el9.aarch64`. Standard `dnf install` could not
resolve desktop WebKit/GTK dependencies because the host already has Fedora 41
ICU/Harfbuzz libraries. No library downgrade or removal was performed.

For this headless host, installed `nss-tools` and `tpm2-tools` with dnf (also
upgrading the EL9 NSS/NSPR packages), imported Cloudflare's signing key, verified
the repository RPM's signature, checked that `warp-cli` and `warp-svc` had no
missing shared libraries, and installed that unchanged official RPM using
`rpm -ivh --nodeps`. Desktop WebKit/indicator dependencies remain unsatisfied;
the GUI is unavailable and future dnf updates may need the same dependency
issue addressed. This is a host-specific packaging workaround, not a native
backend fallback or a general installation recommendation.

Verified results:

```text
warp-cli: 2026.8.2115.0; registration: Team / example-team
meshscale up --backend warp --hostname linux-peer: Connected. Mesh IP: 100.96.0.7
meshscale status: linux-peer (this machine), example-mac, two Docker nodes,
                  two native test nodes, iPhone; seven participants online
100.96.0.6 dev CloudflareWARP table 65743 src 100.96.0.7
100.64.0.2 dev tailscale0 table 52 src 100.64.0.1
1.1.1.1 via 10.0.1.1 dev enp0s6 src 10.0.1.96
ssh alice@100.96.0.6 hostname: example-mac
ssh alice@100.64.0.2 hostname: example-mac
meshscale ssh testuser@meshscale-docker-test hostname: meshscale-docker-test
Cloudflare trace: ip=192.0.2.10, warp=off, gateway=off
Tailscale: Running
meshscale.service and warp-svc.service: enabled, active
```

The host had no `ts-input` chain, so enrollment required no additional host
firewall rule or manual route. The existing firewalld configuration was left
alone. An isolated network namespace with actual iptables and dummy WARP/
Tailscale interfaces verified insertion, no duplicate on repeated setup,
restoration after simulated chain recreation, and exact cleanup after interface
removal. The real tailscaled service was kept running; this test does not claim
a host reboot or a live Tailscale restart was performed.

The final binary also passed a guarded host lifecycle check: stop the daemon,
`meshscale down` (Disconnected), service uninstall (unit absent), `up` (same
registration and `100.96.0.7`), and service reinstall (enabled/active). Mesh SSH,
Tailscale SSH, and direct Internet access passed again afterward; rollback
timers were canceled only after those checks. Formatting, `go vet ./...`, and
`go test -race ./...` passed for the staged implementation in a clean exported
source tree, excluding a concurrent worker's unrelated changes.

## Overlap follow-up verification (2026-10-26)

The priority-5200 operator hotfix is now removed. Under armed four-minute
rollback timers, the deployed daemon recreated its protocol-243 exception and
followed WARP's changed priority: **5198** before WARP **5199**, rather than
assuming the original 5209. MagicDNS `100.100.100.100` and Tailscale peer
`100.100.0.2` resolve through `tailscale0`/table 52; Mesh `100.96.0.6` resolves
through `CloudflareWARP`/65743. Five `getent hosts github.com` subprocesses had a
**9.59 ms median** (maximum 14.14 ms). Internet trace stayed direct
(`192.0.2.10`, warp/gateway off), Tailscale stayed available, and Mesh SSH to
the Mac returned `example-mac`. Each deployment and the manual-rule removal passed
those checks before rollback cancellation. No host default-route/exit-node
experiment or Mac change was needed. Full samples and remaining daemon idle
work are in [status verification](status-verification.md).
