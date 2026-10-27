# Background service

Enroll once with `meshscale up`, then run `meshscale daemon` in the foreground.
The daemon uses the saved backend and the same user/configuration as enrollment.
It never installs or enables itself implicitly.

```sh
meshscale daemon
meshscale daemon --ssh --ssh-port 2222 --ssh-policy /etc/meshscale/ssh.json
meshscale service status
```

For official WARP, it follows `warp-cli --listen status` (with a one-minute
poll as a safety net) and reconnects after a drop.
Startup verifies that the local registration belongs to an active Mesh device
in the selected account; it refuses an unregistered/consumer client. If the
registration changes during its lifetime, it refuses to reconnect it. Linux and
macOS both require Team registration in the selected organization and the safe
Include profile before every connection. WARP must
already be installed and its `warp-svc` running. The daemon does not enroll,
change profiles, or fall back to another backend.

On Linux, each connected check also reconciles the official client's narrow
Tailscale iptables exception, so a recreated `ts-input` chain is repaired within
five seconds. It matches only source `100.96.0.0/12` arriving on `CloudflareWARP`
and returns to the rest of INPUT; it does not disable Tailscale's firewall.
Disconnect, daemon shutdown, and service uninstall remove that exact tagged
rule. `down` saves a pause that prevents automatic reconnection until a valid
explicit `up`; rejected options and failed enrollment preserve it. Unreadable
backend settings also prevent automatic reconnect until repaired. See
[Linux details](linux-host.md).

For native, stop the foreground `up` process first, then run `daemon`. It owns
the existing enrollment's WireGuard transport, TUN/netstack, SOCKS listener, and
native control socket. Another native process holding that state causes an
error. Native refresh/revocation errors stop the daemon explicitly; systemd
restarts it without re-enrolling. Native's existing experimental limitations
still apply; see [native.md](native.md).

Device polling runs immediately and then every 60 seconds. Failures double the
interval up to 15 minutes; the first success restores the normal interval.
`--poll-interval 5s` is useful for container tests. Stable snapshots ignore API
order, online/last-seen changes, and local presentation fields. A device ID,
name, Mesh IP, or owner change runs the registered reconciliation hooks. Failed
hooks are retried; unchanged snapshots perform no Gateway reconciliation or
local device-cache rewrite. DNS reconciliation itself only writes its diff.
External edits to Gateway DNS policies need `meshscale dns sync` unless the
device set changes or the daemon restarts.

SIGINT/SIGTERM cancel polling, close forwarding/SSH sessions and sockets, wait
for workers, and disconnect WARP or close native WireGuard/routes. Enrollment
and saved forwarding survive. `meshscale down` is remembered: the daemon keeps
running but does not reconnect until `meshscale up`, including across reboots.
Running `down` on a managed native transport ends that daemon, and systemd's
restart policy may start it again.

## Linux systemd

Use an installed binary at a stable absolute path. Run enrollment and service
commands under the same root configuration (including `XDG_CONFIG_HOME`, if
set). Credentials must be in that configuration's `dev.env` or saved OAuth
login; shell-only credentials are not embedded into the unit.

```sh
sudo meshscale service install --print     # inspect; no installation
sudo meshscale service install             # explicit enable and start
sudo meshscale service install --ssh       # opt into keyless SSH (saved in the service config)
sudo meshscale service status
sudo meshscale service uninstall           # disable, stop, remove owned unit
```

The generated unit is `/etc/systemd/system/meshscale.service`, runs as root,
sets `HOME`, `XDG_CONFIG_HOME`, `UMask=0077` and `LimitCORE=0`, and restarts on failure.
Installation requires a root-owned executable and protected root-owned parents;
builds in user-owned source directories must first be installed at a stable
system path. Executable paths escape systemd's percent and dollar expansion.
Repeated installation is safe; unrelated units and symlink units are rejected.
Uninstall preserves credentials and configuration. SSH is off by default;
its policy and non-root default are described in [ssh.md](ssh.md).

This combined service deliberately retains the host privileges needed by its
optional modes. `NoNewPrivileges` would also prevent authorized SSH users from
using setuid tools such as `sudo`; `ProtectHome` would hide login homes and saved
credentials; `ProtectSystem=strict` would block exit recovery unit writes.
`PrivateTmp` and address-family/syscall filters would propagate into interactive
SSH commands. A single minimal capability set cannot preserve arbitrary
authorized SSH administration together with netlink/nftables, TUN and raw
network operations. Those restrictions are not enabled in the shared unit.
Splitting SSH session execution from a separately sandboxed network daemon is
future work. Core dumps are disabled to reduce credential disclosure; SSH child
processes inherit that limit. No changed unit has been installed on the live host
as part of this review.

Configuration is stored as mode `0600` in
`<config>/meshscale/service/config.json`, inside a mode `0700` directory:

```json
{
  "ssh": false,
  "ssh_port": 22,
  "ssh_policy": "/etc/meshscale/ssh.json",
  "poll_interval": 60000000000,
  "forwards": [{"port": 9000, "mesh_port": 9000}]
}
```

The stored interval is a Go duration in nanoseconds. Daemon flags override it;
forwarding commands update this configuration through the daemon. Restart to
apply manual configuration changes.

## Local status API

The socket is `<config>/meshscale/service/status.sock`, mode `0600`. Its private
parent and ancestors are checked for ownership, permissions, and symlinks.
Unix filesystem permissions allow only the owning UID and root. A file lock
prevents duplicate daemons. No TCP status listener is opened.

```sh
curl --unix-socket "$HOME/.config/meshscale/service/status.sock" http://meshscale/status
```

`GET /status` returns JSON with mode, backend, connection state/reason, last
successful device sync, sync error, device count, forwards, and whether SSH is
enabled. The `secure` object reports the secure engine state, errors and peer
handshake ages; see [secure mode](secure.md). It contains no tokens or private keys and does not call the account
API when read. `GET /serve`, `PUT /serve` (`{"port":9000,"mesh_port":9000}`),
and `DELETE /serve` are the same-user controls used by the CLI. A foreground
`serve` also exposes this socket, with `mode: "serve"`.

## Device-change hook

Other commands can register a hook during initialization:

```go
devicesync.Default.Register("rules", func(ctx context.Context, s devicesync.Snapshot) error {
    // Use s.Client, s.Account, and stable s.Devices to reconcile owned rules.
    return nil
})
```

`internal/devicesync.Registry` runs hooks by name, attempts every hook even if
one fails, and combines errors. DNS is registered as `dns`. The daemon and the
official `up` path invoke this registry. Native `up` remains an enrollment and
transport-only command; native `daemon` runs the registry. Rules synchronization
is an integration hook, not automatically enabled by this change.

## macOS launchd (generation only)

On macOS, `meshscale service install --print` emits a launchd plist with label
`com.meshscale.daemon`. SSH settings live in the service configuration;
`--print --ssh` is rejected. No launchd job is
installed or loaded by meshscale. Save and review it for a later LaunchAgent or
LaunchDaemon integration, using the same user/configuration as enrollment.
Native enrollment and the current SSH server remain Linux-only; this plist is
not a claim of macOS native support.

See [container evidence](../test/docker/SERVICE.md).

## Status reachability cache

The private control socket serves `POST /reachability` for active device Mesh
IPs. It accepts only `100.96.0.0/12` and `2606:4700:cf1::/48`, limits request
size/count, and uses the socket's existing owner-only permissions. Probe results
are cached for 30 seconds, including negative results; simultaneous status
polls share in-flight work and a 16-worker network limit. Restart an upgraded
daemon to enable this endpoint. See [online status](devices.md#online-status)
for deadlines, fallback ports and JSON provenance.

## Cached inventory and explicit refresh (2026-10-26)

`meshscale status` and `status --json` first read `GET /devices` on the private
Unix control socket. The daemon's existing device poller populates one shared
snapshot immediately and at `--poll-interval` (60 seconds by default, with the
existing failure backoff). Device-sync hooks consume that same snapshot;
there is no additional status polling loop. Registration/device/node inventory,
DNS names, subnet routes, reachability, secure advertisements and SSH mode are
cached together. Connection, secure handshakes and exit state come from the
daemon's current runtime state at read time. The JSON CLI remains a bare array
with additive fields, so existing Swift decoders continue to work.

The daemon reuses the enrollment identity verified at startup for inventory
refreshes. This avoids repeated `warp-cli registration show` calls for listing;
reconnect safety checks still read the real client registration. Routine status
reads invoke neither `warp-cli` nor the Cloudflare API. `status --refresh`
requests `POST /devices`, waits for a bounded live refresh, and prints it.
Concurrent refresh requests share in-flight work; ordinary reads continue to
serve the prior snapshot. Failed refreshes preserve the last successful
inventory and report its timestamp/error. A cold cache returns a warming error;
a responding older daemon must be restarted to expose the new endpoint.

Only a missing/refused daemon socket triggers the direct API path. Permission,
protocol, refresh and warming errors remain visible. The verification flags
`--no-cache` and `--test-stale-ip` deliberately use the direct path; the former
also bypasses persistent association state as before. No private warp-svc
socket protocol was introduced: text and JSON `warp-cli` calls were similarly
fast in this follow-up, and a daemon cache removes the invocation altogether.

The Mac app already runs `status --json` every four seconds while visible and
every 30 seconds otherwise. It benefits when an upgraded daemon is running for
the same user/configuration. Its separate `local-status --json` safety check
still uses live registration/settings and can add latency. The whole Mac UI
refresh has not been benchmarked or deployed here; changing that safety path
belongs to the daemon/event-driven follow-up.

### Foreground SSH mode changes

The private socket also accepts `PUT /ssh` with `{"enabled":false}` or
`{"enabled":true}`. It controls the existing daemon-owned SSH worker for both
foreground and systemd daemons. Disabling cancels that worker and waits for it
to release its listeners before acknowledging; repeated requests are
idempotent. Enabling starts the same managed SSH implementation with the saved
port/policy and its existing failure retry. There is no extra idle timer. The
SSH-mode command owns saving `ServiceSettings.SSH`; this endpoint controls the
running process only. Daemon startup still respects the saved setting, and
shutdown cancels and joins the worker.
