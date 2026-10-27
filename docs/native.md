# Experimental native backend

Cloudflare One (`warp-cli`) remains the default. Native is an explicit opt-in
that registers a Mesh node and runs wireguard-go inside meshscale, without a
Cloudflare application. Enrollment and transparent TUN networking are currently
Linux-only. The userspace transport library also builds for macOS; macOS
node enrollment and OS integration are not implemented.

On first enabling native for a CLI configuration, meshscale prints exactly:

> WARNING: The native backend is experimental. It is not a Cloudflare-documented forwarding mechanism under Cloudflare Zero Trust terms §6. It uses an undocumented device API that may change or break without notice. Use it only if you accept these risks.

The warning acknowledgement is recorded in `backend.json`. Native is not a
supported replacement for all Cloudflare One features: credential renewal,
posture, captive portals and endpoint failover are absent. WireGuard does not
provide Mesh hostname routes, IPv6 CIDR routes or HA. IPv6 addresses and routes
are configured; the integration tests below validate IPv4 application traffic.

## Connect

Use an already configured Mesh account (see `meshscale setup` and its dashboard
reachability step), with API credentials or an OAuth login for the user running
the daemon. Native `up` creates only its own Mesh node and device registration.
It does not run account setup or automatically write Gateway DNS rules.

For transparent Linux networking, run as root with iproute2 and `/dev/net/tun`:

```sh
meshscale up --backend native --hostname my-linux-node
```

This is a **foreground daemon**. Keep it running in a terminal, or run that same
command under a service manager. It creates `meshscale0`, sets MTU 1280, assigns
the returned IPv4 `/32` and IPv6 `/128`, and adds only these destination routes:

- `100.96.0.0/12`
- `2606:4700:cf1::/48`

It never changes default routes, DNS, forwarding or firewall settings. Existing
`meshscale0` interfaces or conflicting routes cause an error, rather than being
replaced. Closing the daemon removes its interface and routes. Ordinary SSH,
curl and ping use the TUN; service-specific ICMP policy can still affect ping.

For a rootless private network stack:

```sh
meshscale up --backend native --userspace --hostname my-userspace-node
# In another terminal, under the same user/configuration:
curl --http0.9 --socks5 127.0.0.1:1080 http://100.96.0.2:8080/
meshscale ssh testuser@100.96.0.2 whoami
meshscale sshd
```

`--socks 127.0.0.1:1080` changes the local SOCKS5 port. Only SOCKS5 CONNECT to
numeric Mesh IPs is supported; there is no general Internet proxy, UDP ASSOCIATE
or proxy DNS resolution. `meshscale ssh` still resolves device names through
Cloudflare's account API, then dials the daemon's netstack directly. It pins SSH
host keys in the user's private meshscale `known_hosts`: new keys are saved,
changed keys are rejected. Interactive shells use a PTY; window resizing is not
yet forwarded. Agent, X11 and TCP forwarding are not enabled.

`sshd` listens through the same netstack, retaining the real source Mesh IP for
account identity and policy checks. An unprivileged server can execute sessions
only as its own local UID/GID. Its private host key defaults to `<native-state>/ssh`.
A root server can switch users under the existing root-owned SSH policy and host
key rules (`--policy`, `--state-dir`). The missing-policy default still allows
account participants to access non-root users, restricted to the server user in
rootless mode. Use an explicit SSH policy to narrow access.

## Lifecycle and state

The selected backend, mode, SOCKS address and native state directory are saved
in `~/.config/meshscale/backend.json` (or `$XDG_CONFIG_HOME/meshscale/backend.json`).
Plain `meshscale up` reuses them. There is no fallback to another backend after
registration, network or API failures. Changing backends requires an explicit
`--backend warp` / `--backend native`; a running backend must first be stopped.
Changing native mode or state directory also requires stopping the old daemon.
Use the same user and config environment for every command.

```sh
meshscale ip          # saved assigned IPv4, also available while down
meshscale ip -6
meshscale status      # marks this machine and native (experimental)
meshscale status --json
meshscale down        # stop, preserve registration and private keys
meshscale up          # same registration, foreground again
meshscale down --forget  # stop, deregister, delete this Mesh node and local credentials
meshscale up --backend warp  # explicit return to the official client
```

Ctrl-C and SIGTERM disconnect without deregistering. `down --forget` needs
administrative credentials for the saved account; it verifies the saved node
ID/name before deletion. It preserves the backend preference and warning record.
It currently applies only to native; official-client forgetting is not added.
When the daemon is PID 1 in a container, its exit ends that container; run the
container with a separate init/supervisor when testing `down` via `docker exec`.

Default native state directory:

| User | Directory |
|---|---|
| root | `/var/lib/meshscale/native` |
| non-root | `~/.config/meshscale/native` |

Override with `up --state-dir /absolute/private/path`. The directory must have
mode `0700`, belong to the daemon user, and have no unsafe or symlink ancestors.
Registration state is atomically written with mode `0600` in `registration.json`:
account/node ID and name, local X25519 private key, device bearer credential,
public key and the minimal parsed WireGuard configuration. Enrollment tokens
are used in memory and are not persisted. Full API responses are never logged
or persisted; override codes and other unused response secrets are discarded.

`daemon.lock` prevents concurrent enrollment, transport instances and forgetting.
An interrupted registration is never silently repeated; `down --forget` can
clean it up before explicit re-enrollment. `control.sock` is a mode `0600` Unix
socket inside the private directory. It exposes status/stop, Mesh-only TCP dial,
and leased listeners for SSH. It is local to this UID, not a stable public API.
`known_hosts` and the warning/backend record live in the config directory;
rootless SSH host keys are stored separately from the system SSH identity.

The daemon re-fetches config every five minutes with the retained device bearer.
GET's missing bearer field cannot erase that credential. Peer changes are
applied in process; address changes require a restart. Revocation/expiry or any
failed refresh stops the connection with an explicit error; it does not
re-enroll, switch backends or assume credentials remain valid indefinitely.
There is no proven token-renewal contract for this undocumented API.

## Implementation

`internal/backend.Backend` supplies `Status`, `Registration`, `Connect` and
`Disconnect`, with transport-neutral status/identity types. `warpcli.Client`
implements it via the official service; `native.Client` implements it via the
private control socket and saved identity. Native enrollment/lifetime is kept
separate from official account setup, so the existing WARP path remains intact.

`internal/native.API` handles token-bound registration, validated parsing,
config refresh and deregistration. `State` persists minimal credentials;
`localstate` supplies private file checks, atomic writes and an exclusive lock.
`Transport` owns wireguard-go and a `Network` interface (`DialContext`,
`ListenTCP`), backed by Linux TUN/OS sockets or gVisor. Both restrict WireGuard's
allowed IPs to the Mesh ranges. `Run` owns cancellation, refresh, SOCKS and the
control socket. The Unix listener lease bridges netstack connections without
losing their Mesh addresses, allowing separate `sshd` processes to use the
existing authorization/session implementation. No host networking is needed.

## macOS next

The CLI deliberately refuses Linux-class registration from macOS. Establish an
appropriate native enrollment contract instead of claiming official macOS node
support by sending `type: linux`. The library and CLI cross-compile for Darwin
ARM64; they have not been runtime-tested there.

- **Userspace:** the menu bar app can run the foreground daemon as the logged-in
  user, present its first-use warning, consume `status --json`/`ip`, and invoke
  `down`. Same-user SSH/proxy can share the private socket. It must keep the
  process alive and report failure, without falling back to WARP.
- **Transparent VPN with utun:** add a Darwin implementation behind
  `createSystemTUN` and a signed privileged helper to create utun and install
  only Mesh routes. Use a narrowly scoped, authenticated helper protocol;
  today's root-only socket is intentionally inaccessible to the menu app.
  WireGuard runs in the helper, and launchd manages its lifecycle.
- **Network Extension:** an embedded `NEPacketTunnelProvider` with signing and
  entitlement support is the preferred app-shaped design. WireGuard consumes
  packet flow, while the extension owns routes/MTU and OS VPN approval. This is
  a distinct lifecycle/transport adapter, not simply launching the Linux CLI.

Neither approach should take over default routes or DNS implicitly. VPN
coexistence, particularly overlapping Tailscale CGNAT routes, needs macOS tests.
