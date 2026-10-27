# Native implementation handoff — 2026-10-26

Implemented the Linux experimental backend in the main module. Official WARP
remains the default, preferences persist, switching is explicit, and failures
never select another backend. No commits or pushes were made. `macos/`, `app/`,
`whoami` and the other worker's additive `status --no-cache` changes were left
intact.

## Design

The shared `backend.Backend` controls status, local registration, connect and
disconnect. Official enrollment still uses `warp-cli`; native enrollment and its
foreground daemon are separate. A private Unix socket gives separate CLI
commands access to status, shutdown and TCP dial/listen through the active
transport. Listener leases preserve remote Mesh IPs for SSH authorization.

TUN mode uses wireguard-go, an exclusive `meshscale0`, MTU 1280, returned `/32`
and `/128` addresses, and only Mesh `/12` and `/48` destination routes. It
removes its interface on shutdown and does not modify DNS/default routes/firewall.
Userspace mode uses gVisor, a loopback SOCKS5 CONNECT proxy restricted to numeric
Mesh IPs, and direct netstack SSH client/server connections. Unprivileged SSH
sessions are restricted to the server's own UID/GID. New SSH hosts are pinned;
changed keys are rejected.

Private state is `registration.json` (0600) under a verified owner-only directory
(0700): account/node identity, local private key, device bearer and minimal
parsed config. Enrollment tokens are not persisted. Writes are atomic; a held
file lock prevents duplicate enrollment and concurrent state deletion.
`backend.json` persists the choice, userspace mode, SOCKS address, state path and
one-time warning record. Refresh runs every five minutes, preserves the original
bearer, applies peer changes and stops on failure/revocation. Address changes
require restart. `down --forget` deregisters, verifies and deletes the saved node,
and removes its registration credentials.

Exact warning:

> WARNING: The native backend is experimental. It is not a Cloudflare-documented forwarding mechanism under Cloudflare Zero Trust terms §6. It uses an undocumented device API that may change or break without notice. Use it only if you accept these risks.

## Container results

Full command/output transcript: [evidence.log](evidence.log).

- `meshscale-native-tun`: bridge, NET_ADMIN, `/dev/net/tun`, no WARP;
  **100.96.0.4**. Plain `ssh testuser@100.96.0.2 whoami` returned `testuser`.
  curl read `hello from 100.96.0.2:8080, you are 100.96.0.4:53774`.
  meshprobe reached node 1 in **16 ms**; node 1 reached its listener in **18 ms**.
  Node 1 also SSH'd back and got `testuser`.
- `meshscale-native-1`: bridge, **UID/GID 1001**, **all capabilities dropped**,
  no TUN, no WARP; **100.96.0.5**. SOCKS curl read
  `hello from 100.96.0.2:8080, you are 100.96.0.5:41792`.
  `meshscale ssh`, by both IP and device name, returned `testuser`.
  Node 1 SSH'd back through netstack and got `testuser`.
- Both `status` outputs mark their own native device. State modes are 0700/0600,
  owned by root for TUN and UID 1001 for userspace. Rootless OS routes have only
  the Docker bridge/default; TUN retains that default and adds Mesh routes only.
- `down` removes TUN/routes and the control socket, while preserving credentials.
  Plain `up` reuses registration/IP and does not repeat the warning. Periodic
  configuration refresh was observed in both modes.
- A temporary `meshscale-native-forget` node tested `down --forget`; registration
  credentials/socket were checked absent and the node disappeared from status.
- Existing MASQUE node 2 → node 1: **OK in 31 ms**, source **100.96.0.3**.
  Neither MASQUE container was stopped, restarted or removed.

The initial TUN container inherited Tailscale DNS at `100.100.100.100`, inside
Mesh's `/12`. The test container's resolver was changed to `1.1.1.1`; reproduction
now uses Docker `--dns 1.1.1.1`. No host networking was changed. Later native-only
container replacements preserved registration/host-key state on private mounts.

The old spike registration was deleted (204), `meshscale-native-test` node
was deleted (200), and its revoked local key
file was removed. Its container name was reused for the new userspace CLI.
The only retained new account nodes are `meshscale-native-tun` and
`meshscale-native-userspace`. Full-result hashes of device profiles/default
profile/global settings/Gateway rules match the spike's post-test snapshot;
see [account-after.json](account-after.json). No other account resources were
written.

## Validation and dependencies

Passed `go vet ./...`, `go test ./...`, race tests covering native/localstate/
backend/config/sshserver/warpcli/CLI, Darwin ARM64 cross-compilation and
`git diff --check`. Unit tests cover redacted evidence parsing, account-bound
node tokens, GET bearer preservation, safe API errors, malformed config,
private permissions/symlinks, restart/partial-enrollment cleanup, exclusive
locks, backend selection, one-time warnings, Mesh-only SOCKS/control traffic,
listener leases/source identity, changed SSH key rejection and rootless UID
restrictions. No WireGuard/native transport was started on the host by tests.

Dependencies match the spike:

- wireguard-go `v0.0.0-20261024220952-b3bc704ef0ee`
- gVisor `v0.0.0-20250503011706-39ed1f5ac29c`
- indirect btree `v1.1.2`, x/net `v0.60.0`, x/time `v0.7.0`, wintun
  `v0.0.0-20230126152724-0fa3db229ce2`
- x/sys `v0.49.0` is now direct; x/term `v0.47.0` is direct for SSH terminal
  handling. Existing x/crypto stays `v0.58.0`.

Static, unstripped Linux ARM64 (`CGO_ENABLED=0`) HEAD baseline: **11,610,330 bytes**;
current: **16,554,699 bytes**, increase **4,944,369 bytes (42.59%)**. This compares
HEAD with the current working tree, including the concurrent additive CLI edits.
The final test image was rebuilt with the current binary; state is excluded from
the build context.

## macOS follow-up

See [docs/native.md](../../docs/native.md). Userspace can be a same-user foreground
process driven by the menu app, CLI JSON and private IPC. Native `up` currently
refuses macOS enrollment rather than sending a Linux registration type silently.
Transparent networking needs either a Darwin utun adapter in a signed privileged
helper with scoped authenticated IPC, or an embedded signed/entitled Network
Extension (`NEPacketTunnelProvider`), the preferred app design. The menu app
cannot access today's root-only daemon socket. Add the appropriate enrollment,
lifecycle and IPC integration, first-use warning UI, and runtime VPN coexistence
tests. No macOS runtime behavior is claimed from the cross-build.

## Files changed by this implementation

Added:

- `internal/backend/backend.go`
- `internal/localstate/{state,unix,other}.go`
- `internal/native/{registration,state,transport,tun_linux,tun_other,daemon,control,socks}.go`
- `internal/native/{registration,state,control}_test.go`
- `internal/native/testdata/{registration.json,README.md}`
- `internal/config/{backend.go,backend_test.go}`
- `cmd/meshscale/{backend.go,backend_test.go,native_ssh.go,native_ssh_test.go}`
- `docs/native.md`
- `test/native/{Dockerfile,.dockerignore,.gitignore,README.md,REPORT.md,evidence.log,account-after.json}`

Modified:

- `cmd/meshscale/{up,down,ip,status,ssh,sshd,main}.go`
- `internal/warpcli/warpcli.go` (transport-neutral type aliases)
- `internal/sshserver/{auth.go,auth_test.go,hostkey.go,session_linux.go}`
- `go.mod`, `go.sum`, `README.md`

The test binary/private bind-mount state are ignored. Other working-tree changes
belong to the concurrent macOS worker; they were preserved.
