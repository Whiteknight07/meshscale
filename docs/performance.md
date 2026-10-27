# Linux daemon idle reconciliation inventory

## Baseline capture

On 2026-10-26, a Linux test host ran `meshscale.service`. A 30-second `strace -f -tt -e trace=execve` capture measured process launches. It recorded 41 successful `execve` calls (the trace window includes an immediate reconciliation on attach), with a steady stream of per-second process launches. The commands and call paths were:

| Command observed | Daemon call site / trigger |
| --- | --- |
| `ip -j -4 route show table all`, `ip -j -4 rule show`, `ip -j -6 route show table all`, `ip -j -6 rule show`, `ip -j -d link show`, `ss -Htnp state established` | `internal/exitnode/network.go:Inspect`; called from `Manager.selectionPlan` via `Prepare` on the `internal/secure/supervisor.go:Run` 5-second loop, and from `Manager.configureSource` / `Manager.Forward` during configure/forward reconciliation. The route/link dump discovers route exceptions and tunnel link kinds; `ss` extracts established `sshd` peers. |
| `ip -4 address replace ... dev meshsecure0` | `internal/exitnode/manager.go:configureSource`; called when secure peers are configured. |
| `ip -6 route show fd6d:6573:6873::/48 dev meshsecure0` | Secure route inspection/reconciliation under `internal/secure`/`internal/secureroute`; emitted repeatedly while the 5-second supervisor refresh retries route setup. |
| `nft list table inet meshscale_exit_v2`, `nft -f -` | `internal/exitnode/network.go:NFT.Apply`; exit forwarding setup in `Manager.Forward`. The table is inspected and then reapplied even when the generated state has not changed. |
| `firewall-cmd --state`, `--get-zone-of-interface=meshsecure0`, `--get-default-zone`, `--get-zone-of-interface=enp0s6`, `--zone=public --query-forward` | `internal/exitnode/firewall.go:Firewall.Reconcile` and `Firewall.zone`, called from `Manager.Forward` on forwarding reconcile. The interface zone lookup is repeated even when firewalld has not reloaded. |
| `iptables -w 5 -S ts-input` | `internal/linuxnetwork/firewall.go:firewall.apply`; called by `Client.ReconcileNetwork` from `service.KeepConnected` every 5 seconds while WARP and Tailscale interfaces exist. The chain probe precedes an idempotence check for the owned rule. |
| `warp-cli --accept-tos status` | `internal/service/daemon.go:KeepConnected`, launched by the 5-second worker in `cmd/meshscale/daemon.go`. |
| `warp-cli --accept-tos registration show` | `service.KeepConnected`, on a status read that is disconnected or non-connected; it verifies registration before reconnecting. |
| `iptables -w 5 -D INPUT ... --dport 51821 ...` (reported in the lead's longer capture; absent from this 30-second sample) | `internal/secure/carrier_linux.go:restrictCarrier` installs the scoped rules at engine start and its cleanup closure runs `iptables -D INPUT ... --dport 51821 ...`; `internal/secure/guardian_linux.go:kernelGuardian` also deletes the owned rules when the kernel interface generation exits. The churn indicates secure engine close/restart activity, and the deletion is cleanup rather than a per-tick reconciliation requirement. |

The netlink reader already used by `internal/linuxnetwork/routing_linux.go` checks IPv4 link/route/rule notifications, but the exit-node `Inspect` path above still shells out for full route, rule, link, socket, and nft table reads. The secure supervisor also calls `Prepare` every five seconds; selected-exit planning therefore repeats its full inspection before the `prepared` fast path can compare plans.

The baseline `warp-cli --help` shows a global `--listen` option described as listening for status changes and DNS logs. The option must accompany a subcommand (`warp-cli --accept-tos --listen status`); verify the exact stream output/lifecycle before wiring it into the daemon.

## Result (Linux test host, 2026-10-26)

The daemon now reacts to kernel, firewalld and WARP events instead of polling with short-lived commands:

- **Exit-node inspection.** Routes, rules and links are read over netlink, and sshd peers come from `/proc`, replacing `ip -j` and `ss`. The snapshot keeps `ip -j`'s vocabulary: tables `main`/`local`, destination `default`, bare host addresses, and link kinds `tun`/`tap`, plus empty for physical devices. Two live, read-only tests check the readers against the real host:
  - `MESHSCALE_LIVE_SNAPSHOT=1 go test ./internal/exitnode` diffs every route, rule and link against iproute2, and checks nft table presence against `nft`'s comment marker.
  - `MESHSCALE_LIVE_FIREWALLD=1 go test ./internal/exitnode` checks the D-Bus answers against `firewall-cmd`.
- **Events.**
  - Netlink route, link, address and rule subscriptions are re-established with backoff if they die, for example on `ENOBUFS`.
  - Any firewalld signal invalidates the firewalld D-Bus cache. Lookups are cached only while the signal watch is alive.
  - `warp-cli --listen status` pushes connection changes and is restarted with backoff when `warp-svc` restarts.
- **Fallback polling.**
  - Connection status is polled every minute while connected (every 30 s otherwise), and network reconciliation runs every minute.
  - The secure supervisor runs a process-free 5 s tick (settings, status, key-directory refresh when due) and a full `Prepare` inspection every minute.
- **Mutations still use the CLIs.** That includes nft ownership checks, which read the table comment, and iptables. They run only when something changes.

Measured on the live daemon (exit node with secure mode, Tailscale coexistence):

| | Before | After |
| --- | --- | --- |
| Processes launched while idle | 37 per 60 s (`ip` ×13, `iptables` ×12, `warp-cli` ×12) | 5 per 120 s (`warp-cli status` ×2, `iptables -S ts-input` ×2, one `registration show`) |
| Idle CPU (one core) | ~1.9% | 0.075% (9 ticks in 120 s, untraced) |
| RSS | 21 MB | 24 MB (event subscriptions) |

Behaviour that changed on purpose:

- **Transient key-directory failures.** Timeouts, 429s and 5xx while secure mode is running keep the last-known peers, and the failure shows as a status warning. Authorization failures (401/403) and a missing local record still fail closed immediately.
- **Policy sync** runs on every directory refresh, not only when peers change.
