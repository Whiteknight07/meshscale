# Status reachability verification (2026-10-26)

Baseline source: `cb454ed4a5d7a3acb6f9a5e64e1820fd49a7253f`. Built baseline
and changed binaries with the same Go toolchain, then alternated three
`/usr/bin/time -p <binary> status` runs against the same account and host.

| Run | Before, seconds | After, seconds |
| --- | ---: | ---: |
| 1 | 10.33 | 10.37 |
| 2 | 10.23 | 9.82 |
| 3 | 9.45 | 9.70 |
| Median | 10.23 | 9.82 |

These are live Cloudflare calls with normal network variability; they show no
noticeable status regression. Initial installed-binary checks took 9.7 seconds.
Probing overlaps later API calls and has a fixed total budget independent of
account size. Fake-prober tests cover 1,000 addresses across simultaneous
requests, enforcing the shared 16-worker limit and cancellation, plus cache
expiry, positive/negative caching, and simultaneous requests for the same IP.

Compiled `internal/reachability`'s test binary and ran `TestLiveProbe` as
`nobody` (UID 65534, effective capabilities `0000000000000000`). Linux
`/proc/sys/net/ipv4/ping_group_range` was `0 2147483647`; it was only read.

| Target | Datagram ICMP echo | Full ICMP/TCP probe |
| --- | ---: | ---: |
| Test phone | replied, 236 ms | reachable, 165 ms |
| Test container | replied, 14 ms | reachable, 14 ms |
| Test Mac | replied, 162 ms | reachable, 165 ms |

ICMP and full probes are separate sequential attempts, so durations differ.
The phone sometimes took over 250 ms; the final implementation keeps ICMP
listening through the full 400 ms deadline while TCP fallback runs.

Each target also passed a separate
`status --json --test-stale-ip <target>` check: `online` was `true`,
`online_source` was `probe`, and `last_seen_at` remained the deliberately stale
in-memory timestamp. The container run took 10.14 seconds; the Mac run took
9.72 seconds. The test flag does not change Cloudflare or persistent state.
No routing/firewall changes, daemon restart, or Mac modifications were used.

A Unix control-socket test verifies three independent client requests produce
one fake network probe, demonstrating that daemon caching survives CLI process
boundaries. Table tests cover stale/fresh devices, reachable/unreachable
results, IPv6, absent/invalid addresses, revoked/deleted devices, TCP fallback,
and explicit secure-route tuning with module retry/fallback.

Validation: `gofmt`, `go vet ./...`, and `go test -race ./...` passed. The Go CLI
also cross-compiled successfully for `darwin/arm64`. The Swift
model adds only an optional string and its JSON coding key; compatibility test
cases cover absent, current, and future values. That earlier verification did not run Swift. The subsequent OSS audit ran
Swift build/tests and app-packaging regression checks in a fresh temporary
directory on an authorized Mac, without launching an app or changing WARP.
See [the Mac build guide](../macos/README.md) for repeatable commands.

## Daemon inventory cache and overlap fix (2026-10-26)

Measured on a test Linux host with the hand-added DNS routing fix already present for the
baseline. Python `time.monotonic()` measured complete subprocess elapsed time,
including process startup and output capture. Five sequential successful runs
per command; these are shared-host samples, not latency percentiles or an SLA.
The pre-change installed executable reports VCS revision `1ae5e43` with
`vcs.modified=true`; it predates the source checkout's latest reachability work.
It was backed up before deployment. Thus the table compares the real installed
before/after experience, not clean builds differing by only one commit.

| Run | Before text status, ms | After text status, ms | After JSON status, ms | DNS (`getent hosts github.com`), ms |
| --- | ---: | ---: | ---: | ---: |
| 1 | 12346.08 | 8.66 | 6.64 | 10.06 |
| 2 | 9465.33 | 7.18 | 7.01 | 14.14 |
| 3 | 6836.62 | 7.27 | 6.77 | 9.59 |
| 4 | 5230.60 | 7.68 | 6.61 | 8.82 |
| 5 | 5541.36 | 7.28 | 6.09 | 9.12 |
| Median | **6836.62** | **7.28** | **6.64** | **9.59** |

The task's earlier approximately 10.5-second observation and five-second DNS
stall are reported diagnostic history; neither is a fresh five-run baseline
here. The earlier three-run table above remains historical evidence. A
separate pre-change DNS batch had a 10.36 ms median because the manual hotfix
was already active.

The reported 2.5-second `warp-cli` delay did not reproduce during this batch:
text status median **6.91 ms**, JSON status **7.43 ms**, text registration show
**7.45 ms**, JSON registration show **6.63 ms** (five runs each). JSON was not
consistently faster, so no private warp-svc protocol dependency was added.
The daemon instead reuses its verified enrollment identity for inventory;
status takes connection state from its runtime cache. These measurements do
not rule out intermittent daemon/client delays observed by the lead.

A live `status --refresh --json` completed successfully in **5629.78 ms**
(including before/after local snapshot inspection), retained seven devices,
and advanced `updated_at` from `07:45:50.782575261Z` to
`07:46:56.841766613Z`. Cached reads remain local while that work runs. The
refresh included the coordinated SSH-mode target lookup; no provisioning was
requested. `strace -f -e execve meshscale status --json` recorded only the
meshscale executable, with no child command execution. Private-socket reads
showed devices, registrations, probe-derived reachability and secure metadata;
local connection/exit/handshake state comes from `/devices`' runtime status.

Two guarded binary/service deployments each had a four-minute
`systemd-run --on-active=4min` rollback armed first. The first established
functional behavior; the second replaced routing subprocesses with netlink.
WARP changed its policy priority from 5209 to **5199** during restart. After
reconciliation and removal of the untagged manual rule, the owned rule was:

The observed Mesh policy rule used the owned protocol tag 243 and ran just
before WARP’s rule. Existing Tailscale peer routes retained their original
interface/table; the Mesh peer route used CloudflareWARP. Account-specific
addresses and raw route dumps are omitted from the public record.

Internet trace after each host change retained the original public address,
`warp=off`, `gateway=off`. DNS stayed fast, Tailscale retained its peers, and
a fresh SSH session to the test Mac over Mesh succeeded.
No sleep exception was needed. Rollbacks were canceled after the health checks.
Table 52 was not given a default route on the host: that guard was exercised
with a fake runner and in an isolated network namespace using actual kernel
routes/rules. No Mac configuration or client was changed.

The inventory cache uses the existing API poller and does not introduce a
second timer. The overlap manager uses an instance-owned netlink handle plus
nonblocking link/route/rule notifications; unchanged ticks do not dump routing.
The dedicated namespace test is opt-in and refuses the initial host namespace:

```sh
go test -c ./internal/linuxnetwork -o /tmp/meshscale-network.test
unshare -n env MESHSCALE_ROUTING_NAMESPACE_TEST=1 \
  /tmp/meshscale-network.test -test.run TestKernelRoutingNamespace -test.v
```

Remaining idle work for the event-driven follow-up: `KeepConnected` still reads
WARP status every five seconds and checks live registration before reconnect;
secure discovery/safety paths can also read registration. Exit forwarding
reconciliation calls `exitnode.Inspect` (IPv4/IPv6 routes/rules, links,
`ss -Htnp`), inspects owned nftables state and checks firewalld state/zones.
The existing Linux coexistence firewall still checks `iptables -S ts-input`.
Secure carrier and guardian cleanup both delete tagged UDP/51821 filter rules;
the guardian's `EXIT` path can run in addition to the Go cleanup. Source review
identifies those deletion sites, but does not prove why the lead observed a
delete every tick; trace parent PIDs and engine/guardian lifetime before
changing cleanup semantics. This work makes no whole-daemon idle CPU claim.

### Foreground SSH control follow-up

A third guarded deployment added the private `PUT /ssh` endpoint. With the
saved own-SSH setting disabled, a live `{"enabled":false}` request returned
**HTTP 204**; no SSH listener was enabled for this smoke check. Socket tests
separately start, cancel, join and restart a fake foreground SSH worker,
including a delayed listener-release gate. Internet, DNS, Tailscale and Mac
Mesh SSH checks passed again before canceling the four-minute rollback.
This final WARP restart returned to priority **5209**, and the netlink manager
recreated the owned rule at **5208**. The earlier 5199/5198 observations above
remain evidence that priority selection is dynamic.
