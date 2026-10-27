# Access rules and routes verification — 2026-10-26

Historical verification record; personal account, host and resource identifiers in examples are anonymized.

Implementation completed in `/path/to/meshscale`; no commit or push.
No host networking, sysctl, firewall, account settings, enrollment or device
profiles were changed. Existing containers were not stopped or removed.

## Implementation and format

Commands: `rules check <file>`, `rules sync [--dry-run] [--file path]`,
`rules list`, `rules reset`; `routes advertise <cidrs> [--node name]`,
`routes list`, `routes remove <cidr>` (route writes also support `--dry-run`).

The default policy is the configuration directory's `rules.json`. Example:

```json
{"groups":{"servers":["homelab","nas"]},"rules":[{"from":["*"],"to":["servers:22,443"]},{"from":["macbook-air"],"to":["*:*"]}]}
```

Strict JSON, exact device names, owner emails, explicit `group:name` or bare
group aliases, default Mesh IPs/CIDRs, single ports, comma lists, ranges and `*`
are supported. IPv6 destinations require brackets. Missing default file means
no writes; an existing empty rules array means deny all Mesh destinations.
Full behavior and caveats: [rules](../../docs/rules.md), [routes](../../docs/routes.md).

Kept the previous worker's ownership model, compiler structure, CLI commands,
route planning and status integration. Corrected IP selector syntax/source
identity, names containing spaces, zoned/external IP validation, reset at quota,
and readback normalization/idempotence. Added the expression-size guard, tests,
documentation, and automatic sync registration.

`SyncRules` in `cmd/meshscale/rules.go` is exported and registered as `rules`
with `internal/devicesync.Default`. The registry existed with a stable Register/
Run API. The hook re-fetches the account inventory to retain registration owner
emails even for Mesh node rows. No edits to up, daemon/service, DNS or the
parallel worker's other files were needed. Policy-file edits still need manual
sync; the registry is triggered by device inventory changes.

## Account API findings

The API rejected documentation-style `any(net.src.ip[*] in {...})` with:

```text
cannot access index MapEach for type Ip
```

Scalar `net.src.ip in {...}` was accepted, but it matches the public on-ramp
address, not the preserved Mesh source. Native-only blocking tests established
that `net.src.internal_src_ip in {...}` matches actual source Mesh addresses.
Use scalar `net.dst.ip in {...}` for destinations.

Gateway strips host-length `/32` and `/128` suffixes and redundant parentheses
in API responses. Diff normalizes the emitted AND/OR grammar and those suffixes;
repeated dry-run sync then reported **0 changes**. The live tests verified
network create/PUT update/list/delete, preserved rule IDs, and unchanged customer
and DNS policies. The documented default limit is 500 network policies per
account (no lower Free-plan limit listed); client guards include existing rules,
temporary create peaks and the 140,000-character expression limit.

Sources: [network policies](https://developers.cloudflare.com/cloudflare-one/traffic-controls/network-policies/),
[Gateway rules API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/gateway/subresources/rules/),
[account limits](https://developers.cloudflare.com/cloudflare-one/account-limits/).

## Live policy and safe staging

Participants were confirmed by Docker and `status`: node-1 `100.96.0.2`, node-2
`100.96.0.3`, native-tun `100.96.0.4`, native-userspace/container native-1
`100.96.0.5`. The executable was copied as `/usr/local/bin/meshscale-rules` to
node-1, node-2 and native-tun; existing binaries were preserved.

The [actual test policy](rules-policy.json) explicitly allows the entire Mesh
IPv4 range **except native-tun's 100.96.0.4** using its CIDR complement, and
allows all Mesh IPv6 traffic. It then permits node-2 to native-tun ports 8080
and 8081. Thus the test restricts only native-tun's IPv4 traffic. No restriction
on node-1↔node-2 was introduced. A temporary meshprobe listener on native-tun's
8081 was started and later stopped; the existing 8080 listener was preserved.

To protect the parallel worker from propagation order, permits were staged
through the same Gateway API first. The preflight deny was limited to
`100.96.0.4/32`. After confirming source-specific and wildcard permits with
native-tun probes, normal `rules sync` updated that deny to the compiler's full
Mesh range. The complete compiled policy then passed API readback and traffic
tests. All mutations carried the network ownership markers.

[Full real Gateway API output](rules-gateway.json) records all four owned rules.
Selected fields from that response, without rewriting expressions:

```json
[
  {
    "id": "00000000-0000-4000-8000-000000000014",
    "name": "meshscale rule: allow-2",
    "description": "Managed by meshscale network rules v1; rule=allow-2",
    "precedence": 1001,
    "enabled": true,
    "action": "allow",
    "filters": ["l4"],
    "traffic": "net.src.internal_src_ip in {100.96.0.3 2606:4700:cf1:1000::3} and (net.dst.ip in {100.96.0.4 2606:4700:cf1:1000::4} and net.dst.port == 8080)"
  },
  {
    "id": "00000000-0000-4000-8000-000000000011",
    "name": "meshscale rule: default-deny",
    "description": "Managed by meshscale network rules v1; rule=default-deny",
    "precedence": 1003,
    "enabled": true,
    "action": "block",
    "filters": ["l4"],
    "traffic": "net.dst.ip in {100.96.0.0/12 2606:4700:cf1:1000::/64}"
  }
]
```

## Allowed/denied traffic and propagation

Initially the third allow permitted any Mesh source to native-tun:8081. At
02:30:38.290 UTC, `rules sync --file` narrowed its source to node-2. The API call
completed in 3.527 seconds. Probes from node-1 to native-tun:8081 showed:

| Elapsed from sync start | Result |
|---|---|
| 3.652 seconds | Allowed, greeting received |
| 5.763 seconds | Denied, curl exit 56, connection reset by peer |

Propagation was observed between those samples, within **5.8 seconds of sync
start**, about **2.2 seconds after sync completion**. This measures an actual
allow-to-deny transition; the earlier staged policy was not used to infer an
exact initial activation time.

At 02:30:13–14 UTC (full compiled default deny already installed):

| Probe | Result |
|---|---|
| node-2 → native-tun:8080, meshprobe | Allowed, 22 ms, greeting sees source `100.96.0.3` |
| node-1 → native-tun:8080, meshprobe | No greeting; edge closes connection |
| node-1 → native-tun:8080, curl | Denied, exit 56, connection reset by peer |
| node-2 → native-tun:8080, curl | Allowed, greeting received |
| node-1 → node-2:8080, meshprobe | Allowed, 19 ms |
| node-2 → node-1:8080, meshprobe | Allowed, 24 ms |

After narrowing port 8081, at 02:31:17 UTC:

```text
node-2 -> native-tun:8080: OK in 18ms: hello from 100.96.0.4:8080, you are 100.96.0.3:46750
node-2 -> native-tun:8081: OK in 18ms: hello from 100.96.0.4:8081, you are 100.96.0.3:60448
node-1 -> native-tun:8080: no greeting (edge closes connection)
node-1 -> native-tun:8081: no greeting (edge closes connection)
```

meshprobe misleadingly prints `OK in Nms:` and exits zero when the edge accepts
TCP then immediately closes without the greeting. Denial was therefore checked
with application data and curl's nonzero connection-reset result, not meshprobe's
exit code alone. Initial preflight probes also saw a transient timeout before
policy convergence; they were not counted as a stable allow/deny result.

## Routes

Used the authorized API-only fallback to avoid profile or network changes;
the participants' configured routes include only Mesh ranges. The test CIDR was `10.250.0.0/24` via native-tun instead.

```text
$ meshscale-rules routes advertise 10.250.0.0/24 --dry-run
[{"network":"10.250.0.0/24","tunnel_id":"00000000-0000-4000-8000-000000000010","comment":"meshscale route: 10.250.0.0/24"}]

$ meshscale-rules routes advertise 10.250.0.0/24
Advertised 10.250.0.0/24 via meshscale-native-tun (route 00000000-0000-4000-8000-000000000007).

$ meshscale-rules routes list
10.250.0.0/24  meshscale-native-tun  true  00000000-0000-4000-8000-000000000007  meshscale route: 10.250.0.0/24

$ meshscale-rules status
Subnet routes via meshscale-native-tun: 10.250.0.0/24

$ meshscale-rules routes advertise 10.250.0.0/24
Routes already advertised; no changes.

$ meshscale-rules routes remove 10.250.0.0/24
Removed route: 10.250.0.0/24
```

The actual route API returned `tun_type: warp_connector`, the selected node ID,
correct ownership comment and the account default virtual network. Forwarding
was already enabled in native-tun; disabled/read-error/IPv6 advice is unit-tested.
No sysctl write was made. A final guard also rejects local native IPv6 subnet
advertisement, since Cloudflare requires MASQUE for IPv6 CIDR routes.

[Cloudflare's return-routing documentation](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/features/routes/#return-traffic-routing)
requires the subnet gateway to route `100.96.0.0/12` via the Mesh node's LAN IP
unless the node already is the default gateway. Both node/client Split Tunnel
profiles also need the advertised CIDR. These requirements are documented and
printed; profile changes are outside this task's authorized account mutations.

## Cleanup, checks and files

`rules reset` removed **4 owned network rules**. `rules list` returned `[]`.
A full-object comparison verified that all four original Gateway policies
(`Do Not Inspect`, disabled `Default deny for private traffic`, and the two DNS
overrides) were exactly unchanged. Active routes matched the empty baseline.

At 02:31:40 UTC, node-1 again received native-tun's 8080 greeting, and node-1 ↔
node-2 passed again at 24 ms each. The temporary 8081 listener was terminated
by its recorded PID. Existing containers, listeners, registrations and binaries
were preserved. Named `meshscale-rules` binaries remain available for review.

Passed:

- `go vet ./...`
- `go test ./...`
- `go test -race ./internal/rules ./internal/routes ./cmd/meshscale`
- `git diff --check`
- Static Linux ARM64 build and container CLI execution.

Tests cover strict parsing, group cycles/aliases, names/emails, ports/ranges,
IPv4/IPv6 selectors, address changes, missing/ambiguous addresses, compile scope,
create/update/delete/idempotence, ownership, quota/precedence refusal, reset,
whole-plan validation before writes, expression normalization, missing files,
registry hooks, route collision/ownership/removal, forwarding advice, and routes
in text/JSON status.

Task files (including resumed prior-worker files):

- `internal/rules/{policy,compile,expression,sync}.go` and tests.
- `internal/routes/routes.go` and tests.
- `cmd/meshscale/{rules,routes}.go` and tests.
- `cmd/meshscale/status.go`: owner email metadata and routes display.
- `internal/cfapi/gateway.go`: shared DNS/network rule comment.
- `docs/rules.md`, `docs/routes.md`, small README command/link updates.
- This report, `rules-policy.json`, `rules-gateway.json`.

Raw intermediate evidence and final executable are ignored under
`bin/rules-evidence/` and `bin/meshscale-rules`.

Remaining scope/questions: no comments/trailing commas, custom Mesh pools or
subnet destination ACLs; no live IPv6/UDP data-plane or real routed-subnet test;
Gateway updates are not atomic and existing flows may outlive changes; one
canonical syncing administrator is recommended. A vanished/ambiguous named
selector aborts sync and leaves the last installed policy, so inspect failures
before IP reuse. Registry owner fingerprints currently use the display owner
(`Mesh node`), so an owner-email-only change on a node may need manual sync;
owner metadata should eventually be part of that fingerprint. The shared
500-policy guard is conservative for Enterprise accounts with raised limits.
No required implementation work remains within this task's scope.
