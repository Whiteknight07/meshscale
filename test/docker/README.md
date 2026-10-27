# Docker end-to-end test

Historical verification record; personal account, host and resource identifiers in examples are anonymized.

Run `bash test/docker/e2e.sh` from the repository. It statically builds the CLI
for the Go toolchain's host architecture (override `GOARCH` if needed), installs Cloudflare WARP from its
official apt repository in Ubuntu 24.04, and starts `warp-svc` directly as PID 1.
No systemd service is started. Only the binary and Dockerfile enter the build
context; credentials are supplied at runtime with
`--env-file` using `${XDG_CONFIG_HOME:-$HOME/.config}/meshscale/dev.env`.
Set `MESHSCALE_TEST_CREDENTIALS` to use a different private credential file.
This is an opt-in live-account test: it enrolls and connects its container and
can reconcile account resources. For a fully offline installer test, run
`bash test/docker/install_test.sh`.

The container is `meshscale-node-1`, with `NET_ADMIN`, `/dev/net/tun`, and the
**default bridge** network. It remains running for subsequent connectivity tests.
Running the script again preserves the container's registration, copies in the
new CLI, and verifies idempotent `up`. Container removal also removes its WARP
registration state and meshscale's local association cache.

## Verified 2026-10-26

Ubuntu 24.04 / ARM64, Cloudflare WARP `2026.8.2115.0`.

Initial account setup changed these settings from false to true with one PATCH:

- `use_zt_virtual_ip`
- `gateway_proxy_enabled`
- `gateway_udp_proxy_enabled`

It created one `meshscale nodes` profile, precedence `100`, matching
`identity.email == "warp_connector@example-team.cloudflareaccess.com"`, with
`service_mode_v2: {mode: warp}`, `tunnel_protocol: masque`, and only
`include: [{address: "100.96.0.0/12"}]`. No `exclude` was sent. The existing
default profile, certificate flag, and override time were unchanged.
Repeated setup performs no writes. No Tunnel, Gateway rule, enrollment policy,
or identity provider was changed.

The initial blank container enrolled at `100.96.0.1`. After testing idempotency
and `down`/`up`, only that test container and test node were removed to verify
fresh enrollment using the finished implementation. The replacement received
`100.96.0.2`. The old node was deleted; Cloudflare retains its old device
registration, which the API still returns. Its status uses registration
`last_seen_at` (a five-minute window), rather than a live node health record.
The old registration was later deleted by hand (`DELETE /devices/registrations/{id}`).
Only one active Mesh node remains: `meshscale-docker-test`.

Final fresh-container run (command output, excluding Docker build output):

```text
Already ready: use_zt_virtual_ip = true
Already ready: gateway_proxy_enabled = true
Already ready: gateway_udp_proxy_enabled = true
Already ready: reusing device profile meshscale nodes
Dashboard step: Verify in the dashboard (no published API field): Cloudflare Zero Trust dashboard > Team & Resources > Devices > Device profiles > Global settings > Allow all Cloudflare One traffic to reach enrolled devices > Enable
Created Mesh node: meshscale-docker-test
Enrolled this machine.
Connected. Mesh IP: 100.96.0.2
100.96.0.2
MESH IP     DEVICE                                USER/OWNER                                      OS     STATUS
100.96.0.1  meshscale-docker-test                 warp_connector@example-team.cloudflareaccess.com  linux  online
100.96.0.2  meshscale-docker-test (this machine)  Mesh node                                       linux  online
Left meshscale-node-1 running on the default bridge network.
```

The commands after `up` are `meshscale ip` and `meshscale status`. Also verified
`meshscale ip -6`, `meshscale whois <mesh-ip>`, repeated `up` without enrollment,
and `down` followed by `up` without enrollment. The wait requires three
consecutive connected samples and an assigned Mesh IP: the client can briefly
reconnect while applying its initial profile.

## Dashboard step

This initial verification predates the automated connectivity-setting API.
Current setup reads and enables `offramp_warp_enabled` through the supported
connectivity-settings endpoint; use [account setup](../../docs/setup.md) for
current behavior. The remainder of this section records the earlier manual test.

The [Mesh guide](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/get-started/#required-account-settings)
identifies enrolled-device reachability as a dashboard-only setting. Neither
the published device-settings/profile API schema nor Gateway configuration
exposes a supported field for it. The CLI cannot determine its current value;
it prints this verification step on every setup/up:

**Cloudflare dashboard > Networking > Mesh > Add participant > Add device**, step
through until the download link appears, then close it. The current dashboard
has no visible toggle for this setting; running the wizard once enables it. ICMP proxying is also dashboard-only and optional;
it is not needed for TCP/UDP services and was not enabled. A connected node does
not prove peer-to-peer application connectivity; that needs a second participant
and the reachability setting above.

## Mesh IP and node identity

Live API evidence establishes this join:

1. `GET /accounts/{account}/warp_connector` supplies node ID, name, and health.
2. `GET /accounts/{account}/warp_connector/{node}/connections` supplies connector
   `id`, equal to the Linux WARP registration/device ID.
3. `GET /accounts/{account}/devices/registrations` supplies registration `id`,
   `device.id`, `virtual_ipv4`, `virtual_ipv6`, and `last_seen_at`.
4. `GET /accounts/{account}/devices/physical-devices` supplies OS and device data.

`origin_ip` is the public address, not the Mesh IP. Node registrations use
`registration_type: warp` and `user.email: warp_connector@<team>.cloudflareaccess.com`.

Real `warp-cli registration show` contains `ID` and `Device ID`, not the Mesh
node ID. `meshscale ip` matches that local identity to registrations directly.
`status` and `whois` join it to the node via the dedicated connections endpoint,
which avoids duplicate live node rows and uses node health for online state.

When fully disconnected, `/connections` returns an empty array. Verified links
are saved atomically in `~/.config/meshscale/mesh-state.json`, mode `0600`, scoped
to account and registration. This allows known offline node IPs and repeated
`up` after `down`. A node never observed online by this CLI has no reliable
remote offline join; hostname equality is deliberately insufficient. An
existing offline registration without cached identity may need `warp-cli
--accept-tos connect` once before `meshscale up` can recognize it.

Sources: [Mesh setup](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/get-started/),
[container guide](https://developers.cloudflare.com/mesh/guides/run-mesh-in-containers/),
[client settings](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/settings/),
[device profiles](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/device-profiles/).

## Implementation and checks

Added:

- `cmd/meshscale/up.go`, `down.go`, `setup.go`, `up_test.go`
- `internal/mesh/setup.go`, `setup_test.go`
- `internal/config/mesh.go`, `mesh_test.go`
- `test/docker/Dockerfile`, `e2e.sh`, `README.md`, `.dockerignore`, `.gitignore`

Updated `internal/cfapi/resources.go`, `internal/warpcli/warpcli.go` and tests,
plus `status`, `ip`, `whois` and status tests. No `go.mod`/`go.sum` changes.
The concurrent auth/login worker's files were not edited.

Passed `go vet ./...`, `go test ./...`, `git diff --check`, and `bash -n
test/docker/e2e.sh`. Tests exercise setup idempotency/preservation, conflicting
profiles, fresh/reused/conflicting enrollments, cached offline reconnection,
context cancellation, live/offline registration joins, account isolation,
state-file permissions, and real Linux WARP output parsing.

## Node-to-node connectivity (verified 2026-10-26)

Second container `meshscale-node-2` joined as `meshscale-docker-test-2` at
`100.96.0.3`. Before the wizard step, TCP SYNs to the other node were answered by
Cloudflare's edge with ICMP "host 100.96.0.2 unreachable". After running the
Mesh wizard once, TCP worked both ways in 30-65 ms, and each side saw the
other's real Mesh IP as the source address.
