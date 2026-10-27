# Mesh DNS implementation handoff — 2026-10-26

Historical verification record; personal account, host and resource identifiers in examples are anonymized.

Implemented and tested in /path/to/meshscale. No commit or push.

## Design and usage

Gateway DNS Override policies work for the proposed design. Each rule matches an exact `dns.fqdn` and returns a Mesh IP. Both existing containers use Traffic-and-DNS mode (`WarpWithDnsOverHttps`) and the account Gateway DoH endpoint. Their Local Domain Fallback lists do not contain `.mesh`. No local daemon or hosts-file changes were needed.

- `meshscale dns sync [--dry-run]`: load participants through the existing status loader, compute names, diff against owned Gateway rules, then create/update/delete only those rules.
- `meshscale dns list`: show the actual owned rules in Gateway, including IP, enabled state and ID.
- `meshscale up`: sync after successful connection; failure prints a warning without failing up. The sync has a 30-second timeout within up's existing timeout.
- `meshscale status [--json]`: DNS NAME column / dns_name field.
- `meshscale whois <name-or-IP>`: accept a sanitized short name, FQDN (case-insensitive; optional trailing dot), or IP.
- Set `MESHSCALE_DNS_SUFFIX=example.mesh` in the syncing CLI environment to configure the suffix. The same variable controls status and whois. Default: `mesh`. Use the same suffix on every CLI that runs sync/up.

Labels are lowercase ASCII letters/digits/hyphens, capped at 63 characters, with `device` as the empty-name fallback. Numeric collision suffixes start at `-2`; natural names are reserved so duplicate `laptop` devices do not steal a real `laptop-2`. Assignment is deterministic by participant ID, independent of API ordering.

Prefer IPv4 when present, otherwise IPv6, with one address per participant. This avoids advertising a second address family that may not be routed by the deployed Mesh profile. Offline participants with unknown IPs keep any existing owned rule; a new participant without a known address cannot create a rule yet. Failures loading the inventory stop sync before Gateway writes.

Rule ownership requires BOTH:

- Name: `meshscale dns: <fqdn>`
- Description: `Managed by meshscale DNS v1; participant=<kind>/<ID>`

The participant marker allows a name/IP/suffix change to update the same rule. Existing owned precedence is preserved; new DNS overrides follow the existing DNS rules. Unrelated policies are never reordered or written. Removed participants and duplicate owned rules are deleted. The API list endpoint is unpaginated according to the published schema.

## Cloudflare findings

- Override returns a custom IP/hostname for a matching query; supports A, AAAA and HTTPS queries. Other matched record types are REFUSED. [DNS policies / Override](https://developers.cloudflare.com/cloudflare-one/traffic-controls/dns-policies/#override).
- The published default account limit is **500 DNS policies per account**, with Enterprise increases available. No separate lower Free-plan DNS-policy limit is listed. One participant consumes one of those policies, sharing the budget with existing DNS policies. Both rules were accepted by the provided account. [Account limits](https://developers.cloudflare.com/cloudflare-one/account-limits/#gateway).
- Policy propagation is documented as about **60 seconds**, with client DNS caching also relevant. [Policies FAQ](https://developers.cloudflare.com/cloudflare-one/faq/policies-faq/).
- Cloudflare now has native Internal DNS, but it is **Enterprise-only** and requires zones/views/resolver policies. Gateway overrides are appropriate for this Free-plan implementation and the permitted account changes. [Internal DNS](https://developers.cloudflare.com/dns/internal-dns/).
- API schema verified for list/create/PUT update/delete and `rule_settings.override_ips`. [Gateway rules API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/gateway/subresources/rules/).

## Initial sync and observed propagation

Sync started 2026-10-26 00:57:12.346 UTC and completed after 3.1 seconds:

```text
create  meshscale-docker-test-2.mesh  100.96.0.3
create  meshscale-docker-test.mesh    100.96.0.2
DNS synced: 2 change(s). Gateway propagation may take about 60 seconds.
```

Measured from sync start:

- +4.3s: node-2 lookup of meshscale-docker-test.mesh returned no entry; at +4.4s meshprobe reported NXDOMAIN.
- +4.6s: node-1 resolved meshscale-docker-test-2.mesh to 100.96.0.3; +4.7s TCP succeeded in 62ms.
- 00:57:46 UTC (about +34s): node-2 resolved 100.96.0.2 and TCP succeeded in 55ms. Node-1 also passed again (42ms).

Thus both names were observed working within about 34 seconds of sync start (about 31 seconds after completion). The second lookup was not continuously sampled, so its exact activation time is unknown.

## Final live outputs

The final statically linked Linux ARM64 binary was copied to `/usr/local/bin/meshscale-codex` in both containers. `/usr/local/bin/meshscale` was left untouched.

### node-1 dry run

```text
$ docker exec meshscale-node-1 meshscale-codex dns sync --dry-run
Dry run: 0 change(s); no Gateway rules written.
```

### node-1 sync

```text
$ docker exec meshscale-node-1 meshscale-codex dns sync
DNS synced: 0 change(s). Gateway propagation may take about 60 seconds.
```

### node-2 sync

```text
$ docker exec meshscale-node-2 meshscale-codex dns sync
DNS synced: 0 change(s). Gateway propagation may take about 60 seconds.
```

### DNS list

```text
$ docker exec meshscale-node-1 meshscale-codex dns list
DNS NAME                      MESH IP     ENABLED  RULE ID
meshscale-docker-test-2.mesh  100.96.0.3  true     00000000-0000-4000-8000-000000000004
meshscale-docker-test.mesh    100.96.0.2  true     00000000-0000-4000-8000-000000000015
```

### node-1 status

```text
$ docker exec meshscale-node-1 meshscale-codex status
MESH IP     DEVICE                                DNS NAME                      USER/OWNER  OS     STATUS
100.96.0.2  meshscale-docker-test (this machine)  meshscale-docker-test.mesh    Mesh node   linux  online
100.96.0.3  meshscale-docker-test-2               meshscale-docker-test-2.mesh  Mesh node   linux  online
```

### node-2 status

```text
$ docker exec meshscale-node-2 meshscale-codex status
MESH IP     DEVICE                                  DNS NAME                      USER/OWNER  OS     STATUS
100.96.0.2  meshscale-docker-test                   meshscale-docker-test.mesh    Mesh node   linux  online
100.96.0.3  meshscale-docker-test-2 (this machine)  meshscale-docker-test-2.mesh  Mesh node   linux  online
```

### node-2 whois by FQDN

```text
$ docker exec meshscale-node-2 meshscale-codex whois meshscale-docker-test.mesh
Mesh IP:       100.96.0.2
Device:        meshscale-docker-test
User/owner:    Mesh node
OS:            linux
Status:        online
DNS name:      meshscale-docker-test.mesh
Node ID:       00000000-0000-4000-8000-000000000016
Registration:  00000000-0000-4000-8000-000000000001
Device ID:     00000000-0000-4000-8000-000000000001
```

### node-1 whois by short name

```text
$ docker exec meshscale-node-1 meshscale-codex whois meshscale-docker-test-2
Mesh IP:       100.96.0.3
Device:        meshscale-docker-test-2
User/owner:    Mesh node
OS:            linux
Status:        online
DNS name:      meshscale-docker-test-2.mesh
Node ID:       00000000-0000-4000-8000-000000000013
Registration:  00000000-0000-4000-8000-000000000002
Device ID:     00000000-0000-4000-8000-000000000002
```

### node-2 resolves node-1

```text
$ docker exec meshscale-node-2 getent hosts meshscale-docker-test.mesh
100.96.0.2      meshscale-docker-test.mesh
```

### node-2 TCP to node-1

```text
$ docker exec meshscale-node-2 meshprobe dial meshscale-docker-test.mesh:8080
OK in 51ms: hello from 100.96.0.2:8080, you are 100.96.0.3:42520
```

### node-1 resolves node-2

```text
$ docker exec meshscale-node-1 getent hosts meshscale-docker-test-2.mesh
100.96.0.3      meshscale-docker-test-2.mesh
```

### node-1 TCP to node-2

```text
$ docker exec meshscale-node-1 meshprobe dial meshscale-docker-test-2.mesh:8080
OK in 49ms: hello from 100.96.0.3:8080, you are 100.96.0.2:46904
```

## Verification and files

Passed:

- `go vet ./...`
- `go test ./...` (all packages, including the other worker's then-current SSH package)
- `git diff --check`
- `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /path/to/meshscale/bin/meshscale-codex ./cmd/meshscale`
- `file` reports ARM aarch64 ELF, statically linked.
- Repeated sync on both nodes reports zero changes; dry run performs zero Gateway writes.
- Exact full-object API comparison before and after confirms `Do Not Inspect` and `Default deny for private traffic` are unchanged. Only the two owned DNS policies were added.

New files:

- internal/names/names.go
- internal/names/names_test.go
- internal/cfapi/gateway.go
- internal/cfapi/gateway_test.go
- cmd/meshscale/dns.go
- cmd/meshscale/dns_test.go

Modified files:

- cmd/meshscale/up.go
- cmd/meshscale/status.go
- cmd/meshscale/status_test.go
- cmd/meshscale/whois.go
- cmd/meshscale/whois_test.go

Tests cover sanitization, long labels, collision reservation, deterministic ordering, suffix/IP validation, create/update/delete/idempotency, unrelated-rule preservation, duplicate cleanup, offline unknown addresses, read-only errors, apply failure/ownership checks, HTTP methods/payloads, command dry-run/apply/list, status JSON/text, and whois names/IPs. The existing invalid-input whois test now isolates credentials to avoid a live API request after short names became valid.

No edits were made to go.mod, go.sum, internal/sshserver, ssh.go or sshd.go. Other-worker changes remain in the shared tree. No containers were stopped/restarted/removed; WARP settings, host DNS/routes/firewall and unrelated Cloudflare resources were untouched.

## Remaining limitations

- Phones were not physically tested. They should consume the same central answers while connected to the same account Gateway in Traffic-and-DNS mode; apps using an independent resolver and suffixes in Local Domain Fallback can bypass these answers.
- External inventory changes (including phone enrollment) need a later `dns sync` or successful CLI `up`; there is no periodic watcher. DNS resolution itself needs neither a meshscale process nor API credentials on each querying device.
- `status` and `whois` show names computed from the current inventory/suffix. `dns list` is the authoritative view of published Gateway rules; after a failed or deferred sync these can differ.
- Numeric collision assignments are deterministic for the current membership; removing/renaming a colliding participant can change another participant's assigned numeric name at the next sync.
- An offline node never observed by the current CLI still has the existing loader's unknown registration/IP caveat. Existing owned answers are retained, but unknown addresses cannot be invented.
- IPv4 is preferred; dual-stack records and reverse PTR records are not provided. Gateway Override does not implement a complete authoritative DNS zone.
- Read-only or higher-priority customer DNS rules may prevent resolution; sync does not alter or bypass them.
- Simultaneous sync processes can race to create duplicate rules; a later sync reconciles duplicates. No account-wide locking is available here.

Evidence artifacts (ignored under bin/): dns-before.json, dns-after.json, dns-live-outputs.json, meshscale-codex, and this report.
