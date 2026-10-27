# Publicly trusted device certificates

`meshscale cert [name]` obtains or reuses a publicly trusted Let's Encrypt
certificate for `<device>.mesh.<zone>`, using ACME DNS-01 and the user's own
Cloudflare domain. The default device name and IPv4 Mesh address come from the
connected device's verified local Mesh registration. The default name uses the
Mesh DNS sanitizer (`Alice's MacBook Pro` becomes `alice-s-macbook-pro`).

```sh
meshscale cert ashburn --zone example.com
meshscale cert                    # default local Mesh name and saved zone
meshscale cert ashburn --staging  # untrusted Let's Encrypt test certificate
meshscale cert rm ashburn         # remove owned A record and certificate state
```

Names must be single lowercase DNS labels, not arbitrary FQDNs or wildcards.
The command publishes a DNS-only A record, for example:

```text
ashburn.mesh.example.com  A  100.96.0.7
```

The zone is selected and pinned as described in [Funnel](funnel.md). A name
already present in DNS is rejected rather than adopted, even if its value is
identical. Each record created by meshscale has a comment beginning with
`managed-by: meshscale` and containing a random creation nonce. The nonce and
attempted payload are saved before creation; its ID/name/content are then stored
in the private ownership ledger. Issuance and
renewal verify the saved ID, name, type, content, proxy setting and management
comment before any mutation. If the device Mesh IP changes, `cert` updates that
verified owned A record in place. Externally modified records are preserved.
Updates and cleanup preserve legacy DNS records without creation nonces and report that
manual removal is required. `cert rm <name>` deletes the verified owned A record, production/staging certificate
entries and their private generation directories; unrelated DNS records remain.

## What is public

Public DNS exposes the device hostname and private `100.96.0.0/12` Mesh address,
similar to publishing private Tailscale addresses under `ts.net`. This does not
make the service Internet-routable: clients still need Mesh connectivity and the
application must listen on its Mesh IP or be shared with `meshscale serve`.
Some DNS rebinding protections reject public answers containing private/CGNAT
addresses; the client resolver must permit the chosen Mesh domain. No Gateway,
router, routing table or firewall configuration is changed by `cert`.

The hostname is also disclosed in public Certificate Transparency logs. DNS-01
proves domain control without an Internet-reachable web server. Temporary
`_acme-challenge.<device>.mesh.<zone>` TXT records carry the same management
comment and are removed by their recorded IDs on success and error. If the
process is killed mid-challenge, daemon startup reclaims those recorded TXT
records. Other TXT values at the challenge name are left alone.

The production directory is
`https://acme-v02.api.letsencrypt.org/directory`. `--staging` uses
`https://acme-staging-v02.api.letsencrypt.org/directory`; it never falls back to
production. Production and staging have separate persistent ACME account keys
and certificate entries. Issuing accepts the selected CA's terms of service.
Staging certificates are not publicly trusted and must not be installed as the
production TLS certificate.

## Files and TLS use

The command prints JSON containing `name`, `ip`, `directory`, `cert_file`,
`key_file`, `not_after`, and `renew_at`. State lives beneath
`<config>/meshscale/publication`, with mode `0700` directories and mode `0600`
certificates, keys, ACME account keys and JSON manifests.

Every issuance writes the full PEM chain and a new P-256 private key into a new
private generation directory, then atomically publishes both paths together in
`state.json`. This prevents a reader from observing a new certificate paired
with an old key. After committing the manifest, meshscale removes the replaced
`cert-*` directory, after checking it is inside the publication store.
Install the returned pair in the local HTTPS service, or load it directly from
those paths. The chain includes intermediates for full TLS verification.

```sh
# After configuring the service with the returned cert_file and key_file:
meshscale serve 8443 --mesh-port 8443
# From a different connected Mesh device, using its normal CA trust store:
curl https://ashburn.mesh.example.com:8443/
```

The `serve` forward is unnecessary if the TLS service already listens on the
Mesh IP. Application certificate reload is the application's responsibility.
On renewal, reload the **new paths** from `state.json`, `meshscale funnel status`,
or a repeated `meshscale cert` invocation. Paths are immutable per generation;
meshscale removes superseded generations after publishing the replacement paths.
Applications must reload the new paths; already loaded certificate pairs remain
available in application memory.

## Renewal and daemon lifecycle

The running daemon owns renewal through the private publication socket. An
explicit cert request uses this daemon when available; if stopped, it takes the
publication lock and issues synchronously. For automatic renewal, keep the daemon
running under the same configuration. A temporary
`meshscale daemon --publications-only` can supervise renewal alongside an older
connectivity daemon without restarting Mesh or changing routes/firewall rules.

Renewal is scheduled at two thirds of the actual issued certificate lifetime,
which also supports short-lived certificates. There is no hourly/daily API scan
and no certificate work in the daemon's existing reconcile loop. An idle state
with no certificates has no renewal timer. A certificate already due at startup
is renewed immediately; failures retain the working certificate, appear in local
status and retry after one hour. Explicit requests before renewal reuse the
existing validated pair without ACME or DNS API calls. The saved account, zone,
CA directory and current desired Mesh IP are reused for renewal. The desired
address is stored once per hostname and shared by production and staging;
reissuing either CA entry after an address change updates that shared value.
Renewing the other entry cannot restore its older address. Older manifests are
migrated on load using the owned A record's saved content, with certificate IPs
as a fallback; the shared map is persisted with the next state save.

## Permissions and tests

The Cloudflare credential needs Zone Read and DNS Edit on the chosen zone, plus
**Zero Trust Read** and **Cloudflare One Connector: WARP Read** for local
identity discovery. Restrict DNS Edit to that zone. Standard login OAuth scopes
do not include zone/DNS administration; use a separate scoped API token when
those grants are unavailable. No Cloudflare
Origin CA certificate is used; the result is an ordinary public ACME certificate.

Unit/race tests use fake DNS, tunnel, process and ACME interfaces. The opt-in live
integration test is hard-wired to Let's Encrypt staging, uses a unique device
label, and removes all DNS it creates:

```sh
MESHSCALE_ACME_LIVE=1 MESHSCALE_ACME_ZONE=example.com \
  go test -v ./internal/publication -run '^TestACMEStaging$' -count=1 -timeout=12m
```

Credentials are read through meshscale's existing config environment loader.
Ordinary `go test` never contacts a certificate authority. Historical production
issuance was limited to one development device; it was not repeated during the
OSS review. See [publication-live.md](publication-live.md).

ACME issuance runs outside the publication state lock. Status reads a separately
guarded snapshot, and Funnel cleanup remains available during renewal. Certificate
issuance and removal are serialized; DNS changes retain ownership checks.
