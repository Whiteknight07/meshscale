# Public sharing with Funnel

`meshscale funnel <port>` publishes a local HTTP service through a new,
remotely managed Cloudflare Tunnel. It creates a proxied CNAME such as
`ashburn-funnel.example.com` and runs `cloudflared` as a supervised child of the
meshscale daemon. No inbound firewall port, route change, quick tunnel, or
Cloudflare-owned public hostname is required.

```sh
meshscale daemon
# In another terminal; the HTTP server should bind 127.0.0.1:8000:
meshscale funnel 8000 --zone example.com --name ashburn
meshscale funnel status
meshscale funnel off
```

Use the same user and config directory as the daemon. An installed older daemon
must be upgraded before it can accept publication requests. For a connectivity
upgrade that cannot tolerate restarting the existing Mesh daemon, the new binary
can run `meshscale daemon --publications-only` alongside it. This mode supervises
only public sharing and cert renewal; it neither connects/disconnects Mesh nor
changes routes/firewall rules. Stop that temporary supervisor before starting a
full upgraded daemon, because both claim the same publication lock/socket.

Install `cloudflared` separately and put it on the daemon's PATH:
[Cloudflare downloads](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/).
On macOS, `brew install cloudflared` is supported. meshscale does not vendor,
download, install, or enable an additional cloudflared service. Missing binaries
produce installation instructions before creating any resources.

## Domain and public hostname

The first publication selects an active zone in the authenticated account.
`--zone example.com` explicitly selects a domain. Without it, exactly one active
zone must qualify; multiple eligible zones require `--zone`. Zone queries are
filtered by account and active status, and record counts use API metadata.
The selected zone and account are pinned in local state; later commands refuse
to switch that state to another account/domain.

The default name uses the same sanitizer as Mesh DNS: for example,
`Alice's MacBook Pro` becomes `alice-s-macbook-pro`. Explicit names must be valid
lowercase DNS labels. The hostname is `<name><suffix>.<zone>`. The default suffix is `-funnel`:

```sh
meshscale funnel 8000 --name ashburn --funnel-suffix=-public
# https://ashburn-public.<zone>
```

The name plus suffix must form one lowercase DNS label of at most 63 characters.
Dots, slashes, leading/trailing hyphens and longer results are rejected. An empty
suffix uses the default. A pre-existing record at that hostname causes an error,
even if it has the same value or a meshscale-looking comment. Only the exact
record ID created and recorded by this installation may be reused or deleted.

This single-label design is deliberate: Universal SSL on a full Cloudflare zone
covers the apex and one wildcard level (`*.example.com`). It does **not** cover
`ashburn.share.example.com`. Funnel works with the zone's Universal SSL without
buying Advanced Certificate Manager, enabling Total TLS, or ordering a new
certificate pack. Universal SSL must already be active on the zone, and normal
DNS/edge propagation still applies. See
[Universal SSL coverage](https://developers.cloudflare.com/ssl/edge-certificates/universal-ssl/limitations/).

Device certificate names use `<device>.mesh.<zone>` separately; those certificates
come from [ACME DNS-01](cert.md), rather than Cloudflare edge SSL.

## Owner-only Access

```sh
meshscale funnel 8000 --name ashburn --access-owner-only
```

This creates a new self-hosted Cloudflare Access application with one allow rule
for the authenticated owner's email, using the same email selector as device
enrollment. With an account-scoped API token that cannot read `/user`, meshscale
requires a sole accepted account Super Administrator to identify the owner.
Existing identity providers and organization configuration are reused; no broad
bypass rule or new identity provider is installed.

The application is created before DNS is published. The tunnel's hostname ingress
also requires cloudflared to validate an Access JWT against that application's
AUD and team, so delayed edge policy propagation cannot expose the localhost
origin anonymously. Unauthenticated HTTPS requests should redirect to the
organization's Access login page once the application propagates. An Access
redirect demonstrates the anonymous gate; it does not prove an interactive owner
login succeeded.

Changing between public and owner-only modes requires `funnel off`, followed by
a new `funnel` invocation. This also avoids changing unrelated Access apps.

## HTTPS localhost origins

External HTTPS terminates at Cloudflare. Plain HTTP is the default only for the
loopback hop from cloudflared to the origin. For a TLS origin:

```sh
meshscale cert ashburn
meshscale funnel 8443 --name ashburn --https
# Origin: https://127.0.0.1:8443, verified as ashburn.mesh.<zone>
meshscale funnel 8443 --name ashburn --https --origin-server-name app.example.com
```

The origin must serve a publicly trusted certificate for the selected origin
server name. Verification remains enabled; there is no `noTLSVerify` switch.
The tunnel's catch-all ingress returns 404 for other hostnames.

## State, lifecycle and cleanup

Private state is `<config>/meshscale/publication`, mode `0700`. Its
`publication.sock` and `state.json` are mode `0600`. A random 128-bit creation
nonce is journaled before each create attempt. Access application names, tunnel
names and DNS comments carry the nonce; DNS comments begin with
`managed-by: meshscale`. Returned resource IDs are journaled before proceeding.
If a create returns a server error or loses its response after the request was
sent (including connection resets, EOF and malformed successful responses),
meshscale reconciles only the exact attempted nonce and resource attributes.
Pre-send failures do not reconcile. Ambiguous matches fail. Access applications
must also be self-hosted and have exactly the intended owner-only policy.

GET/PUT/DELETE retry rate limits and server errors with bounded jittered backoff
and respect `Retry-After`. Before deletion, meshscale fetches each recorded ID
and checks its nonce. DNS checks also cover name, type, content and proxy setting;
Access checks also cover domain, type and owner-only policy. Changed resources
are preserved and reported. Predictable names and management comments without
this attempt's nonce never authorize reconciliation. Older resources without
creation nonces are preserved during cleanup and require manual removal.

`funnel status` reads local state/process status without Cloudflare API calls.
The status JSON also includes certificate paths/expiry and renewal failures; it
contains no tunnel tokens or private keys. `running` means the local connector
process is running, not that Cloudflare has completed DNS/edge propagation or
that the origin is healthy.

The daemon restarts crashed children with bounded exponential backoff. Tunnel
tokens are fetched at enable/startup, passed through the child environment, and
excluded from argv, persisted state and status output. Account API credentials
are filtered out of that child environment. An explicit empty configuration
prevents cloudflared from inheriting another tunnel's local configuration.

Stopping the daemon stops its child, preserving the saved Funnel for restoration
on the next startup. Before resuming, the daemon verifies the saved tunnel
nonce and, for owner-only sharing, the application ID and effective owner-only
policy. It then reapplies the owned ingress, including connector-side JWT
validation. A mismatch stops restoration before the connector starts. `funnel off` first persists disabled state and stops the
child, then removes its owned DNS, tunnel and Access application in that order.
It also works with the daemon stopped. Interrupted cleanup is retried on the next
startup/off. If cleanup fails, IDs stay in state and the error directs the user
to retry; a DNS deletion failure preserves the Access application.

Nothing is added to the Mesh reconcile tick. Idle publication has no timer or
API work; cert renewal uses its own expiry deadline.

## Live validation

The implementation's ashburn validation and resource audit are recorded in
[publication-live.md](publication-live.md).

## Token permissions

Use **Zone Read** and **DNS Edit** restricted to the selected zone, plus account
**Cloudflare Tunnel Edit** for tunnel creation, configuration, tokens and
cleanup. Automatic local-name discovery additionally uses **Zero Trust Read**
and **Cloudflare One Connector: WARP Read**. Owner-only sharing also needs
**Access: Apps and Policies Edit**, **Access: Organizations Read**, and
**User Details Read** to resolve the authenticated owner (or **Account Settings
Read** for the sole-owner membership fallback). Public sharing does not require
Access administration. Standard login OAuth scopes do not grant zone/DNS or
Cloudflare Tunnel administration; use a dedicated scoped API token where needed.

The Go client keeps ordinary TLS verification, a 45-second HTTP timeout and a
three-minute limit per API operation including retries. It never follows
redirects, caps responses at 16 MiB, and removes the bearer token from API/error
diagnostics. Page inventories fail on inconsistent or incomplete metadata.
