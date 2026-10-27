# Login and account setup

Historical verification record; personal account, host and resource identifiers in examples are anonymized.

`meshscale login` saves the selected Cloudflare account and OAuth session, then
runs the same account preparation as `meshscale setup` plus
`meshscale setup --devices`. The menu bar app already calls this Go login
command, so it gets the same behavior. No Swift changes are needed. Setup uses
the newly saved OAuth session directly, even if a development API token points
to another account. Setup failure leaves the login saved; retry with
`meshscale setup --devices` after resolving the reported problem.

**A completely new account still needs one Zero Trust Free plan activation in
the dashboard.** Organization creation and enrolled-device reachability are
API-supported; the remaining gap is Billing authorization through OAuth.
The default `meshscale` OAuth client is public (verified on
`meshscale.stavan.ai`), so any Cloudflare account can sign in with it.

## What setup changes

Only absent resources and required disabled flags are written. Every successful
write is described with `Changed:`; unchanged resources use `Already ready:`.
A ready account performs no writes. Setup never deletes resources, changes a
subscription, rewrites an existing profile, replaces an organization, or edits
an existing enrollment policy. It leaves Default, Gateway rules, optional ICMP
proxying, root certificate installation, and unrelated settings alone.

| Prerequisite | Read / create or enable API | OAuth scope |
|---|---|---|
| Zero Trust organization and team name | GET / POST `/accounts/{id}/access/organizations`; POST `{}` lets Cloudflare generate a unique `auth_domain` | `access-acct.write` |
| Zero Trust Gateway account | GET / POST `/accounts/{id}/gateway` | `teams.write` |
| Unique Mesh IPs; TCP and UDP proxying | GET / PATCH `/accounts/{id}/devices/settings`; enable only missing `use_zt_virtual_ip`, `gateway_proxy_enabled`, `gateway_udp_proxy_enabled` | `teams.write` |
| Enrolled-device reachability | GET / PATCH `/accounts/{id}/zerotrust/connectivity_settings`; patch only `{"offramp_warp_enabled":true}` | `teams.write` |
| Safe Mesh-node and owner-device profiles | GET `/accounts/{id}/devices/policies`; POST `/accounts/{id}/devices/policy`; read back owner profile before enrollment | `teams.write` |
| Email login provider, if the account has no Access apps or providers | GET / POST `/accounts/{id}/access/identity_providers`; create `type: "onetimepin"` | `access-acct.write` |
| Device enrollment app and owner-only policy | GET / POST `/accounts/{id}/access/apps` (`type: "warp"`, owner policy embedded atomically); existing app: GET / POST `/accounts/{id}/access/apps/{app}/policies` | `access.write` |
| Active Zero Trust plan | GET `/accounts/{id}/subscriptions`; setup never writes subscriptions | Billing Read; **no Billing OAuth scope exists in the current catalog** |

Node enrollment remains a separate, explicit `meshscale up` operation. Login
performs no local network changes, installs no service, and does not connect
WARP. Phones still need the Cloudflare One app, the generated/existing team
name, owner email login, and OS VPN approval; see [devices.md](devices.md).

Existing enrollment that allows other users, bypasses authentication, uses
service tokens, or has additional requirements/exclusions is refused. An owned
policy with different settings is also refused; setup no longer rewrites it.
Existing owner enrollment and supported PIN/GitHub providers are reused.
Unsupported IdPs, conflicting profiles, or unsafe precedence stop enrollment
with an account-specific settings link. Setup adds no new login provider to an
existing Access deployment, where that could weaken other applications.

## The two investigated manual steps (2026-10-26)

### Organization and Free subscription

Organization creation **can** be automated. The public OpenAPI schema for POST
`/accounts/{account_id}/access/organizations` explicitly says `auth_domain` is
optional: Cloudflare generates an `adjective-noun-hex4.cloudflareaccess.com`
domain when omitted. The app prints that domain instead of asking for a team
name. Existing organizations are only read. Authorization errors and API-router
404s are not treated as permission to create resources.

Free plan activation has a documented subscription endpoint, but **cannot be
automated by the current OAuth flow**. POST
`/accounts/{account_id}/subscriptions` requires **Billing Write**. The
read-only discovery calls established:

- GET `/billing/rate_plans/teams_free` returns rate-plan ID `TEAMS_FREE`, 50 users,
  with zero-price tiers.
- GET `/accounts/{id}/subscriptions` on the development account returns an active
  `teams_free` subscription (`state: "Paid"`, price 0, 50 users). This endpoint
  caps `per_page` at **50**, unlike most endpoints used here.
- GET `/oauth/scopes` with the development token returns 400 scope entries,
  including Zero Trust and Access permissions, but **no Billing Read or Write
  OAuth scope**. Requesting an invented Billing scope is not a solution.

No subscription POST was attempted. The rate-plan catalog and documented
subscription write API do not prove that an ordinary new account can activate
Free without payment/onboarding requirements. Accounts with no active plan stop
before Mesh configuration and receive one specific instruction:

```text
Dashboard step: No active Zero Trust subscription was found. Open https://one.dash.cloudflare.com/<account>/settings/billing; select Zero Trust Free (50 users, $0) if no plan is active, then run `meshscale setup --devices`.
```

OAuth may receive HTTP 403 when reading subscriptions. In that case setup
continues with the supported resource APIs, but explicitly reports that Billing
could not be verified and gives the same billing link. It does not claim full
readiness. Verifying the plan in the dashboard does not grant Billing API access;
a later OAuth run may still print this verification instruction. Other billing
read errors are returned rather than silently treated as an absent subscription.

**Unverified on a fresh account:** which Gateway/device reads or writes work
before a plan is active, their exact error responses, and whether organization
creation auto-provisions any additional resources. The configured dev account
cannot establish those facts. The implementation handles missing Gateway,
settings, and connectivity objects, but never interprets authorization failures
as missing settings or attempts a paid-plan change.

### Allow Cloudflare One traffic to reach enrolled devices

This **can** be automated. The setting is outside device settings and Gateway
configuration:

```http
GET /client/v4/accounts/{id}/zerotrust/connectivity_settings
PATCH /client/v4/accounts/{id}/zerotrust/connectivity_settings
Content-Type: application/json

{"offramp_warp_enabled":true}
```

The schema describes `offramp_warp_enabled` as enabling WARP-to-WARP traffic;
PATCH needs **Zero Trust Write**, already granted by `teams.write`. It also
exposes `icmp_proxy_enabled`; meshscale deliberately omits that optional field.
The official npm `cf` CLI **1.0.0-beta.21** exposes the same endpoint/flag
(`cf zero-trust connectivity-settings ... --offramp-warp-enabled`). The
cloudflare-go SDK and Terraform's `zero_trust_connectivity_settings` resource
contain the same two fields. The Mesh guide's “human-only” statement is stale
relative to the connectivity-settings API reference.

Read-only GET on the development account returned:

```json
{"icmp_proxy_enabled":true,"offramp_warp_enabled":true}
```

Device settings, Gateway configuration, and device profiles did not expose
this flag. No dashboard wizard was run, and no reachability PATCH was sent on
the development account. The API/schema and live enabled state establish the
control; a before/after connectivity test on a fresh account is still needed.

## OAuth registration

OAuth uses PKCE S256 and a random state, with an HTTP callback bound to IPv4
loopback. Pasted callback URLs must match the original redirect and state;
bare authorization codes remain bound to the login's PKCE verifier. Token,
revocation and userinfo requests reject redirects, and errors withhold response
contents. Logout holds the same file lock as token refresh, revokes the latest
saved refresh/access tokens, and only then deletes the login. A failed
revocation retains the login for retry. A new interactive login uses this lock
too, so an older in-flight refresh cannot overwrite it.

The configuration directory must belong to the invoking user with mode `0700`;
OAuth state and `dev.env` must be owned regular files with mode `0600`.
Symlinks, foreign ownership, writable ancestors and exposed file modes cause
failure. JSON state is bounded to 1 MiB, files are opened without following a
final symlink, and saves use a private temporary file and atomic rename.
For an existing installation, review ownership and repair permissions explicitly
(`chmod 700 <config>/meshscale`; `chmod 600 <config>/meshscale/dev.env
<config>/meshscale/oauth.json` for files that exist). Use the real configuration
path for that user; do not run a root daemon from another user's configuration.
The CLI removes Cloudflare API-token/key environment variables from browser
openers, system SSH clients, the Mac administrator prompt, diagnostic tools and
systemd control commands.

Login now requests:

```text
teams.write teams-connector-warp.write teams-connectors.write teams-networks.write access-acct.write access.write access-ssh-auditing.write access-service-token.write account-settings.read user-details.read offline_access
```

`access.write` is required for enrollment apps/policies. The experimental
Cloudflare SSH integration additionally requests `access-ssh-auditing.write`
(**Access: SSH Auditing Write**) for account SSH CA provisioning.
The live scope catalog lists `access.write` as **Access: Apps and Policies Write**. The
existing `access-acct.write` covers organizations/providers, not app policies.
Node, connector, route, service-token, account-read, user-read, and refresh-token
scopes remain for existing CLI functionality. No `openid` or invented Billing
scope is requested.

The bundled client `729d292b876c17b76bdb960f02410abd` (`auth.DefaultClientID`) is
**public**, secretless (token authentication `none`, PKCE), verified for
`https://meshscale.stavan.ai`, and registers exactly the scope list above with the
redirects `http://127.0.0.1:8976/callback` and `http://localhost:8976/callback`.
Keep the CLI's requested scopes (`internal/auth`) and the registered client
scopes identical. A self-registered client used through
`MESHSCALE_OAUTH_CLIENT_ID` needs the same scopes and redirect. When the scope
list changes, existing OAuth users must run `meshscale login` again to consent.

## Validation and fresh-account test

`httptest` coverage exercises absent organizations/Gateway/settings/connectivity,
no Access apps/providers, partial setup, ready accounts, missing plans, Billing
403, authorization failures, unsafe profiles, restricted/conflicting policies,
profile readback failures, repeated setup, and partial failure reporting. The
login test uses a new saved OAuth session even when environment credentials
point elsewhere, and checks that setup failure retains the login.

`go vet ./...`, `go test ./...`, and `git diff --check` passed on the shared
workspace after the concurrent macOS changes compiled. No host networking,
containers, Swift sources, or go.mod were changed by this task.

The opt-in real-account check runs the same helper as login and `setup
--devices`, with a transport that **rejects every non-GET request**:

```sh
MESHSCALE_LIVE_SETUP_CHECK=1 go test ./cmd/meshscale -run '^TestLiveSetupReadOnly$' -v -count=1
```

Verified result: **14 GETs, zero writes attempted or sent**, ending with:

```text
Already ready: Zero Trust organization example-team.cloudflareaccess.com
Already ready: Zero Trust subscription teams_free
Already ready: Zero Trust Gateway account
Already ready: use_zt_virtual_ip = true
Already ready: gateway_proxy_enabled = true
Already ready: gateway_udp_proxy_enabled = true
Already ready: offramp_warp_enabled = true
Already ready: reusing device profile meshscale nodes
Already ready: device enrollment application
Already ready: device profile meshscale user devices
Already ready: owner-only enrollment policy meshscale device enrollment: owner@example.com
Mesh is already ready (no changes).
```

A human must use a **new disposable Cloudflare account**, not reset the dev
account, to prove the remaining onboarding behavior:

1. Create the account and leave Zero Trust uninitialized. Register a separate
   private, secretless OAuth client for that test account with the listed scopes,
   PKCE, refresh tokens, and `http://127.0.0.1:8976/callback`. Use its ID through
   `MESHSCALE_OAUTH_CLIENT_ID`, and an empty configuration directory (no dev token).
2. Run `meshscale login`, approve once, and record organization creation and the
   billing instruction. With read-only requests, record Gateway/device/settings
   behavior before activating a plan; don't assume successful configuration means
   that a plan is active. This is the unproven API gating behavior above.
3. At the supplied billing link, activate **Zero Trust Free** once. Record whether
   Cloudflare requires a payment method. Retry `meshscale setup --devices` and
   verify only the reported missing resources/flags were created/enabled.
4. On separate disposable test devices, enroll via Cloudflare One using the
   printed team and owner email; verify Mesh TCP connectivity without running the
   dashboard Mesh wizard. Do not use the Tailscale host or existing containers.
5. Repeat setup; verify no resource writes. OAuth may still report its inability
   to read Billing; a Billing-capable test token can independently verify the plan.

## Sources

- [Cloudflare API OpenAPI schema](https://github.com/cloudflare/api-schemas/blob/main/openapi.json)
- [Create Zero Trust organization](https://developers.cloudflare.com/api/resources/zero_trust/subresources/organizations/methods/create/)
- [Connectivity settings API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/connectivity_settings/)
- [Create account subscription](https://developers.cloudflare.com/api/resources/accounts/subresources/subscriptions/methods/create/)
- [Rate-plan catalog](https://developers.cloudflare.com/api/resources/billing/subresources/rate_plans/methods/get/)
- [Available Zero Trust subscription IDs](https://developers.cloudflare.com/tenant/reference/subscriptions/)
- [Official cf CLI](https://github.com/cloudflare/cf)
- [Go connectivity settings implementation](https://github.com/cloudflare/cloudflare-go/blob/main/zero_trust/connectivitysetting.go)
- [Terraform connectivity settings model](https://github.com/cloudflare/terraform-provider-cloudflare/blob/main/internal/services/zero_trust_connectivity_settings/model.go)
