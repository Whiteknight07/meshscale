# Phone and laptop enrollment

Phones join through the official Cloudflare One app, rather than a Linux Mesh
connector token. Login now prepares owner enrollment automatically. To retry the
complete account setup explicitly:

```sh
meshscale setup --devices
```

This command reads the signed-in user's email via OAuth userinfo or `/user` and
creates one owned allow policy containing that exact email. For an account API
token lacking User Details Read, it can instead verify an account with exactly
one accepted member who is a Super Administrator. Multi-member accounts without
a readable signed-in identity fail closed; use OAuth or grant User Details Read.
It never guesses an email from the account name or accepts a manually supplied
email. Login or `--devices` authorizes this owner-only setup; no additional
confirmation is needed.

The existing `warp` Access application and existing login providers are reused.
An existing owner-only enrollment policy is preserved; setup creates/reuses its
own `meshscale device enrollment: <email>` policy. It refuses existing policies
that permit other users, bypass authentication, or allow service tokens. It does
not modify existing enrollment policies, identity providers, Gateway policies,
tunnels, or the Default profile. Conflicting owned policies also stop setup.
A missing `warp` app is created with the owner-only policy embedded in the same
request, after the safe routing profile is verified. An email PIN provider is
created only when there are no existing Access apps or providers. The complete
setup also enables missing required Mesh account flags. Subscription activation
still needs the billing dashboard because OAuth has no Billing scope; see
[setup APIs and findings](setup.md). The account in this verification already
had the enrollment app and a separate owner-only policy.

## Safe routing before enrollment

Before writing an allow policy, setup creates and reads back the
`meshscale user devices` profile:

- Match: `identity.email == "<signed-in owner email>"`.
- Enabled WARP profile, MASQUE, before other non-default WARP profiles.
- **Include mode**, never Exclude/default-route routing.
- IPv4 Mesh range `100.96.0.0/12` and IPv6 Mesh range `2606:4700:cf1::/48`.
- The team's `*.cloudflareaccess.com` authentication host and, when using the
  existing GitHub provider, `github.com` and `api.github.com`.

The authentication hosts follow Cloudflare's Include-mode requirements. Other
IdP types fail closed until their required domains can be specified safely.
Browser Isolation and DNS block pages are not enabled by this command, so their
optional destinations are not added. Cloudflare may automatically route reserved
service IPs. General Internet traffic continues outside the Mesh tunnel.

The owned profile must exactly retain these routing/match settings; setup
refuses a conflicting or shadowed profile instead of modifying Default or an
unowned profile. Repeated setup performs no writes when the policy/profile
already match. Creating/verifying the profile first prevents a failed setup
from creating a new allow policy without safe routing. Existing enrollment
policies are never temporarily disabled during setup.

## Enroll in your account

1. Install **Cloudflare One** (Cloudflare One Agent) from the iOS App Store or
   Google Play. For a laptop, install the official Cloudflare One client.
2. Open it and choose the organization / Zero Trust sign-in flow.
3. Enter the **team name printed by setup** (for example `example-team`, not
   the full `cloudflareaccess.com` URL).
4. Sign in with **the owner email printed by setup** using the configured
   email one-time PIN or GitHub provider.
5. Approve the OS VPN configuration and connect.
6. In the client settings, confirm the organization and Include routing profile.
   Then open a private service such as `http://meshscale-docker-test.mesh:9000/`
   while it is being shared with `meshscale serve 9000`.

Use the organization sign-in flow before connecting. A consumer/personal WARP
connection can route general traffic through Cloudflare. Phones generally allow
one active VPN; migrate one device at a time if Tailscale is in use. No real
phone was enrolled during testing; the human performs these steps.

See the anonymized [API evidence and connectivity checks](../test/docker/SERVICE.md).

Sources: [device enrollment permissions](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/device-enrollment/),
[Access application policy API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/subresources/policies/methods/create/),
[Include-mode routing requirements](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/route-traffic/split-tunnels/).

## Online status

`meshscale status` first uses Cloudflare's registration `last_seen` (five-minute
threshold) or Mesh node health. iOS can leave `last_seen` stale while connected.
For an offline entry with an old or missing timestamp and an active Mesh IP,
status now tries a live reachability check. Deleted/revoked registrations and
deleted physical devices are excluded before any probing.

The probe uses unprivileged datagram ICMP echo on Linux (`ping_group_range`
must permit the caller's group) and macOS (`SOCK_DGRAM` ICMP). It never opens a
raw socket, invokes privileged ping, or changes routing, firewalls or sysctls.
Replies must match the source IP, echo sequence and random payload. TCP fallback
tries ports 22, 2222, 443 and 80, plus the daemon's configured SSH port. A closed
TCP port does not count as a successful reply. ICMP keeps listening while TCP
fallback runs, so slower mobile replies can still succeed. Unanswered probes
leave the Cloudflare-derived offline state intact; a sleeping or filtered device
can remain unreachable even if enrolled.

Each address has a 400 ms deadline. Sixteen workers run concurrently, with an
800 ms total batch budget so a large unreachable inventory cannot stall status.
Devices not reached within that budget retain their existing state. This work
overlaps the other status API reads. The private daemon caches positive and
negative results for 30 seconds, shares in-flight checks across callers and caps
network workers across simultaneous requests. Upgrade/restart the daemon to
activate this cache; an older or absent daemon uses a bounded local probe per
CLI invocation. No probe cache is written to disk.

Status JSON includes `online_source`: `cloudflare` for API-derived state,
`probe` after a successful live check, or `local` for this machine's native
backend state. `last_seen_at` remains Cloudflare's timestamp. The macOS model
reads this as an optional string, accepting older binaries and future sources.

For read-only verification, `meshscale status --json --test-stale-ip 100.96.0.2`
treats that active account device as stale in this invocation only. It changes
neither the registration nor the saved timestamp. An opt-in socket check is:

```sh
MESHSCALE_TEST_PROBE_IPS=100.96.0.1,100.96.0.2,100.96.0.6 \
  go test ./internal/reachability -run TestLiveProbe -v
```

Run the compiled test binary as an ordinary user to verify unprivileged ICMP.
Reachability failures are logged by this diagnostic test and are not test
failures: phones and laptops may be asleep. Ordinary tests use fake probers
and loopback TCP listeners and never contact these devices.

See the [recorded timing and live checks](status-verification.md) for this change.
