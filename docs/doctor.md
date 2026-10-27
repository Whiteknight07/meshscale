# Doctor and local bugreports

Run diagnostics using the same user and configuration as enrollment and the
meshscale daemon:

```sh
meshscale doctor
meshscale doctor --json
meshscale bugreport --out /tmp/meshscale-bugreport.tar.gz
```

`doctor` prints `ok`, `warn`, or `fail`, the measurement, its result, and an
actionable hint. JSON has `version` and an ordered `checks` array containing
`name`, `status`, `measurement`, `detail`, and `hint`. Exit status is 1 if any
check fails; warnings alone return 0. Invalid arguments also return a nonzero
status. Each check runs concurrently with a 2.5-second deadline, inside a
10-second total budget. Healthy checks normally complete in under 3 seconds.
There is no extra daemon timer, poller, refresh request, or persistent cache.

The checklist covers the installed official client/version, selected backend
connection state, unique active registration in the configured account, Team
organization and effective safe Include profile, daemon reachability and last
successful sync age, secure engine/errors/handshakes, saved SSH mode and daemon
SSH enablement, a system resolver lookup of a known Mesh name, WARP route and
MTU evidence, Tailscale coexistence, an authenticated account-organization GET,
and one peer reachability probe. The daemon records every successful device poll
(default every minute), including when nothing changed; a last sync older than
three minutes warns, and a reported sync error fails. An absent daemon warns unless enabled secure mode
requires it. A deliberately paused connection warns.

DNS uses cached inventory when available; without it, names are derived from
active account registrations with the normal name allocator. This fallback may
not reflect a Mesh node's custom name. `MESHSCALE_DNS_SUFFIX` is respected.
One successful lookup does not verify every name or every resolver. The API
GET tests account authentication and organization-read permission, not all
permissions required by other commands. Saved OAuth access tokens are used
without refresh: an expired token fails with a login hint. Doctor makes no
account or credential changes. Its diagnostic `warp-cli` executor allows only
status, registration and settings reads. Doctor reaches `warp-cli` only after
`meshscale up`/`setup` saved a backend, where the terms were already agreed.
Like the rest of meshscale it passes `--accept-tos`: without a TTY, Linux
`warp-cli` refuses every command otherwise, and the flag is not saved, so it
changes no consent state. If a read still fails with a terms prompt, affected
checks warn with `unavailable: Cloudflare One terms not accepted yet`.

On Linux, the existing netlink snapshot reader supplies routes, policy rules
and links. Doctor requires the full `100.96.0.0/12` WARP route and checks that
sample address `100.96.0.1` actually selects WARP. A peer-specific route can
still differ. With `tailscale0`, it checks a narrow table-52 lookup before the
inverted WARP lookup, refuses to claim safe overlap when table 52 has a default
route, and reads `ts-input` to check its first ingress exception. A missing
iptables chain is reported explicitly; permission errors warn and never cause
privilege escalation. MTU is the interface setting, not measured path MTU.

On macOS, local client, backend, registration, API, resolver and available
daemon data are checked. `route -n get` supplies a sample utun route and MTU;
WARP ownership and coverage of the whole prefix remain unverified and warn.
Linux policy rules/iptables are not available there. Secure mode retains its
existing platform limitations.

The shared reachability helper can succeed through datagram ICMP echo **or** a
TCP connect on a common service port. Doctor reports that combined measurement,
not ICMP RTT. `meshscale ping` separately measures a TCP connect to the chosen
port. An unanswered peer warns because it may be asleep or have no probed port
open. A WireGuard handshake is labeled **handshake seen**, and public egress
is labeled **unverified**: doctor sends no public-egress test traffic. SSH mode
and daemon enablement do not establish successful SSH authorization.

`bugreport` writes only after explicit `--out PATH` or an affirmative local
prompt. With confirmation it chooses a timestamped file in the current
directory. It never overwrites an existing destination. Archives and their
members have mode 0600. No upload path exists.

The tar.gz contains allowlisted doctor JSON (check names and statuses), parsed
meshscale/Go/OS/official-client versions, boolean and enum service/secure
configuration fields, and discovered WARP table numbers. Doctor details, hints,
measurements, raw route/rule output and other free-form command output are
withheld. Unknown JSON fields are dropped, including their names; allowed fields
also require the expected type and a reviewed enum or version grammar. Missing
or unreadable JSON sources get an unavailable field with its content withheld.

When `journalctl` is available, at most the last 500 daemon journal lines are
read. Only validated timestamps from short-iso records and timestamps/levels
from JSON records survive; all arbitrary message content is withheld, including
nested JSON, escaped emails and unlabelled key material. Unrecognized lines are
replaced with `[redacted]`. Each source has a ten-second collection deadline and
a 1 MiB limit; oversized config files are withheld and command output is
truncated to that limit. Config reads and commands never modify routes,
firewall rules, services, consent or account resources.

Credential files, enrollment state, private key files, packet captures and
vendor diagnostic bundles are excluded. The export allowlist withholds OAuth
access/refresh tokens, Mesh node/connector tokens, WireGuard private keys,
Access service-token client secrets, ACME account keys, certificate private
keys, API tokens from `dev.env`, emails and unknown future credential fields.
Known local credential values are additionally scrubbed from permitted strings.
Over-redaction is deliberate; review the archive before sharing it.
