# Access rules

meshscale compiles a local JSON allow policy into Cloudflare Gateway network
(L4) rules. Without a policy file, sync does nothing and creates no rules.
Once a policy is synced, unmatched traffic **destined to Mesh device ranges**
is blocked. This does not configure SSH login authorization; see [SSH](ssh.md).

Save this as `~/.config/meshscale/rules.json` (or
`$XDG_CONFIG_HOME/meshscale/rules.json`):

```json
{
  "groups": {
    "servers": ["homelab", "nas"],
    "admins": ["alice@example.com", "macbook-air"]
  },
  "rules": [
    {"from": ["*"], "to": ["servers:22,443"]},
    {"from": ["group:admins"], "to": ["*:*"]}
  ]
}
```

Use strict JSON: comments, trailing commas and unknown fields are rejected.
`{"rules": []}` deliberately denies all traffic to Mesh device IPs.

## Selectors and ports

A `from` selector or the selector part of `to` can be:

- `*`: the default Mesh device ranges, `100.96.0.0/12` and
  `2606:4700:cf1:1000::/64`.
- An exact device name from `meshscale status`, including spaces.
- `group:servers`: a group defined in this file. Bare `servers` also selects
  that group, as in the example. Groups may contain other groups; cycles fail.
  An explicit group takes priority over an identically named device.
- An exact registration owner email. This expands to all that owner's devices;
  it is resolved to Mesh IPs, rather than becoming a Gateway user identity rule.
  Mesh nodes commonly share a synthetic `warp_connector@...` owner.
- A Mesh IP or CIDR within the default device ranges. Custom IP pools and
  subnet destinations outside these ranges are not supported by this policy.

Names/emails are case-sensitive. An unknown or ambiguous device name, unmatched
email or device without a known Mesh IP stops sync before Gateway writes.
Use IP selectors to disambiguate duplicate names. Offline devices with a known
cached registration/IP can still be resolved. Names, owners and IP assignments
are trusted account metadata; an IP selector can later refer to a new device if
that address is reused.

Each destination has `selector:ports`. Ports are `22`, `22,443`, `8000-8010`,
`22,8000-8010`, or `*`. The valid numeric range is 1–65535. IPv6 destinations
use brackets: `[2606:4700:cf1:1000::4]:443` or
`[2606:4700:cf1:1000::/64]:*`. Use `group:servers:22` for an explicit group.
All sources are alternatives, and destinations retain their own port lists.
Allows are directional; the policy describes new flows, not explicit return
packet rules. Gateway applies policies to enabled protocols, including TCP/UDP;
this is not a host firewall or control of traffic bypassing Cloudflare.

## Commands

```sh
meshscale rules check ./rules.json
meshscale rules sync --dry-run
meshscale rules sync
meshscale rules sync --file ./another-policy.json
meshscale rules list
meshscale rules reset
```

`check` validates against a fresh device inventory and shows both the planned
changes and full compiled rules. It makes only read API requests; the normal
local node-association cache can be updated. `sync --dry-run` does the same.
`list` prints the actual owned Gateway rules as JSON, including their IDs,
expressions, enabled state and precedence. Missing default files are a no-op;
an explicit missing path is an error. A `--file` path is used for that invocation
only. Keep one administrator's canonical file to avoid competing writers.

`reset` deletes every owned network policy, removing the deny first. Other
Gateway policies still apply. Remove or rename the default file when resetting
permanently; a later sync can otherwise reinstall it. Deleting a file alone
does not erase an already published policy: devices without a local policy
must not erase the administrator's centrally installed rules.

The `rules` device-sync hook is registered in `cmd/meshscale/rules.go` with
`internal/devicesync.Default`. Up/daemon callers of that registry recompile the
default file after inventory changes. The daemon must run under the policy
file's user/config directory and have Gateway write credentials. Editing the
file itself requires `rules sync`; a custom `--file` is not watched. The exported
`SyncRules` function is also available to command-level lifecycle callers.

## Gateway compilation and ownership

Each policy entry becomes one enabled `allow` rule. One final `block` rule
matches the Mesh destination ranges. Source addresses use
`net.src.internal_src_ip in {...}`; destination addresses use
`net.dst.ip in {...}`, combined with `net.dst.port` comparisons. The current
Gateway API accepts scalar IP selectors. Its documentation contains some array
selector examples that the live API rejects; these expressions were checked
against the real account API and native/MASQUE traffic.

All owned rules require **both** `meshscale rule: ` in the name and
`Managed by meshscale network rules v1; rule=` in the description, plus the
single `l4` filter. Sync/reset never edit DNS rules (`meshscale dns:`),
`Do Not Inspect`, `Default deny for private traffic`, or other customer rules.
Rule IDs are retained on updates; stale and duplicate owned rules are removed.

Lower precedence numbers run earlier. meshscale reserves unused values before
enabled customer network policies so a customer's earlier catch-all cannot
silently bypass the Mesh deny. It fails if there is insufficient space; it
never reorders customer rules. Allows run before the sole owned default deny.
The usual starting precedence is 1000. This ordering means Mesh access allows
can precede customer network blocks; review the compiled plan for your account.
DNS and HTTP inspection policies remain separate enforcement layers.

Cloudflare's published default is **500 network policies per account**,
including existing customer network policies; no lower Free-plan limit is
listed. A file with N allow entries uses N+1 policies. Sync checks both final
and temporary policy counts. API permission/plan errors are returned directly.
Enterprise accounts with raised limits currently still use this conservative
500-policy client guard. The Gateway expression limit is 140,000 characters.

Gateway changes are not transactional. Creates/updates run before stale-rule
removal; errors can leave a partial policy. Retry sync to reconcile or use reset.
Propagation can take about a minute, and already established flows can behave
differently from new flows. Simultaneous sync processes can race; use one policy
writer. Policy edits are not an immediate device-revocation mechanism.

References: [Network policies](https://developers.cloudflare.com/cloudflare-one/traffic-controls/network-policies/),
[Gateway rules API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/gateway/subresources/rules/),
[order of enforcement](https://developers.cloudflare.com/cloudflare-one/traffic-controls/order-of-enforcement/),
[account limits](https://developers.cloudflare.com/cloudflare-one/account-limits/).
