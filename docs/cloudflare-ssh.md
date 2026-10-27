# Experimental Cloudflare SSH over Mesh

Cloudflare SSH is an explicit Linux-server opt-in using stock OpenSSH and
Access for Infrastructure. Cloudflare authorizes the session and signs a
short-lived origin certificate. It terminates SSH and can read session
plaintext. Meshscale's own SSH server remains the default.

```sh
# Run on the target Linux server with the official WARP backend.
# Install openssh-server first. The listed local accounts must already exist.
sudo meshscale ssh-mode cloudflare --users alice
# Root is explicit: --users alice,root

# Run from an owner-enrolled official WARP client.
meshscale ssh alice@server-name hostname

# Restore the saved meshscale listener, or disable it.
sudo meshscale ssh-mode own
sudo meshscale ssh-mode off
```

`--enable-gateway-proxy` explicitly opts into **account-wide** TCP proxying if
it is disabled. It affects all enrolled clients, does not enable HTTPS
decryption, and does not change device profiles.

## Identity and origin trust

The verified signed-in owner email (or sole accepted account Super
Administrator for account-scoped tokens) is the only Access policy identity.
`--users` supplies explicit local usernames. No wildcard or implicit root
mapping is installed. Infrastructure certificates can carry the local username
as principal and the Access email as certificate ID; Access enforces the email,
and OpenSSH checks the principal against the account CA.

Meshscale reserves `/etc/ssh/sshd_config.d/50-meshscale-cloudflare.conf` and
`/etc/ssh/meshscale-cloudflare/`. The drop-in matches only the selected Mesh
address on port 22, accepts certificates from the account CA, uses explicit
per-user principal files, and disables other authentication and forwarding.
It does not rewrite the main SSH configuration. `sshd -t` and effective
`sshd -T -C` checks must pass before a previous meshscale listener is stopped.
A system OpenSSH service is reloaded; if none is active, a tracked OpenSSH
process binds only the selected Mesh address.

The CA is created only if absent and is never deleted during cleanup. Trust
files are recorded before writing; updates/removal refuse administrator changes,
symlinks, and untracked files. Public principal files are readable by their
local users; only root may change them. Local state uses the invoking
configuration's `cloudflare-ssh/state.json`, a mode 0600 file in a mode 0700
directory. Retain it until cleanup is complete.

## Remote resource ownership and recovery

A random 128-bit nonce is saved before any resource creation. The target
hostname is `meshscale-ssh-<nonce>` (a policy label, not DNS); the application
name includes the same nonce. Saved IDs alone never authorize an update or
deletion. Meshscale reads both remote resources and verifies their marker,
address/virtual network, application type, exact SSH target criteria, owner
email and explicit usernames before mutation. Effective policies are fetched
separately rather than trusting policy references in an application response.

API-assigned default virtual-network IDs are pinned when the target is first
created. Later changes fail closed. An interrupted POST is recovered only by
its journaled nonce and exact expected payload; duplicate or changed matches
stop recovery. Provisioning errors retain the ledger for a retry or cleanup.
Cleanup removes application interception before the target, then restores the
host. An API or ownership failure leaves certificate-only origin trust in place.

Legacy state without a nonce cannot prove remote ownership. Meshscale refuses
remote updates/deletes for those IDs. An administrator must review and remove
the legacy interception/target manually before clearing its recorded IDs and
running `ssh-mode own` to restore the local listener. Do not add a fabricated
nonce to adopt an existing resource. Restore `own` before changing the Mesh IP,
owner, resource name or username mapping, including after partial provisioning.

## API permissions

Use a token scoped to the selected account. API labels may say Edit in the
dashboard and Write in endpoint documentation; see the
[permission catalogue](https://developers.cloudflare.com/fundamentals/api/reference/permissions/).

| Feature | Endpoints under `/accounts/{account}` | Permission / OAuth scope |
| --- | --- | --- |
| Target create/read/update/delete and recovery | `/infrastructure/targets`, `/infrastructure/targets/{id}` | Zero Trust Edit / `teams.write` |
| Infrastructure app and effective policies | `/access/apps`, `/access/apps/{id}`, `/access/apps/{id}/policies` | Access: Apps and Policies Edit / `access.write` |
| Read/create reusable account CA | `/access/gateway_ca` | Access: SSH Auditing Edit / `access-ssh-auditing.write` |
| Settings preflight; explicit TCP proxy opt-in | `/devices/settings` | Zero Trust Read; Edit only for opt-in / `teams.write` |
| Local Mesh identity discovery | registrations, physical devices, WARP connectors | Zero Trust Read and Cloudflare One Connector: WARP Read |
| Owner lookup | `/user` outside account prefix, or account `/members` | User Details Read, or Account Settings Read for sole-owner fallback |

The login flow requests `access-ssh-auditing.write`; an older OAuth grant needs
fresh login consent. This mode does not configure command-log encryption,
rotate the CA, or install a broad Gateway allow rule. API references:
[targets](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/infrastructure/subresources/targets/),
[applications](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/),
[SSH CA](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/gateway_ca/).

## Verification and limits

Historical private-account validation on 2026-10-26 established a successful
owner certificate login over Mesh, denial of a different connector identity and
an unlisted root username, stable host keys, and restoration of the prior
meshscale SSH server during cleanup. No retained profile, routing, Gateway or
pre-existing application changes were reported. Private account identifiers,
personal emails and raw deployment artifacts are omitted from this public doc.

The OSS review used fakes and local tests only. New nonce ownership/recovery
checks have not been validated against a live account. Infrastructure changes
are eventually consistent; discovering a target does not prove edge enforcement.
Existing sessions need not terminate immediately after policy revocation.
Human-enrolled WARP login and automated connector/service-token enrollment
are different identities: a synthetic connector identity does not satisfy the
owner email policy. SCP/SFTP, recording and every enrollment mode are not
claimed as verified.

`meshscale ssh` uses cached daemon target inventory where available and invokes
system OpenSSH with private keys, agent and password authentication disabled.
It uses a separate `meshscale-cloudflare-<ip>` host-key alias and still rejects
changed host keys. A Cloudflare denial does not fall back to meshscale SSH.
Status reports remote target-derived `cloudflare`, the exact saved local mode,
or `unknown` when a remote own/off mode cannot be established.
