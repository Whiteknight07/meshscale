# Keyless SSH over Mesh

`meshscale sshd` is a Linux SSH server authorized by the caller's Mesh device
registration. An ordinary OpenSSH client needs no SSH key or password:

```sh
# On the server, after WARP is connected. Requires root and account credentials.
sudo meshscale ssh policy init   # verified owner -> non-root local users
sudo meshscale sshd

# On another participant:
ssh alice@100.96.0.2
ssh alice@100.96.0.2 whoami
meshscale ssh alice@server-name hostname
meshscale ssh server-name             # defaults to your local OS username
scp report.txt alice@100.96.0.2:report.txt
sftp alice@100.96.0.2
```

The client resolves names/IPs using the same account device loader as `status`,
rejects ambiguous names/IPs, and executes the system `ssh` client. Flags precede
the target: `meshscale ssh --port 2222 alice@server-name hostname`.
Commands after the target have OpenSSH's usual remote shell semantics, including
shell expansion and quoting; they are not a direct remote argv API.

## Experimental Cloudflare authorization

For stock OpenSSH with Cloudflare-managed Access identity, policy checks and
short-lived origin certificates, Linux servers can opt in per host:

```sh
sudo meshscale ssh-mode cloudflare --users alice
meshscale ssh alice@server-name hostname
sudo meshscale ssh-mode own --init-policy   # restore own SSH; initialize policy if missing
sudo meshscale ssh-mode off   # remove this integration and stop own SSH on :22
```

`alice` must exist locally. Only the verified account owner can connect, and only
explicit `--users` names are allowed; root requires an explicit entry. The client
must have an owner-enrolled official WARP identity. Connector/service-token
registrations do not automatically acquire a person's identity. Cloudflare
terminates SSH and can inspect plaintext; meshscale manages an OpenSSH drop-in,
owned Access resources and rollback. The account CA is retained when opting out.

Gateway TCP proxying is account-wide. If disabled, the command stops and explains
`--enable-gateway-proxy`; it is never silently enabled. Existing OAuth users must
run `meshscale login` again to consent to `access-ssh-auditing.write`.
`status` exposes the cached SSH mode; unknown remote own/off states are shown as
`unknown`. Mode changes can take time to propagate through Cloudflare.

See [Cloudflare SSH](cloudflare-ssh.md) for provisioning, trust/privacy boundaries,
known limits, exact live certificate/refusal/rollback evidence, and resource IDs.
The remaining sections describe meshscale's own SSH server.

## Server configuration

```sh
meshscale sshd --port 22 \
  --state-dir /var/lib/meshscale \
  --policy /etc/meshscale/ssh.json
```

The server obtains its active WARP registration using `warp-cli`, reads its
Mesh IPs from the account registration API, and verifies those exact addresses
are assigned locally before binding. It binds IPv4 and IPv6 separately, with
no wildcard/public-interface fallback. Only default device ranges are supported:
`100.96.0.0/12` and `2606:4700:cf1:1000::/64` (see
[Cloudflare device IPs](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/device-ips/)).
Cloudflare's proxy/source ranges are excluded. Custom IPv4 pools are unsupported
in this release. A bind failure closes all listeners and suggests `--port` or
adjusting OpenSSH's `ListenAddress`; meshscale never changes OpenSSH settings.
Restart sshd after re-enrollment or a change in this server's Mesh addresses.

An ed25519 host key is generated once at
`/var/lib/meshscale/ssh_host_ed25519_key`. The state directory must be root-owned
0700; the private key must be root-owned 0600. Existing invalid/insecure keys
cause failure and are never silently replaced. Paths must be absolute; file and
directory symlinks and untrusted writable parents are rejected (root-owned
sticky directories such as `/tmp` are allowed as ancestors).

For SFTP and modern SCP, install `openssh-sftp-server` on Debian/Ubuntu or your
distribution's equivalent. The server executes the installed `sftp-server`
helper as the target user. It does not run a file server with root credentials.

## Policy

**With no policy file, meshscale's own SSH server denies every login.**
The listener and daemon still start. A startup warning and the client's SSH
banner explain the fix; `status` and the Mac app show
`SSH: no policy (denying all)` when the local daemon reports this state.
Root requires an explicit matching `root` rule; alternate names with UID 0 are
always denied.

Create a safe starter policy using the signed-in account owner's verified email:

```sh
sudo meshscale ssh policy init
sudo meshscale ssh policy show
sudo meshscale ssh policy test alice@example.com alice
sudo meshscale ssh policy test alice@example.com root # DENY by default
sudo meshscale ssh policy test alice@example.com alice --from device:00000000-0000-4000-8000-000000000008
```

`init` grants that owner access to existing non-root local accounts with usable
login shells. It does not grant other account participants access. Review which
local accounts the owner should use and narrow `users` below if needed. Root is
included only with an explicit `init --allow-root`; rootless servers reject that
flag and can serve only their own UID. Existing policies are never overwritten
without `--force`, including malformed policies. Publication is atomic, mode
0644, owned by the invoking root/server user. File and ancestor symlinks and
insecure ownership/modes are refused, even with `--force`.

The default system path is `/etc/meshscale/ssh.json`; non-root servers use
`<meshscale-config-dir>/ssh.json` (normally `~/.config/meshscale/ssh.json` on
Linux). The commands and sshd honor the daemon's configured `ssh_policy` path;
`--policy /absolute/path` selects an explicit file. Run commands as the same
user and with the same configuration as the server. A running server reloads
policy for every new authentication/session, so initialization needs no restart.

`show` pretty-prints the effective JSON. A missing file prints `{"rules": []}`
and a warning; a malformed or insecure file returns an error. `test` is offline:
it checks local account/shell eligibility, rootless UID limits and the same
rule matcher as sshd. It prints ALLOW with the first granting rule's number and
optional `name`, or DENY with the matching identity rules and reason (nonzero
exit status). Identity inputs are an email, `device:<id>`, or an admin-managed
Mesh node name. `--from` can additionally assert a node name/device ID or supply
a Mesh IP. An IP alone cannot establish a device ID or node name offline;
identity assertions are not proof of enrollment, routing, or remote access.
Self-reported user-device hostnames must never be used as Mesh node assertions.
Neither `show` nor `test` contacts Cloudflare.

`meshscale ssh-mode own` and `meshscale service install --ssh` offer to initialize
a missing policy in an interactive terminal. Use `--init-policy` for unattended
setup; it initializes only a missing policy and never overwrites an existing
one. Missing, invalid, empty, or locally unusable policies prevent setup from
reporting SSH ready. The low-level `sshd`/`daemon --ssh` commands remain available
for deliberately starting a denying listener. Cloudflare SSH policy semantics
are unchanged; an own-mode policy is required before restoring own mode.

### Upgrade from the permissive default

Older development installs without a policy allowed any active account
participant to log in as any non-root local user. **That fallback is removed.**
After upgrading/restarting, existing SSH-enabled daemons start with all new
logins denied and log a prominent migration warning. Run this on the server,
with the daemon's account credentials/configuration:

```sh
sudo meshscale ssh policy init
# With an explicit daemon policy path:
sudo meshscale ssh policy init --policy /absolute/path/ssh.json
```

Review the printed owner and scope, then use `policy test` and try a new SSH
connection. Existing explicit policies retain their rules, including deliberate
`{"rules": []}` denial. Already running sessions are not disconnected. Removing
a policy now denies access immediately at the next admission check.

A policy replaces default deny completely:

```json
{
  "rules": [
    {
      "from": ["alice@example.com"],
      "users": ["alice"]
    },
    {
      "from": ["build-runner"],
      "users": ["autogroup:nonroot"]
    },
    {
      "from": ["device:00000000-0000-4000-8000-000000000008"],
      "users": ["root"]
    }
  ]
}
```

`from` selectors match only identities a client cannot choose for itself:

| Selector | Matches |
| --- | --- |
| `*` | every active participant in the account |
| `alice@example.com` | devices enrolled by that user (case-insensitive) |
| `device:<id>` | one Cloudflare device (`device_id` in `meshscale status --json`) |
| `build-runner` | the Mesh node with that name; only account admins can name nodes |

A user device's name is the hostname it reports, so a plain name never
matches one: anyone in the account could register a laptop called
`admin-laptop`. Use the owner's email or the device ID instead.

Node names come from live node-to-registration connections. Owner emails always
come from the registration, even for Mesh nodes. Node names and device IDs are
case-sensitive; emails are case-insensitive. Patterns and nested groups are
unsupported. Any matching rule grants its listed users;
there are no ordered deny rules. `autogroup:nonroot` means UID != 0, not just a
username other than `root`. Nonexistent users and `false`/`nologin` shells are denied.

`{"rules": []}` denies everyone. An existing file must belong to root or, for
rootless servers, the server user. It must not be writable by group/others
(0600 or 0644 is appropriate), and its directories must be protected too. Malformed JSON, unknown fields, unsupported user groups,
symlinks, insecure ownership/modes, and read failures deny login. Policies are
read on every authentication and new session channel, so atomic file replacement
applies immediately. Removing the file denies all new logins and sessions.

## Identity and trust

SSH's encrypted transport, key exchange and `none` authentication callback use
[Go's x/crypto/ssh](https://pkg.go.dev/golang.org/x/crypto/ssh#ServerConfig).
There is no password, public-key, or keyboard-interactive authentication path.
The `none` callback succeeds only after all identity, local-user and policy
checks pass. PTYs use `github.com/creack/pty`.

The identity source accepts a Mesh source IP only when exactly one active,
non-revoked, non-deleted WARP registration in this account owns it. Duplicate,
unknown or incomplete registrations are denied. Registrations and node names
are cached for at most 15 seconds, with a 10-second lookup context and 20-second
handshake deadline. A failed refresh invalidates the snapshot; expired entries
are never reused during an API outage. A still-valid cache entry can authorize
until its TTL expires. New session channels recheck identity/policy and must
retain the registration, device ID and UID/GID used at the original handshake.
Existing running sessions are not terminated by a policy change or revocation.

This trusts Cloudflare's authenticated Mesh routing and preservation of source
IP, its registration API, account administrators, and the security of enrolled
devices. An IP address alone is not cryptographic proof of an individual person.
Any process able to originate traffic on an enrolled device receives that
device's identity. Connector nodes commonly share a synthetic
`warp_connector@...` owner; an owner-email rule can therefore authorize multiple
nodes. Device names/emails are mutable and names may be duplicated: prefer
narrow device rules and review who can enroll or rename devices. Stable,
explicitly typed identity selectors would improve a later policy version.

The client uses `StrictHostKeyChecking=accept-new`: first use is trust on first
use, and a changed key is rejected. Plain `ssh` uses the user's normal OpenSSH
host-key settings. For stronger first-connection trust, compare the fingerprint
printed by the daemon over a trusted channel and prepopulate `known_hosts` with
the public key. A future account API host-key registry (ideally signed/pinned)
could automate verified host-key distribution. Merely publishing a key through
the same account API still trusts that account/Cloudflare. WireGuard device-key
identity is the preferred v2 improvement for caller authentication.

Native/secure client host pins are stored in the private configuration's
`known_hosts` file. The file must be owned by the invoking user with mode `0600`;
symlinks and foreign-owned or exposed files are rejected before use. API-token
environment variables are removed before executing the system SSH client.

## Sessions, logging and limits

Shells use the target's `/etc/passwd` login shell; exec uses that shell with
`-c`. Processes receive the target UID, primary GID, supplementary groups, HOME,
SHELL, USER, LOGNAME and home directory as cwd. Their environment is constructed
fresh: daemon credentials and arbitrary client variables such as `LD_PRELOAD`,
PATH or HOME are not inherited. LANG and common LC_* locale variables are
allowed; TERM comes from the PTY request. SSH_CLIENT, SSH_CONNECTION and SSH_TTY
are supplied where applicable. PTYs have target ownership, support window resize,
and relay input/output. Exit codes are returned to OpenSSH. Session closure
kills the initial process group; successful commands can still launch detached
processes under their own user privileges, as with a normal shell.

TCP/Unix-socket forwarding, agent forwarding, X11 and unsupported channels or
requests are rejected. This does not restrict what an authorized shell user can
do, including running their own forwarding programs. Admission is bounded to
128 connections and 16 session channels per connection.

Every authentication/session admission decision logs the owner, device,
registration, Mesh source IP, local username and reason to stderr (journald when
run under a service manager). A normal command produces one authentication
accept and one new-session accept. Identity failures have empty fields where
identity could not be established. Forwarding refusals are also logged. Logs
contain identity metadata, not commands, credentials or session content.

This v1 has no PAM integration, account/password expiration checks, MFA, browser
re-authentication, utmp/lastlog updates, command recording, or
live disconnection on revocation. A locked password does not disable Mesh SSH;
use the policy or a disabled login shell to deny the account. PTY terminal modes
use Linux defaults; SSH terminal-mode overrides and signal requests are not yet
implemented (PTY Ctrl-C works through the terminal). Per-source rate limiting,
resource quotas and independent protocol/security review remain future work.
The daemon runs as root to switch local user credentials; this implementation
has not undergone an external security audit.

See [the container verification record](../test/docker/SSH.md) for exact test
outputs and the test daemon left running in node-1.

## WireGuard secure identity (v2)

Linux servers with secure mode enabled additionally accept `.secure` clients
through an authenticated WireGuard listener. Key-to-device identity and plain
Mesh downgrade protection are described in [secure mode](secure.md). Existing
SSH user policies still apply; non-secure participants retain Mesh-IP identity.

If Infrastructure target inventory cannot be read (for example, the token lacks
permission), `meshscale ssh` treats the SSH mode as unknown and continues with
normal SSH target resolution. Mode-specific behavior requires a known mode.
