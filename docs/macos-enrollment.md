# Connecting the Mac safely

The macOS official backend uses Cloudflare One device registration, never the
Linux-only `warp-cli connector` command. Install the official client from
[Cloudflare's download page](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/download/).
meshscale discovers `warp-cli` in the app bundle as well as PATH.

## Browser enrollment

Run `meshscale up`, or choose **Connect** in the menu bar app. The selected
Cloudflare account's Access organization `auth_domain` supplies the team name.
Before enrolling an unregistered device, meshscale calls the same owner-only
setup implementation as `setup --devices`. Existing account resources are
reused; conflicting configuration fails closed.

The states are:

1. Missing client: show the official install link.
2. Personal/consumer registration: stop and offer **Clear personal registration
   and connect**. CLI consent is `meshscale up --replace-consumer`. This first
   disconnects, then deletes only the personal registration. Team registrations
   are never replaced by this flag.
3. Unregistered: run `warp-cli registration new <team>` and open the trusted
   `https://<team>.cloudflareaccess.com/warp` URL.
4. Registration pending: **Finish signing in in your browser**. The Cloudflare
   app's URL handler completes registration asynchronously. Poll `registration
   show`; a successful `registration new` exit is insufficient. A private pending
   marker prevents another `up` from restarting the browser for ten minutes.
5. Another Team organization: stop and explain how to leave it in Cloudflare One.
6. Correct Team registration: **Checking safety settings**, then **Connecting**.

Every macOS `Client.Connect`, including daemon reconnects, reads registration
and effective merged `warp-cli settings` immediately before invoking connect.
The expected team comes from the selected account API, never the local client's
untrusted organization setting. The guard requires Team + exact organization,
WARP traffic mode, and one network-policy Include list containing exactly the
Mesh IPv4 range `100.96.0.0/12`. It rejects Exclude mode, default routes, paired
half-Internet routes, Tailscale's broader range, unknown formats/destinations,
and wildcard hosts. Allowed destinations are Mesh IPv4/IPv6, Cloudflare's token
CIDR, the selected team's authentication host, and the existing GitHub login
hosts. This intentionally narrow policy may need an explicit code change for
another identity provider or a future client output format.

The initial profile has up to 30 seconds to arrive. A failed guard never invokes
connect. Cancellation/failure after a connect attempt disconnects with a fresh
timeout. No process can prevent the Cloudflare app itself or another program
from changing its policy after the check; meshscale also rechecks after connect.

`meshscale down` only disconnects; it preserves registration. `meshscale ip`
requires a confirmed connection and finds the address in the selected account.
`status --json` prefers the Mac's active registration UUID (labeled Device ID by
this client) before falling back to physical-device matching. The app reads
`local-status --json` for actual local connection/safety, independently of remote
inventory freshness. `up --json` streams sanitized, typed progress events.

The `safety_blocked`, `connection_failed`, `error`, `different_org`, and
`disconnect_failed` issues
expose **Turn off Cloudflare connection**. It cancels enrollment, allows up to
14 seconds for cleanup, then runs `down` with a 20-second command timeout. The
process runner escalates SIGTERM to SIGKILL after its cleanup grace period.
Every issue offers **Refresh**. Inventory fetch failures retain the last inventory
and mark it stale without changing successfully observed local connection state;
a failed Connect remains visible until dismissed or another action starts.
Sign out attempts disconnect whenever the physical tunnel may be active,
including unsafe/wrong-organization registrations and unknown/error observations.
It still attempts logout if disconnect fails, surfaces the failure, and keeps a
**Turn off Cloudflare connection** recovery control after sign-out. A confirmed
physically disconnected client needs no `down` command.

The connection button captures Connect or Disconnect at click time. Polling
cannot turn a Disconnect into Connect. Polls pause throughout connection and
account actions; observations started before an action or a newer completed
fetch cannot overwrite current state. Cancel also invalidates a sign-in restart
that is still waiting for the previous login's cleanup.

Quit defers application termination while owned CLI and Terminal-automation
children, including superseded login and enrollment processes, cancel and exit.
Cleanup allows the runner's SIGTERM/SIGKILL grace period, with a 14-second total wait limit. Quit
does not invoke `down` or start another login/connect flow. The pinned CLI PATH
includes system directories followed by `/opt/homebrew/bin` and `/usr/local/bin`.

SSH requires a safe connected Mac, an online target with an address, a non-mobile
OS (excluding iOS, iPadOS, Android, and phone), and a different device.
Terminal uses the current Mac username; the server must permit that username.
SSH requires a successful fresh inventory fetch; retained stale inventory is
display-only when revalidation fails. Pending account/connection actions block SSH.
An account/connection action or quit that supersedes SSH's inventory refresh
prevents Terminal from launching. CLI stdout is capped at 8 MiB and stderr at
256 KiB; excess output cancels the child and produces a sanitized error.
Blank/duplicate device IDs, multiple local devices and a blank account ID are
invalid responses and never replace the last successfully decoded state.

## Optional service-token enrollment (`--no-login`)

This route is implemented but has **not been run on the user's Mac**. It creates
no Cloudflare token, enrollment rule, or profile. An administrator must prepare
and review those resources separately. It refuses existing managed files.

Cloudflare documents [headless macOS enrollment](https://developers.cloudflare.com/mesh/guides/connect-client-devices/),
[Service Auth enrollment rules](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/device-enrollment/),
and [service-token profile selectors](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/device-profiles/).
The required existing rule is `decision: non_identity` (Service Auth), with one
Include service-token selector `{ "service_token": { "token_id": "<resource UUID>" } }`.
It must allow exactly that token, with no additional Require/Exclude conditions.
The token must be active, unexpired, and belong to the selected account.

The existing enabled WARP/MASQUE Include profile must match exactly
`identity.service_token_uuid == "<resource UUID>"`; the UUID is the token's API
`id`, **not** its client ID. Service-token devices use
`non_identity@<team>.cloudflareaccess.com`; the browser owner's email profile
does not match them. Matching the shared email would enroll all service tokens
into that profile, so this implementation requires the narrower UUID selector.
The profile must precede all other enabled non-default WARP profiles, include
the Mesh range, and contain only the same narrowly allowed destinations.

Place the already-issued token's `id`, `client_id`, and `client_secret` in a JSON
file owned by your user, mode 0600, inside a mode-0700 directory. Run:

```sh
meshscale up --no-login --service-token-file /absolute/private/path/token.json
```

The human must approve exactly one macOS **administrator privileges** prompt
to run the bundled `mac-mdm-install` helper. It will create, as root with mode
0600, `/Library/Managed Preferences/com.cloudflare.warp.plist`. Its parameters
are organization, auth_client_id, auth_client_secret, service_mode,
warp_tunnel_protocol=masque, onboarding=false, auto_connect=0, switch_locked=false.
The secret passes through a private temporary JSON file, never a command-line
argument or log. The temporary copy is removed when the parent exits; the root
plist retains the secret as required for managed enrollment. Existing `.plist`
or `/Library/Application Support/Cloudflare/mdm.xml` files are never overwritten.

The helper enrolls first with `service_mode=postureonly` and `warp-cli mdm
refresh`. It checks the delivered Team organization, exact profile ID and safe
Include routes before changing the same file to `service_mode=warp` and
refreshing again. It checks the full effective guard and disconnects before
returning to the ordinary guarded connection flow. It never calls connect
itself. On error it disconnects and retains Posture only mode for review.

This staging matters: Cloudflare's [MDM parameter documentation](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/mdm-deployment/parameters/)
says specifying auto_connect, even 0, defaults a new deployment to connected.
Zero permits an indefinite manual disconnect; it does not promise an initially
disconnected deployment. Posture only mode avoids a data tunnel before route
verification. Local administrator testing must confirm this client's exact
Posture only settings output and MDM refresh behavior; an unknown format fails
closed. The administrator must also approve retaining/removing this managed
file if abandoning the experiment. To remove it, first disconnect Cloudflare,
then remove the owned file with administrator approval and refresh MDM.

Do not test this route on the daily Mac until those administrator actions and
the new service-token account resources have been explicitly approved. No such
account resources or Mac managed files were created during this implementation.

The existing owner-only `setup --devices` validator deliberately rejects Service
Auth enrollment rules. The optional route verifies its own existing resources
and bypasses that setup path. Adding such a rule would require reconciling this
owner-only setup restriction before using browser enrollment on another fresh
device; this implementation does not broaden that validator.
