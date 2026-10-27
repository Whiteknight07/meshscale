# Install and enroll

## Quick install (release)

**Release delivery is prepared, not published.** The commands below become usable once the owner publishes a reviewed release. The tag workflow creates a **draft only**; a manual workflow run uploads test artifacts without creating a release or attestations. Packaging requires an owner-reviewed root `LICENSE` and dependency notices. Until these gates are resolved, use the from-source path below. A release download does not grant OAuth access.

For a prepared Cloudflare account with an active Zero Trust plan and authorized OAuth client or supported API credentials, the documented Linux path is **3 command phases** under the [roadmap metric](roadmap.md#onboarding-baseline-and-measurement-method): install, `up` (browser sign-in → setup → enrollment → connection), verify a known peer service. Previously `login` was a separate fourth phase. This removes one CLI invocation; it does not remove browser consent or hide authentication/connection/DNS time. A fresh account adds dashboard Free-plan activation and a retry of `up`, for **5 phases**. Tool installation, extra account-selection/OS prompts, provisioning the known peer and recovery cases must be recorded separately. This is a static walkthrough count, **not** a timed user trial or a claim that the roadmap's independent-user/time gates passed. Public OAuth availability remains a separate release gate; see [account setup](setup.md).

The guided installer supports Linux amd64/arm64 on Debian 12/13, Ubuntu 22.04/24.04/26.04, and EL 9/10 (RHEL, CentOS, Rocky, AlmaLinux, Oracle Linux). **Support qualification remains pending:** target Debian/Ubuntu first; track EL separately until normal dependency installation passes. Have `curl`, `tar`, `gzip`, SHA-256/coreutils, and `awk` available; Debian/Ubuntu client setup also needs GnuPG. EL client setup requires the distribution's appropriate EPEL repositories enabled first. Cloudflare package availability can vary by release/architecture; consult the [official package repository](https://pkg.cloudflareclient.com/).

1. **Download, verify and install.** No Go or Git required. Download the installer as a file, verify it against the release manifest, then run it. `--with-cloudflare-client` explicitly permits official repository/package setup if `warp-cli` is missing. Without that flag, the installer only prints those instructions and installs meshscale. Package-manager dependency/signature failures stop setup; it never bypasses dependency checks.

   ```sh
   release=https://github.com/Whiteknight07/meshscale/releases/latest/download
   # For a pinned version instead: release=https://github.com/Whiteknight07/meshscale/releases/download/vX.Y.Z
   curl --fail --location --proto '=https' --proto-redir '=https' --output install.sh "$release/install.sh" &&
     curl --fail --location --proto '=https' --proto-redir '=https' --output SHA256SUMS "$release/SHA256SUMS" &&
     awk '$2 == "install.sh" { print; found++ } END { if (found != 1) exit 1 }' SHA256SUMS > install.sh.sha256 &&
     sha256sum --check install.sh.sha256 &&
     sudo -H sh ./install.sh --with-cloudflare-client
   # With a pinned download above, also pass --version vX.Y.Z to the installer.
   ```

   The installer verifies the selected archive before extracting/installing anything. It installs `/usr/local/bin/meshscale`, retaining the previous binary as `meshscale.prev`; it does not connect a VPN or install the meshscale service by default. `--dry-run` prints the planned commands with read-only host detection and no downloads or writes. `--service` explicitly permits installing/enabling/starting the meshscale system service, using root's HOME/config; alternatively enable it after login/up using the service section below. Client/service flags are restricted to the default prefix to protect local test runs.

2. **Sign in and connect** with the same user/configuration as the optional root service:

   ```sh
   sudo -H meshscale up
   # Optional: --hostname my-linux-node --no-browser --account ACCOUNT-ID
   ```

   `up` opens the browser, or prints the URL over SSH and accepts a pasted callback URL/code. It saves login before preparing the account, then enrolls and connects the node. Follow any Free-plan billing link once and rerun `sudo -H meshscale up` to resume. Existing node/account setup is reused; ready resources are not rewritten. A deliberate `down` remains paused until enrollment and connection succeed. The existing Mac app still uses `login` followed by `up --json`; its JSON progress format is unchanged.

3. **Verify a known peer's TCP service.** The peer must already be connected and serving the chosen port; provisioning it is excluded for both products in the roadmap metric.

   ```sh
   sudo -H meshscale ping --port 22 my-peer
   ```

   `Connected` confirms the carrier and a Mesh address; this peer probe establishes the headline metric. `meshscale status` is optional diagnosis, not another required onboarding command.

Keep an independent management path available when changing networking. The [experimental native backend](native.md) is a separate opt-in. Enrollment conflicts, missing account permissions or an inactive Zero Trust plan need the recovery steps below, not an installer bypass.

### Release integrity, local testing and rollback

Tagged releases contain `meshscale_linux_amd64.tar.gz`, `meshscale_linux_arm64.tar.gz`, and the groundwork for Mac delivery: `meshscale_darwin_arm64.tar.gz` (**CLI only**, not an app bundle). Each archive contains the static CLI, project `LICENSE`, short README, dependency-license CSV and collected third-party license/notice files. `SHA256SUMS` covers archives and `install.sh`; filenames stay stable within each versioned release URL. Builds inject the tag into `meshscale version`.

Checksums detect corruption and rely on the downloaded HTTPS manifest. They are not independent publisher signatures. Tagged builds also create GitHub artifact attestations; if you have GitHub CLI, verify provenance before installation with `gh attestation verify ./meshscale_linux_amd64.tar.gz --repo Whiteknight07/meshscale` (choose your architecture). The owner reviews the project/dependency licenses and security/support gates before publishing the draft. Mac app packaging, ad-hoc signing and attended enrollment qualification remain separate roadmap #3 work; there is no notarization claim.

For offline/local artifact validation, use the same archive layout and manifest:

```sh
sh scripts/install.sh --from-dir /path/to/artifacts --prefix /tmp/meshscale-test --dry-run
sh scripts/install.sh --from-dir /path/to/artifacts --prefix /tmp/meshscale-test
# Run installation again with a newer archive to retain the previous binary.
sh scripts/install.sh --rollback --prefix /tmp/meshscale-test
sh scripts/install.sh --uninstall --prefix /tmp/meshscale-test
```

`--from-dir` copies and verifies local artifacts without a release download. `--prefix DIR` installs into `DIR/bin`. Installation writes a private receipt at `DIR/share/meshscale/install-receipt` (mode **0600**, containing directory **0700**). Its tab-separated entries contain the fixed relative installed paths (`bin/meshscale` and, when present, `bin/meshscale.prev`) and their SHA-256 hashes. Upgrades and rollback atomically rewrite the receipt; uninstall removes it after removing the binaries.

All existing destination ancestors and the temporary-directory base are checked
before file operations. Symlinked directories, foreign owners and group/other
writable installation directories are rejected; root-owned sticky ancestors
such as `/tmp` remain supported. Install into a directory owned by the invoking
user or root. `test/docker/install_test.sh` exercises the offline lifecycle,
modified binaries, bad/duplicate checksums, symlink destinations and dry runs
without starting any service or VPN.

Upgrade, rollback and uninstall check every affected existing binary before changing anything. An absent/invalid receipt, an untracked binary (including a source build), or a changed hash stops the operation and prints the path to review/delete manually. `--force` explicitly bypasses these ownership/hash refusals; use it only after reviewing both binaries. Symlinks and non-regular files remain refused. `--dry-run` performs the same read-only ownership checks and prints planned receipt operations without writing anything. Rollback restores and consumes `meshscale.prev`; it fails clearly if no backup exists. Stop an existing service before changing binaries and explicitly restart it when ready. Neither rollback nor binary uninstall changes services, enrollment, credentials or Cloudflare packages. Root binary uninstall at the default prefix removes the marked hosts DNS block through the verified installed CLI; alternate-prefix tests never touch `/etc`. If hosts cleanup is needed, a missing/modified/untracked CLI is never executed, including with `--force`: run `dns cleanup-hosts` with a trusted CLI first. **Complete the Linux network/service cleanup below before `sudo -H sh ./install.sh --uninstall`**; that operation removes both installed and backup binaries. Keep private state for recovery.

### Self-update

```sh
meshscale update --check
sudo -H meshscale update
sudo -H meshscale update --version v1.2.3
sudo -H meshscale update --rollback
```

The CLI selects the platform archive from the published GitHub release, verifies its exact unique `SHA256SUMS` entry before extracting/replacing anything, stages beside the installed executable, atomically replaces it, and retains `meshscale.prev`. `--check` reads only release metadata; `--rollback` uses no network and restores/consumes the backup. Installer receipts are refreshed when present. The updater repository is defined once in `internal/selfupdate.Repository`. Supported assets match `release.yml`: Linux amd64/arm64 and Darwin arm64 CLI. Unknown platforms/missing assets fail clearly. This updates the CLI only; updating the signed Mac app bundle and automatic updates remain separate work. Restart an existing daemon explicitly when ready. A failed receipt refresh after binary replacement is reported and needs repair before installer operations.

### .mesh names with another system resolver

Root `up` and the root daemon automatically check known `.mesh` names through the system resolver. When resolution fails or returns stale addresses, they maintain only a `# BEGIN meshscale hosts v1` / `# END meshscale hosts v1` block in `/etc/hosts`. Other lines are preserved byte-for-byte, including CRLF and a formerly missing final newline. The daemon uses its existing inventory-change hooks; unchanged inventory adds no DNS checks, timer, or file rewrite. If the daemon is not running, `up` seeds a snapshot; start the optional daemon for continuing inventory updates. Hosts fallback always uses `.mesh`; a custom Gateway DNS suffix does not rename this block.

```sh
sudo -H meshscale set --dns-hosts=auto  # default, check system resolution
sudo -H meshscale set --dns-hosts=on    # explicitly use hosts
sudo -H meshscale set --dns-hosts=off   # disable and remove only the block
```

These DNS preferences are set separately from secure/exit preferences. An auto-created block is retained until `down`/disable so its own successful lookups do not disable the fallback. `down`, daemon shutdown, service uninstall and default-prefix root binary uninstall remove the block. Root is required on Linux and macOS; the ordinary Mac menu app does not gain root implicitly. A read-only `/etc/hosts` fails safely. A bind-mounted one (as in Docker) can't be atomically replaced, so meshscale rewrites it in place while holding its lock, writing the new contents before truncating so an interrupted write never leaves the file empty. Meshscale writers share a lock; detected concurrent edits are retried against fresh contents and persistent conflicts fail with a retry instruction. An editor that ignores the lock can still race the final rename; ordinary files provide no universal compare-and-swap against arbitrary editors.

Hosts tests use temp files. The opt-in live resolver test refuses to run outside Docker; it launches a private mount namespace over the container's `/etc`, checks `getent hosts peer.mesh`, and verifies exact cleanup. With a local test image containing `unshare` and `getent`:

```sh
go test -c -o /tmp/meshscale-hostsdns.test ./internal/hostsdns
docker run --rm --network none --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
  --entrypoint /tmp/hostsdns.test \
  --mount type=bind,src=/tmp/meshscale-hostsdns.test,dst=/tmp/hostsdns.test,readonly \
  -e MESHSCALE_CONTAINER_HOSTS_TEST=1 meshscale-e2e \
  -test.run '^TestContainerSystemResolver$' -test.v
```

The image's normal entrypoint is explicitly bypassed; no VPN service runs. This test does not qualify live Cloudflare DNS propagation or macOS resolver caching.

### Shell completion

```sh
meshscale completion bash > ~/.meshscale-completion.bash
source ~/.meshscale-completion.bash
meshscale completion zsh > ~/.meshscale-completion.zsh
source ~/.meshscale-completion.zsh  # after compinit
meshscale completion fish > ~/.config/fish/completions/meshscale.fish
```

Command names and descriptions come from the live command registry. This covers top-level commands; nested arguments/flags are not yet modeled by that registry.

## Linux (from source)

Use Go **1.27.3 or newer** (see `go.mod`) and Git. The default backend uses the official Cloudflare One client. Install and enroll one device at a time; the guided release installer is optional and is not used by this source path.

### 1. Install the official Cloudflare One client

Use a supported OS/architecture from [Cloudflare's downloads](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/download/). These commands follow the [official package repository](https://pkg.cloudflareclient.com/) and [Linux Mesh guide](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/guides/run-mesh-on-linux/).

On Debian/Ubuntu, install `curl` and `gnupg` first if absent, then:

```sh
curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | sudo gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(. /etc/os-release && echo "$VERSION_CODENAME") main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list
sudo apt-get update
sudo apt-get install -y cloudflare-warp
```

On EL9/RHEL-compatible systems, enable the appropriate EPEL repository for your distribution first; Cloudflare's RHEL 9+ packages depend on it. Where `epel-release` is available:

```sh
sudo dnf install -y epel-release
curl -fsSL https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo | sudo tee /etc/yum.repos.d/cloudflare-warp.repo
sudo dnf install -y cloudflare-warp
```

Start the official service and check its CLI:

```sh
sudo systemctl enable --now warp-svc
warp-cli --version
warp-cli --help
```

**EL9 aarch64 dependency exception.** On the tested Oracle Linux 9 ARM64 host, `cloudflare-warp-2026.8.2115.0-1.el9.aarch64` could not resolve desktop WebKit/GTK dependencies alongside existing Fedora ICU/Harfbuzz libraries. That host used the unchanged official RPM with `rpm -ivh --nodeps` after installing `nss-tools` and `tpm2-tools`, importing Cloudflare's signing key, verifying the RPM signature, and checking that extracted `warp-cli`/`warp-svc` had no missing shared libraries. Desktop dependencies remain unresolved and future package updates need care. This is a **recorded headless-host workaround**, not the normal install procedure: `--nodeps` skips all dependency checks. Prefer fixing repositories/dependencies or using a supported OS; do not downgrade/remove system libraries to imitate the test. See [the exact host record](linux-host.md#oracle-linux-arm64-verification-2026-10-26).

### 2. Build meshscale

```sh
git clone https://github.com/Whiteknight07/meshscale.git
cd meshscale
go build -o bin/meshscale ./cmd/meshscale
sudo install -m 0755 bin/meshscale /usr/local/bin/meshscale
meshscale --help
```

### 3. Sign in and connect

Use the **same user and configuration** for login, enrollment and daemon. The system service runs as root, so these examples consistently use root's HOME:

```sh
sudo -H meshscale up --hostname my-linux-node
sudo -H meshscale status
sudo -H meshscale ip -4
```

`--no-browser` prints an authorization URL and accepts the resulting callback URL/code, which is useful over SSH. For multiple accounts, select one interactively or use `up --no-browser --account ACCOUNT-ID`. If using your own OAuth client, supply `MESHSCALE_OAUTH_CLIENT_ID` to this `up` process as described in [setup](setup.md).

`up` saves OAuth and prepares the account, safe profiles and owner enrollment. If setup reports a dashboard requirement, complete it and retry `sudo -H meshscale up`; the saved login is retained. It then creates/enrolls a Linux Mesh node and connects only after checking its Team organization and effective Mesh Include profile. Existing personal/other-team registrations require operator attention; Linux has no automatic consumer replacement flow.

Existing API-token users need `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN` in the same configuration's private `dev.env` or process environment. These take priority over OAuth. Keep credentials private; do not put token values in command arguments or source control. For the system service, persist credentials in that root configuration or use saved OAuth: the installer does not copy shell environment credentials into the unit.

### 4. Optionally install the background service

Use a stable binary path, as above:

```sh
sudo -H meshscale service install --print
sudo -H meshscale service install
sudo -H meshscale service status
```

The first command only prints the systemd unit; the second installs, enables and starts it. SSH is off by default. Configure a narrow [SSH policy](ssh.md) before opting in with `sudo -H meshscale service install --ssh`. Alternatively, `sudo -H meshscale daemon` runs in the foreground without installation. Never run competing daemons for the same configuration.

The service checks/reconnects the selected backend and reconciles devices. `meshscale down` is remembered, so the service stays disconnected until the next explicit `up`. See [service lifecycle](service.md) and [Linux routing/firewall coexistence](linux-host.md).

Secure mode is optional and Linux-only. `sudo -H meshscale up --secure` runs in the foreground; with an existing service, use `sudo -H meshscale set --secure=true` instead. Linux exit nodes additionally require root, kernel WireGuard, forwarding prerequisites and nftables. Read [secure mode](secure.md) and [exit-node prerequisites/recovery](exit-nodes.md) before enabling them.

### Linux rollback and uninstall

For a temporary disconnect, stop the reconnect loop first:

```sh
sudo systemctl stop meshscale.service
sudo -H meshscale down
```

For removal, **first deselect any exit while the CLI and its configuration still exist**:

```sh
# Only when an exit was selected/offered or secure mode enabled:
sudo -H meshscale set --exit-node=
sudo -H meshscale set --advertise-exit-node=false --secure=false

# If explicit WARP buffer tuning was applied, undo it before removing the CLI:
sudo -H meshscale tune --warp-buffers --undo

sudo -H meshscale service uninstall
sudo -H meshscale down
sudo -H meshscale logout
sudo rm /usr/local/bin/meshscale
```

Stop any manually started foreground daemon too. Exit deselection is essential: daemon loss intentionally retains its leak guard, and deleting state first can leave routing blocked. Do not remove exit guard tables or recovery files by hand; use [exit recovery](exit-nodes.md). Service uninstall preserves enrollment and private configuration. Logout revokes saved OAuth, not API tokens, Mesh registration, shared DNS/rules/routes, or account resources.

If also removing the official client, explicitly delete **this device's** registration only when you intend to re-enroll later, then use your distribution's package removal:

```sh
sudo warp-cli --accept-tos registration delete
# Debian/Ubuntu:
sudo apt-get remove cloudflare-warp
# EL/RHEL-compatible (choose this instead of apt):
sudo dnf remove cloudflare-warp
```

Remove the repository file/signing key only if no longer needed. In Cloudflare, review/revoke the old registration and remove any owned Mesh node/routes or key-directory record no longer needed; do not delete shared account resources used by other devices. For native enrollment, `down --forget` is the explicit deregistration operation; see [native lifecycle](native.md).

Retain a private backup of `/root/.config/meshscale/` (or the actual `XDG_CONFIG_HOME` location) for rollback. It contains credentials and private keys. For a binary rollback, stop the service, restore a known-good binary at `/usr/local/bin/meshscale`, then start the service again. After network cleanup, the inactive configuration directory may be archived/deleted deliberately; deleting keys changes secure identity on re-enrollment.

## macOS

### Build and test the menu bar app

Install Xcode with its command-line tools, Go 1.27.3+, and the [official Cloudflare One client](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/download/). The app targets macOS 14+; the supported build below is Apple Silicon. Build in a dedicated checkout, separate from any running app or unconfirmed local changes:

```sh
git clone https://github.com/Whiteknight07/meshscale.git meshscale-ci
cd meshscale-ci
mkdir -p macos/bin
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o macos/bin/meshscale ./cmd/meshscale
cd macos
./scripts/swift.sh test
./scripts/build-app.sh
```

`build-app.sh` builds the release Swift executable, embeds the Darwin CLI and resources, ad-hoc signs the bundle, and verifies signatures. `swift.sh` keeps SwiftPM caches inside this checkout. Intel app delivery has not been verified. This is not a notarized distribution; downloaded builds may require Finder's **Open** approval. See [the app README](../macos/README.md).

When ready to use this build, quit another meshscale menu app before opening it:

```sh
open meshscale.app
```

Testing alone does not require launching/replacing your running app. Optional `./scripts/snapshots.sh` renders fixtures using the bundle in the current checkout and exits without opening the app UI or connecting a VPN.

### Sign in, then Connect

Choose **Sign in with Cloudflare** and complete OAuth in the browser. This prepares account/owner enrollment but does not connect the Mac. If several accounts require an interactive choice, run the bundled CLI once in Terminal, then reopen the menu app:

```sh
./meshscale.app/Contents/Resources/meshscale login
```

Choose **Connect**. The app enrolls through Cloudflare One and shows browser sign-in, safety checking and connection progress. Approve the Cloudflare client's requested OS permissions. A personal registration requires the separate **Clear personal registration and connect** action. Another team's registration is never silently replaced.

Before every connection, the guard requires Team registration in the selected account's exact organization and a narrow Mesh Include routing profile. It rejects Exclude/full-tunnel/unknown routing settings; it does not disable another VPN or alter its routes. A failed guard stays disconnected and offers recovery. Confirmed local tunnel state, rather than remote inventory freshness, drives **Connected**. See [the guard and optional managed enrollment](macos-enrollment.md).

Mac secure/exit mode is gated off. Peer handshake/exit details are informational and do not mean the Mac uses the encrypted overlay or that Internet egress was tested. Phone targets have no menu-app SSH action. The app's Terminal action uses the current Mac username, which the target server must allow.

### macOS rollback and uninstall

Choose **Disconnect**, turn off **Launch at login** if enabled, then quit meshscale. Remove the build's `meshscale.app` bundle. For rollback, open a previously retained bundle after quitting the current one; keep your prior source/build directory until satisfied. If you separately installed a daemon with a rendered launchd plist, stop/remove that exact job; automatic `service uninstall` is Linux-only.

For OAuth sign-out, use the app or its bundled CLI **before deleting it**:

```sh
./meshscale.app/Contents/Resources/meshscale logout
```

Sign-out is not device deregistration and leaves configured API credentials active. Keep or privately archive `~/Library/Application Support/meshscale/` for rollback; deleting it removes saved login/state. In Cloudflare One, leave the organization/delete the device registration only if you intend to re-enroll. If using administrator-managed enrollment, have its owner remove only the managed file/profile they installed; removing the menu app does not remove Cloudflare management.

To remove Cloudflare One too, use its [official uninstaller](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/uninstall/), accepting the administrator prompt:

```sh
cd '/Applications/Cloudflare WARP.app/Contents/Resources'
./uninstall.sh
```

Leave the official client installed if another team/application needs it. Review/revoke this device's stale registration in the Cloudflare account; do not reset shared enrollment policies.

## iPhone, iPad and Android

There is no meshscale mobile binary. On your signed-in desktop/server, `meshscale login` already prepares owner enrollment; retry explicitly with `meshscale setup --devices` in that same configuration if needed.

1. Install the official **Cloudflare One Agent** from your device's app store, following [Cloudflare's manual enrollment guide](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/manual-deployment/).
2. Enter the team name printed by setup (the prefix of its `.cloudflareaccess.com` organization domain).
3. Sign in as the exact owner email allowed by setup, using its configured login provider, and approve the OS VPN configuration.
4. Connect. Verify the device appears in `meshscale status` and can reach a known Mesh service.

Phones use ordinary Mesh, not secure mode or Linux exit-node selection. Their OS permits one active device VPN in the usual setup; connecting Cloudflare may replace another VPN. Setup creates a narrow Include profile rather than intentionally routing all phone Internet traffic. Enrollment/profile conflicts stop setup for review rather than broadening access. See [phone/laptop enrollment](devices.md).

For a temporary rollback, disconnect Cloudflare One and reconnect the previous VPN. For uninstall, sign out/leave the organization, disconnect, remove the app and any remaining VPN profile belonging to it in OS settings. Managed devices may require the administrator to remove the deployment profile. Revoke the corresponding device registration in Cloudflare if it should no longer be trusted. Manually installed inspection certificates must be removed separately; meshscale setup does not install one. Reinstalling and enrolling with the same team/owner restores access without resetting account policies.
