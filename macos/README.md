# meshscale for macOS

A SwiftUI menu bar app for macOS 14 or later. Release app packages target Apple
Silicon. The app embeds the Go CLI and uses the official Cloudflare One client
for its network connection. No third-party Swift packages are required.

## Build and test

On a Mac with Swift 6 and the Go version in `../go.mod`:

```sh
./scripts/swift.sh build
./scripts/swift.sh test
```

SwiftPM caches and configuration stay under `.build/`. Tests inject command
runners and do not enroll a device, connect/disconnect WARP, launch Terminal,
or change login items. The optional snapshot exporter is in the test target:
`./scripts/snapshots.sh`. Existing screenshots are described in
[screenshots/README.md](screenshots/README.md).

For a remote build, create a fresh private `/tmp/meshscale-build-*` directory
on the authorized Mac. Copy this directory and the project LICENSE there,
excluding `.build`, `.swiftpm`, `.runtime`, `bin`, `dist`, and existing app
bundles. Build only in that directory and remove it when finished. Never sync
into an installed or running app, `/Applications`, or a shared build directory.

## Package an app

From the repository root, build the embedded CLI for the build Mac's CPU:

```sh
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -mod=readonly -trimpath \
  -buildvcs=false -ldflags '-s -w -X main.version=v0.1.0' \
  -o /tmp/meshscale-cli ./cmd/meshscale
CLI_BINARY=/tmp/meshscale-cli APP_OUTPUT=/tmp/meshscale.app \
  APP_VERSION=0.1.0 APP_BUILD=1 macos/scripts/build-app.sh
CLI_BINARY=/tmp/meshscale-cli python3 macos/scripts/test-build-app.py
```

`APP_OUTPUT` must be a new absolute `.app` path; existing bundles are refused.
The script verifies the CLI architecture, builds Swift in release mode,
includes the project LICENSE, artwork and only the app's Swift resource bundle, and verifies
both signatures before placing the result at the requested path. It never
runs the app or CLI. For Intel development, build an amd64 CLI on an Intel Mac;
Intel app artifacts are not currently released.

| Setting | Default | Purpose |
| --- | --- | --- |
| `CLI_BINARY` | `macos/bin/meshscale` | Darwin CLI matching the build Mac's architecture |
| `APP_OUTPUT` | `macos/meshscale.app` | New app destination |
| `BUNDLE_ID` | `com.whiteknight07.meshscale` | Reverse-DNS app identity; forks should set an identifier they own |
| `APP_VERSION` | `0.1.0` | Three-number bundle version |
| `APP_BUILD` | `1` | Positive integer bundle build number |
| `LICENSE_FILE` | `../LICENSE` | Project license to embed |
| `DEPENDENCY_LICENSES_DIR` | unset | Go dependency notices/report/inventory to embed before signing |
| `SIGNING_IDENTITY` | `-` | Ad-hoc signing; set to an installed Developer ID Application identity for distribution |

The release workflow supplies the Go dependency notices and module inventory.
Both binaries use hardened runtime. The app's only extra entitlement is
`com.apple.security.automation.apple-events`, for opening SSH sessions in
Terminal. `NSAppleEventsUsageDescription` explains that request; a local-network
purpose string explains Mesh peer access when macOS requests it. The app is not
sandboxed: the CLI needs the user's config directory and subprocess access.
The plist sets `LSUIElement=true` and `LSMinimumSystemVersion=14.0`.

### Optional Developer ID signing and notarization

The default CI zip is ad-hoc signed, **not Developer ID signed or notarized**.
Gatekeeper can block a downloaded copy. Public distribution should use an
owner-controlled Developer ID certificate and notarization. Apple's
[notarization guide](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
describes the requirements.

Set `SIGNING_IDENTITY` to the imported Developer ID Application identity when
running `build-app.sh`; it adds secure timestamps to both signatures. After
packaging, notarize a zip, staple the app, and recreate the distribution zip:

```sh
ditto -c -k --sequesterRsrc --keepParent /tmp/meshscale.app /tmp/meshscale-submit.zip
xcrun notarytool submit /tmp/meshscale-submit.zip \
  --keychain-profile meshscale-notary --wait
xcrun stapler staple /tmp/meshscale.app
xcrun stapler validate /tmp/meshscale.app
spctl --assess --type execute --verbose /tmp/meshscale.app
ditto -c -k --sequesterRsrc --keepParent /tmp/meshscale.app /tmp/meshscale-macos.zip
```

A CI signing variant should run only in a protected release environment after
an explicit opt-in (for example `vars.MACOS_SIGNING_ENABLED == 'true'`), with
certificate/password and App Store Connect credentials from environment-scoped
secrets. Import into a temporary keychain, use a temporary notarytool profile,
and delete both in an `always()` cleanup step. Never run signing or notarization
on pull requests. Generate SHA256SUMS and attestations **after** stapling and
repacking. The checked-in workflow has no signing secrets or notarization step.

## Behavior and trust boundaries

The app launches its embedded CLI by absolute path and argument array. Its
pinned PATH is `/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin`.
The runner drains both pipes, caps stdout at 8 MiB and stderr at 256 KiB, and
returns sanitized failures. It sends SIGTERM on cancellation, timeout or excess
output and escalates to SIGKILL after the command's cleanup grace period.
Enrollment gets 12 seconds; ordinary commands get one second. Raw command
errors, OAuth URLs and credentials never reach the UI. Ordinary app launches
share `~/Library/Application Support/meshscale/` with the CLI. The optional
`MESHSCALE_RUNTIME_HOME` development override changes only the child HOME.

Account state requires a decoded, nonempty account ID. Device responses reject
blank/duplicate IDs and more than one local device. JSON failures keep the last
successful inventory and show **Last known status**. Identity, local connection,
inventory and action errors are independent. Only a safe, confirmed
`local-status --json` connection produces **Connected**; recent remote device
activity does not imply a local tunnel. Unknown JSON fields remain compatible.

Connect/Disconnect captures the intended action when clicked. Polls pause during
account and connection actions; observations from before an action or a newer
completed fetch are discarded. Sign-out attempts `down` if the physical tunnel
may be active, still removes credentials if disconnect fails, and keeps a
**Turn off Cloudflare connection** recovery control. Quit cancels and joins CLI
and Terminal-automation children, including superseded commands, with a
14-second cleanup bound. Quit never launches `down`. See
[Mac enrollment safety](../docs/macos-enrollment.md).

SSH requires a safe local connection and an online, non-mobile remote device
with an address. The target is refreshed before launching `/usr/bin/osascript`;
a failed inventory refresh blocks SSH, and a superseding connection/account
action or quit cancels the request. The
Terminal command shell-quotes the embedded CLI path and `<Mac-user>@<Mesh-IP>`.
The remote server must permit that OS username. Terminal may require the user's
Apple Events approval. Launch at login uses `SMAppService` and may require
approval in System Settings; failures restore the system-reported state.

The views use main-actor state, native controls, accessible row labels/headings,
keyboard navigation, announcements, and Reduce Motion support. Clipboard,
VoiceOver, interactive OAuth, Terminal consent, and login-item approval still
need manual acceptance on an authorized Mac. With multiple Cloudflare accounts,
run the bundled CLI's `login` command in Terminal once to choose the account.
The development OAuth client's restrictions also apply to this app.

## Verification

Swift tests cover connection/action races, stale observations, cancellation,
quit cleanup, output limits, JSON identity validation, SSH quoting, accessibility
structure and layout. `test-build-app.py` verifies bundle metadata, hardened
runtime, entitlements, ad-hoc signatures, exclusion of test bundles, invalid metadata and refusal to
overwrite an existing app. Fixtures contain synthetic inventory data. CI runs
these checks on a Mac and produces a separately downloadable release zip.

Historical account-specific remote connection helpers have been removed. A
normal build/test/package verification must not change a real device's WARP,
Tailscale, login items or installed app.
