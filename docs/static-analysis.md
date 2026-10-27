# Static analysis, CI and release artifacts

CI builds and tests source without production credentials or deployment steps.
Each job grants only the GitHub permissions it uses. Checkout credentials are
not persisted. Actions use full commit SHA pins with version comments;
Dependabot groups weekly Go, npm (both projects) and GitHub Actions updates.
Analyzer binaries have explicit versions; update these pins deliberately.

## Pull request checks

| Check | Coverage |
| --- | --- |
| Go on Linux amd64 and arm64 | Formatting, vet, Darwin vet, uncached race tests |
| Cross-build | Static CLI binaries for Linux amd64/arm64 and Darwin arm64 |
| Staticcheck v0.8.2 | Go correctness and style diagnostics |
| Govulncheck v1.9.0 | Reachable Go vulnerabilities; runs even if staticcheck fails |
| JavaScript | Locked install with lifecycle scripts disabled, `npm audit --omit=dev` in `control/` and `app/frontend/` |
| Control | Tests and TypeScript typecheck |
| Frontend | TypeScript check and reference frontend build |
| macOS | Swift tests, release app packaging and signature/metadata regression tests |
| Workflow lint | Actionlint v1.7.12 and offline zizmor v1.16.3 |
| CodeQL | Go, JavaScript/TypeScript and Swift, plus a weekly scan |

Jobs have timeouts. New CI/CodeQL runs cancel superseded runs for the same ref;
release jobs serialize by ref. CodeQL requires code scanning enabled. It is
available for public repositories; private forks need the relevant GitHub plan.
Go and Swift use manual CodeQL builds; JavaScript uses source analysis. See
[GitHub's build-mode documentation](https://docs.github.com/en/code-security/reference/code-scanning/codeql/build-options-for-compiled-languages).

Go tests run as an ordinary hosted-runner user, with no sudo or integration
opt-ins. Privileged namespace, TUN, real-device and live-account tests are
explicit opt-in tests; normal CI never connects or reconfigures a device.
Swift tests use injected command runners. Packaging tests sign only temporary
bundles ad hoc and never launch the app or its CLI. See the test source for
platform/root-specific skips.

Local checks:

```sh
gofmt -l .
go vet ./...
GOOS=darwin go vet ./...
go test -race -count=1 ./...
go install honnef.co/go/tools/cmd/staticcheck@v0.8.2
go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
staticcheck ./...
govulncheck ./...
(cd control && npm ci --ignore-scripts && npm test && npx tsc --noEmit && npm audit --omit=dev)
(cd app/frontend && npm ci --ignore-scripts && npm run build && npm audit --omit=dev)
go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
actionlint
# Install zizmor in an isolated environment first:
zizmor --offline --persona pedantic .github/workflows
```

On a Mac also run `macos/scripts/swift.sh build`,
`macos/scripts/swift.sh test`, and the packaging checks in
[macos/README.md](../macos/README.md).

## Draft release contract

A `vMAJOR.MINOR.PATCH` tag (optionally with prerelease/build metadata) builds
packages and opens a **draft** release after checksumming and attestation.
A manual workflow run exercises packaging only, using a development version;
it does not create a release or publish attestations. Release builds disable
shared caches and use read-only module resolution. Publishing a draft remains
an owner action.

The installer contract is unchanged:

| Release asset | Contents |
| --- | --- |
| `meshscale_linux_amd64.tar.gz` | Linux amd64 CLI, project/dependency licenses, build inventory and README |
| `meshscale_linux_arm64.tar.gz` | Linux arm64 CLI with the same supporting files |
| `meshscale_darwin_arm64.tar.gz` | Darwin arm64 CLI with the same supporting files |
| `meshscale_macos_arm64.zip` | Apple Silicon menu bar app with embedded CLI, project/dependency notices and inventory |
| `meshscale_<os>_<arch>.buildinfo.txt` | Native Go module inventory: exact versions, sums and build flags |
| `install.sh` | Installer from the tagged source |
| `SHA256SUMS` | SHA-256 digests for every asset above |

The Linux installer consumes the existing underscore-separated CLI archive
names and SHA256SUMS. Changes to installer verification belong with the
installer; no macOS zip is substituted for a CLI tarball.

CLI builds use `CGO_ENABLED=0`, `-mod=readonly`, `-trimpath`,
`-buildvcs=false`, and a version ldflag. Explicit source commit IDs live in
BUILDINFO and artifact provenance, avoiding checkout-path/dirty-state metadata.
Tar ordering, owner/group, permissions and timestamps are normalized to the
source commit; gzip excludes wall-clock metadata. Go module inventories come
from `go version -m`, rather than a standard SPDX/CycloneDX SBOM. Swift app
zips are not claimed to be reproducible across Xcode/macOS versions.

Tagged archives, app zips, inventories, installer and checksum manifest receive
[GitHub build provenance attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations).
Only the attestation job gets OIDC/attestation write permissions; it does not
check out or execute project source. Only the final draft-creation job gets
contents-write permission. All downloaded artifacts come from the current run.
Verify a downloaded artifact, using the actual repository and release path:

```sh
sha256sum --check SHA256SUMS
gh attestation verify meshscale_linux_arm64.tar.gz --repo Whiteknight07/meshscale
```

Checksums detect corruption; provenance separately binds the artifact digest
to its GitHub workflow/source identity. The default app is ad-hoc signed, **not
Developer ID signed or notarized**. The optional protected-environment signing
and notarization procedure is in [the Mac build guide](../macos/README.md).
The owner must configure signing identity/secrets and public OAuth separately.

## OSS audit validation (2026-10-26)

The shared working tree passed Linux vet, Darwin vet, uncached Go race tests,
staticcheck, and govulncheck (zero reachable/imported-package vulnerabilities;
one advisory in an unimported module package). The final combined checkout passed 81 control tests and
TypeScript checking; both npm production audits reported zero vulnerabilities.
The reference frontend built successfully. Its build regenerates the tracked
`app/frontend/preview.html`; review that generated file with frontend changes.

An authorized Apple Silicon Mac with Swift 6.4 passed Swift build and 67 tests
(one optional snapshot-export test skipped), three app-packaging regression
tests, and the release app build/signature checks. These ran in a fresh
temporary source directory without launching the app or changing WARP; the Mac
directory was removed after verification.
Regression tests first reproduced unbounded output, ambiguous inventory IDs,
and unintended test-resource packaging before the corresponding fixes.

All three CLI archives and build inventories matched byte-for-byte across two
independent temporary output directories built from the same source snapshot.
Actionlint and offline zizmor's pedantic profile passed without findings.
Tagged GitHub attestations, hosted CodeQL execution, Developer ID signing,
notarization and interactive accessibility/consent checks were not exercised by
this local audit; no branch or tag was pushed.

Tracked Go files passed the CI formatting command. Literal `gofmt -l .` also
visits the ignored upstream checkouts under `spike/nativewg/research/` and
reports formatting in those external files. They are outside the release tree
and were left unchanged for the owner of the research directory.
