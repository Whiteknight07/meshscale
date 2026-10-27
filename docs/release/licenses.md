# Dependency license audit

Audit date: 2026-10-26. The repository's own code is MIT; that does not replace dependency terms. Re-run this audit when dependency locks or release targets change. Include dependency notices/license texts with redistributed binaries and bundled third-party assets.

## Go CLI

`go-licenses` v2.0.1 successfully reported `./cmd/meshscale` and saved dependency license texts. The Linux ARM64 dependency report contains 19 entries: seven MIT, one BSD-2-Clause, six BSD-3-Clause, and five Apache-2.0. The Darwin ARM64 report has 13 entries: two MIT, one BSD-2-Clause, six BSD-3-Clause, and four Apache-2.0. See [Linux report](go-dependencies.csv) and [Darwin report](go-dependencies-darwin.csv). No copyleft license was identified for the CLI's linked dependencies by these reports.

```sh
go install github.com/google/go-licenses/v2@v2.0.1
go-licenses report ./cmd/meshscale --ignore github.com/Whiteknight07/meshscale
go-licenses save ./cmd/meshscale --ignore github.com/Whiteknight07/meshscale --save_path /tmp/meshscale-third-party-licenses
```

The tool warns that architecture-specific assembly cannot be inspected for additional dependencies; this is not a license-classification error. WireGuard, gVisor, and the Go networking libraries appear in the report under permissive licenses. The release workflow is responsible for packaging notices and saved texts for each built target; validate the resulting archives rather than assuming the presence of the workflow is sufficient.

## TypeScript projects

`npx --yes license-checker --summary` was run against installed lockfile dependencies in both projects. It audits the installed platform's packages, so optional native packages on other release/build platforms need their own check.

| Project/scope | Result |
| --- | --- |
| `control/`, production dependencies | Three MIT packages (`effect`, `ipaddr.js`, `jose`); local project root (now declared MIT) |
| `control/`, full installed tree | MIT 144, Apache-2.0 33, ISC 11, BSD-2-Clause 6, BSD-3-Clause 2, MIT OR Apache-2.0 2, MPL-2.0 3, LGPL-3.0-or-later 2, Apache-2.0 AND LGPL-3.0-or-later AND MIT 1, BlueOak-1.0.0 1, 0BSD 1, plus the local project root |
| `app/frontend/`, installed tree | MIT 11, Apache-2.0 4, ISC 1, BSD-3-Clause 1, plus the local project root (now declared MIT) |

The control project's development/deployment toolchain includes **MPL-2.0** `lightningcss` and its installed native variants, **LGPL-3.0-or-later** `@img/sharp-libvips-linux-arm64` and `@img/sharp-libvips-linuxmusl-arm64`, and mixed Apache/LGPL/MIT `@img/sharp-wasm32`. They are not among the three declared production dependencies. This does not relicense meshscale source; redistribution of those tools/native artifacts still requires their notices and applicable source/relinking obligations. Do not include `node_modules` in release archives. Audit any container, offline toolchain, or bundle that includes these packages separately.

Both npm package files declare MIT, consistent with the repository LICENSE. No GPL/AGPL package was reported in the installed trees, but these scans do not prove licensing of uninstalled platform variants or downloaded runtime tools.

## Copied source and assets

An un-attributed design instruction document referring to a missing `LICENSE.txt` was removed rather than relicensed. Native prototype research checkouts are ignored and not tracked; do not ship them in filesystem archives. Existing tracked prototype notes identify upstream research references and state that their implementation was independent. No vendored upstream implementation tree was identified in the tracked files. Preserve upstream license texts and attribution if code is copied later.

The official Cloudflare client, `cloudflared`, operating-system packages, and other separately downloaded tools have their own terms and are not licensed by meshscale's MIT file. A dependency scan does not establish vendor permission for the experimental native backend's undocumented APIs.
