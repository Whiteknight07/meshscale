# Pre-publication history audit

Audit date: 2026-10-26. Scope: all locally available Git refs, full `git log --all -p` additions, the tracked tree, and a separate filesystem gitleaks scan. History was **not rewritten**. Reports below contain locations and data types, never the values themselves. Local scan reports are outside the repository and are not release artifacts.

**Recommendation: publish a fresh single-commit history after every stream's tracked-tree privacy fixes are reviewed.** Existing history contains personal email/team identities, device and account/resource identifiers, public and private endpoint addresses, WireGuard public keys, local home/workspace paths, live logs, screenshots, and packet captures. Removing files in the tip does not remove those earlier objects. Keep the old repository private or archive it privately. If preserving history, the owner must separately authorize and verify a history cleanup, including tags/other refs and old clones. This review did not rotate credentials or change any live resources.

## Scanner findings and classification

Gitleaks v8.30.1 found eight historical findings. Manual context review classified them as:

| Historical location | Classification | S1 action |
| --- | --- | --- |
| `spike/publication/live-20261026/access-policy-proof.json:3`, `owner-only-funnel.json:8` | Access application UUIDs, not bearer credentials; live resource identifiers | Deleted raw evidence |
| `internal/publication/process_test.go:21` | Deliberately synthetic Cloudflare-token test input | Outside S1; safe fixture if kept synthetic |
| `docs/tailscale-parity.md:23` | Generic-key detector matched prose about credential flags | Reworded prose; no secret |
| `docs/secure.md:351` in commit `2b652761be50` | WireGuard public identity in SSH audit output; live peer identifier, not evidence of a private-key disclosure | Outside S1; redact identity/output |
| `internal/warpcli/testdata/mac-registration.txt:4` | Live registration public key and related account/device identity; public key is not a private credential | Outside S1; replace fixture identities |
| `macos/verification/connectivity-2026-10-26.log:8,32` | Same live registration public identity in diagnostics | Deleted raw log |

No confirmed active bearer credential or private key was found in the tracked historical additions by these scans. This is a bounded scan result, not a guarantee. Gitleaks ignores many identifiers and cannot inspect text rendered into PNGs. The final tracked/nonignored-tree scan retained two findings outside S1: the synthetic token test and the live WARP registration public identity noted above. It found zero findings in S1-owned files. The separate filesystem scan detected ignored local environment/registration/SSH private state under `control/.env` and `test/native/state-*`; these paths are not tracked in the audited refs and were left untouched. Never distribute a raw checkout or filesystem archive containing ignored state.

Go module `h1:` checksums and deliberately synthetic unit-test keys are not secret findings. Published Cloudflare endpoint addresses, documented network ranges, and resolver addresses are not host disclosures. The candidate ledger below deliberately includes address/key/UUID candidates so that no suspected live identifier is silently dropped; not every candidate is sensitive.

## Historical candidates by commit and path

Line numbers refer to the file added in that commit, not the current tree. Personal email/team/host/path matches are high-confidence privacy findings. IP, UUID, 32-hex, and key candidates also include synthetic fixtures, public endpoints, dependency references, and public keys. Removed paths now exist only in history; paths outside S1 may still need tip cleanup, listed in [working-tree-audit.md](working-tree-audit.md). Repeated occurrences are grouped by type and line; actual values are intentionally omitted.

| Commit | File | Candidate types and lines |
| --- | --- | --- |
| `190c3a091aba` | `CHANGELOG.md` | host-or-username: 10 |
| `353675407301` | `CHANGELOG.md` | host-or-username: 10,22 |
| `16f536ac2c4d` | `README.md` | host-or-username: 67 |
| `3b166a2e4111` | `README.md` | email-review: 52 |
| `0202e8bb038d` | `app/DESIGN.md` | email-review: 63,118; mesh-ip: 51,55,57,59,73,118–119 |
| `0202e8bb038d` | `app/frontend/README.md` | personal-path: 12–13,25,33 |
| `0202e8bb038d` | `app/frontend/preview.html` | email-review: 9; mesh-ip: 9 |
| `0202e8bb038d` | `app/frontend/scripts/verify.mjs` | mesh-ip: 44–46,144,154 |
| `0202e8bb038d` | `app/frontend/src/mock.ts` | email-review: 7,9,11,16; mesh-ip: 7–11 |
| `21b12dfbd479` | `cmd/meshscale/bugreport_test.go` | ipv6-review: 211; key-material: 224; mesh-ip: 209 |
| `3f3cf1062258` | `cmd/meshscale/dns_test.go` | ipv6-review: 75; mesh-ip: 24,74,80,82,86 |
| `21b12dfbd479` | `cmd/meshscale/doctor_inputs.go` | mesh-ip: 232 |
| `21b12dfbd479` | `cmd/meshscale/doctor_network.go` | mesh-ip: 71,82; public-ip-review: 63 |
| `21b12dfbd479` | `cmd/meshscale/doctor_network_linux.go` | mesh-ip: 23,25,27,31,33 |
| `21b12dfbd479` | `cmd/meshscale/doctor_network_other.go` | mesh-ip: 16,31,33 |
| `21b12dfbd479` | `cmd/meshscale/doctor_test.go` | mesh-ip: 44,50,52,54,78,216–217,234 |
| `e7c155fda51b` | `cmd/meshscale/ip_test.go` | ipv6-review: 43; mesh-ip: 42,44,83 |
| `b10c7aed4a58` | `cmd/meshscale/login_setup_test.go` | email-review: 153; ipv6-review: 156; mesh-ip: 153,156 |
| `ad8473b9e3c5` | `cmd/meshscale/native_ssh_test.go` | mesh-ip: 31,33,36,39 |
| `2e86e3b0f2cf` | `cmd/meshscale/publication_test.go` | host-or-username: 132,139 |
| `f7c76cd7c4a7` | `cmd/meshscale/publication_test.go` | host-or-username: 22 |
| `d0eabd86b516` | `cmd/meshscale/routes.go` | mesh-ip: 146 |
| `d0eabd86b516` | `cmd/meshscale/rules_test.go` | mesh-ip: 31 |
| `742dc7419e2d` | `cmd/meshscale/secure_live_test.go` | mesh-ip: 70; uuid: 68 |
| `1ae5e436bd00` | `cmd/meshscale/secure_test.go` | mesh-ip: 232 |
| `742dc7419e2d` | `cmd/meshscale/secure_test.go` | ipv6-review: 188; mesh-ip: 71 |
| `2e86e3b0f2cf` | `cmd/meshscale/ssh_mode_inventory_test.go` | mesh-ip: 18 |
| `3f3cf1062258` | `cmd/meshscale/ssh_test.go` | ipv6-review: 8,10; mesh-ip: 8,10,17,22,26–27 |
| `4371324fa1b1` | `cmd/meshscale/ssh_test.go` | mesh-ip: 33–34,45 |
| `e61b62905ccc` | `cmd/meshscale/status_reachability_test.go` | ipv6-review: 35; mesh-ip: 30–34,70 |
| `ea781f77a063` | `cmd/meshscale/status_reachability_test.go` | ipv6-review: 35 |
| `16f536ac2c4d` | `cmd/meshscale/status_test.go` | host-or-username: 365; mesh-ip: 85–86 |
| `190c3a091aba` | `cmd/meshscale/status_test.go` | mesh-ip: 85–86 |
| `3f3cf1062258` | `cmd/meshscale/status_test.go` | mesh-ip: 83–84 |
| `742dc7419e2d` | `cmd/meshscale/status_test.go` | mesh-ip: 85–86 |
| `946743ea92e6` | `cmd/meshscale/status_test.go` | mesh-ip: 242,269,295 |
| `cb454ed4a5d7` | `cmd/meshscale/status_test.go` | mesh-ip: 85–86 |
| `e7c155fda51b` | `cmd/meshscale/status_test.go` | ipv6-review: 50,105,218,221; mesh-ip: 50–51,82–83 |
| `4d6ee2b09357` | `cmd/meshscale/up_test.go` | mesh-ip: 109,163 |
| `946743ea92e6` | `cmd/meshscale/up_test.go` | mesh-ip: 66,123 |
| `e7c155fda51b` | `cmd/meshscale/whois_test.go` | ipv6-review: 13; mesh-ip: 13,19,24,27,40,51 |
| `72c2cfd27021` | `control/src/policy.ts` | ipv6-review: 13,29; mesh-ip: 12,29 |
| `72c2cfd27021` | `control/test/auth.test.ts` | team-domain: 22 |
| `999c73c5fe79` | `control/test/auth.test.ts` | team-domain: 38 |
| `72c2cfd27021` | `control/test/fixtures.ts` | mesh-ip: 5,7 |
| `999c73c5fe79` | `control/test/fixtures.ts` | mesh-ip: 18,35 |
| `72c2cfd27021` | `control/test/http.test.ts` | mesh-ip: 31 |
| `999c73c5fe79` | `control/test/http.test.ts` | mesh-ip: 71 |
| `72c2cfd27021` | `control/test/inventory.test.ts` | mesh-ip: 11,24 |
| `999c73c5fe79` | `control/test/inventory.test.ts` | mesh-ip: 30,64,110,124,126,132,259,267,273,303,306,313,385 |
| `72c2cfd27021` | `control/test/policy.test.ts` | ipv6-review: 14,19,21; mesh-ip: 14,21,30,33–34,37–40,44 |
| `999c73c5fe79` | `control/test/policy.test.ts` | ipv6-review: 25,42,46; mesh-ip: 26,46,63,73,76,89–90 |
| `72c2cfd27021` | `docs/admin-console.md` | host-or-username: 3 |
| `190c3a091aba` | `docs/case-study.md` | host-or-username: 12,16,82,98; mesh-ip: 81–83,86,100 |
| `353675407301` | `docs/case-study.md` | host-or-username: 174,198; ipv6-review: 205 |
| `2e86e3b0f2cf` | `docs/cert.md` | host-or-username: 13 |
| `f7c76cd7c4a7` | `docs/cert.md` | host-or-username: 9,11,18,72,110,116; mesh-ip: 18,31 |
| `1a28ee020a55` | `docs/cloudflare-ssh.md` | hex-id: 149; host-or-username: 240–242,249; mesh-ip: 25,177–178,197,249,288; personal-email: 249; uuid: 217–226 |
| `4371324fa1b1` | `docs/cloudflare-ssh.md` | email-review: 85; host-or-username: 82,85,87,89,94,98,112; personal-email: 85; uuid: 100–102,107–109,117 |
| `d0eabd86b516` | `docs/devices.md` | email-review: 59; host-or-username: 58–59; ipv6-review: 36; mesh-ip: 36; personal-email: 59; uuid: 71–72 |
| `e61b62905ccc` | `docs/devices.md` | mesh-ip: 117,122 |
| `21b12dfbd479` | `docs/doctor.md` | mesh-ip: 44–45 |
| `16f536ac2c4d` | `docs/exit-nodes.md` | host-or-username: 530,591,594,596–597,613,621; mesh-ip: 591,593; personal-email: 591; public-ip-review: 595 |
| `1ae5e436bd00` | `docs/exit-nodes.md` | host-or-username: 633; public-ip-review: 633 |
| `89f3ae4c647b` | `docs/exit-nodes.md` | host-or-username: 57,64,79,82,85,90,140,215,391–393,501; mesh-ip: 82–83,88,94,97,143,501; personal-email: 501; public-ip-review: 85–86,88,94–97,106,476–479; uuid: 83,476–479 |
| `cb454ed4a5d7` | `docs/exit-nodes.md` | host-or-username: 641,644–645,669–670,682,688,692,705,720,729,742,744,749; mesh-ip: 644,669,702; personal-email: 644; public-ip-review: 671,674–677,680,711,723–724,746 |
| `f7c76cd7c4a7` | `docs/funnel.md` | host-or-username: 5,12,42–43,54,66,93–96,136 |
| `3b166a2e4111` | `docs/install.md` | personal-path: 122 |
| `190c3a091aba` | `docs/linux-host.md` | host-or-username: 42; mesh-ip: 42,45–46,54,79–80,103,183–184; public-ip-review: 187 |
| `4d6ee2b09357` | `docs/linux-host.md` | host-or-username: 7,75,93–95,100–101; mesh-ip: 19,42–43,47,94,97–98,100–101,118; personal-email: 100–101; public-ip-review: 103 |
| `d59394c6b612` | `docs/macos-enrollment.md` | mesh-ip: 37 |
| `ad8473b9e3c5` | `docs/native.md` | ipv6-review: 37; mesh-ip: 36,49–50 |
| `443d4eef4559` | `docs/performance.md` | host-or-username: 23; ipv6-review: 11 |
| `16f536ac2c4d` | `docs/plan.md` | host-or-username: 234,236 |
| `4d6ee2b09357` | `docs/plan.md` | host-or-username: 202 |
| `9136fdb97a48` | `docs/plan.md` | mesh-ip: 83 |
| `b10c7aed4a58` | `docs/plan.md` | hex-id: 91 |
| `f7c76cd7c4a7` | `docs/publication-live.md` | hex-id: 18,76,90–92; host-or-username: 3,15,17,22,27–28,30–31,36,39–40,46,49–51,57,65,75,98,104–105; mesh-ip: 3,75,105; personal-email: 105; personal-path: 43,78; team-domain: 30; uuid: 90–92 |
| `9136fdb97a48` | `docs/research.md` | mesh-ip: 15 |
| `d0eabd86b516` | `docs/routes.md` | mesh-ip: 56 |
| `d0eabd86b516` | `docs/rules.md` | ipv6-review: 32,52–53; mesh-ip: 31 |
| `2b652761be50` | `docs/secure.md` | email-review: 348; host-or-username: 89,161,249,307,312,321,350,369,384–385; ipv6-review: 41,314,318,320,322,347,352,371; key-material: 351; mesh-ip: 249,251,313,317,358,369; personal-email: 369; personal-path: 90; uuid: 350 |
| `742dc7419e2d` | `docs/secure.md` | email-review: 24; ipv6-review: 39,109; mesh-ip: 112 |
| `cb454ed4a5d7` | `docs/secure.md` | host-or-username: 677,688; ipv6-review: 625,679; mesh-ip: 678 |
| `f845a0f0d899` | `docs/secure.md` | host-or-username: 413,460,472,597; ipv6-review: 415; mesh-ip: 414 |
| `4d6ee2b09357` | `docs/service.md` | mesh-ip: 24 |
| `e61b62905ccc` | `docs/service.md` | ipv6-review: 142; mesh-ip: 142 |
| `b10c7aed4a58` | `docs/setup.md` | email-review: 186; hex-id: 146; host-or-username: 176,186; personal-email: 186; team-domain: 56,176 |
| `3f3cf1062258` | `docs/ssh.md` | ipv6-review: 37; mesh-ip: 11–12,15–16,37 |
| `a1c18fbb645c` | `docs/ssh.md` | uuid: 106 |
| `190c3a091aba` | `docs/status-verification.md` | host-or-username: 56,113,115; mesh-ip: 105,107–109,115; personal-email: 115; public-ip-review: 112 |
| `e61b62905ccc` | `docs/status-verification.md` | mesh-ip: 27–29 |
| `f7240c343dc8` | `docs/tailscale-parity.md` | personal-path: 3 |
| `e7c155fda51b` | `internal/auth/client.go` | hex-id: 17 |
| `e7c155fda51b` | `internal/cfapi/client_test.go` | ipv6-review: 57,69; mesh-ip: 57 |
| `742dc7419e2d` | `internal/cfapi/gateway_lists_test.go` | mesh-ip: 29,39 |
| `3f3cf1062258` | `internal/cfapi/gateway_test.go` | mesh-ip: 10,29,39 |
| `800ab690711b` | `internal/cfapi/infrastructure_test.go` | mesh-ip: 23,25 |
| `f7c76cd7c4a7` | `internal/cfapi/publication_test.go` | host-or-username: 26,29,38,46,68; mesh-ip: 29 |
| `2e86e3b0f2cf` | `internal/cfapi/retry_test.go` | hex-id: 103,105,107,112,118,120,129,133,137,229; mesh-ip: 105,129,229 |
| `4371324fa1b1` | `internal/cloudflaressh/host.go` | email-review: 146,266 |
| `4371324fa1b1` | `internal/cloudflaressh/host_test.go` | email-review: 28; mesh-ip: 81 |
| `4371324fa1b1` | `internal/cloudflaressh/mode.go` | ipv6-review: 86 |
| `4371324fa1b1` | `internal/cloudflaressh/mode_test.go` | mesh-ip: 100,175 |
| `d0eabd86b516` | `internal/devicesync/sync_test.go` | mesh-ip: 23,28 |
| `16f536ac2c4d` | `internal/exitnode/datapath_linux_test.go` | mesh-ip: 87–88,148–149,158 |
| `1ae5e436bd00` | `internal/exitnode/datapath_linux_test.go` | ipv6-review: 176–178,180,182,193,195,221; mesh-ip: 180 |
| `16f536ac2c4d` | `internal/exitnode/firewall.go` | mesh-ip: 77; public-ip-review: 77 |
| `1ae5e436bd00` | `internal/exitnode/firewall.go` | mesh-ip: 126 |
| `16f536ac2c4d` | `internal/exitnode/firewall_test.go` | ipv6-review: 46,48; mesh-ip: 48,60,64,101 |
| `1ae5e436bd00` | `internal/exitnode/firewall_test.go` | ipv6-review: 111,113 |
| `d7a83a3e0bde` | `internal/exitnode/firewall_test.go` | public-ip-review: 194,202 |
| `afb8eb25c91e` | `internal/exitnode/manager_test.go` | ipv6-review: 42–43 |
| `cb454ed4a5d7` | `internal/exitnode/manager_test.go` | ipv6-review: 42–43; mesh-ip: 15,28; public-ip-review: 106,114 |
| `d7a83a3e0bde` | `internal/exitnode/manager_test.go` | ipv6-review: 160,273; mesh-ip: 155,160,164 |
| `443d4eef4559` | `internal/exitnode/network_reader_linux_test.go` | hex-id: 209; mesh-ip: 50–51,68–69,84,208,236 |
| `16f536ac2c4d` | `internal/exitnode/routing.go` | ipv6-review: 204; mesh-ip: 202 |
| `d7a83a3e0bde` | `internal/exitnode/routing.go` | ipv6-review: 289; mesh-ip: 289 |
| `16f536ac2c4d` | `internal/exitnode/routing_test.go` | ipv6-review: 20; mesh-ip: 19,41,101,105–106,112 |
| `1ae5e436bd00` | `internal/exitnode/routing_test.go` | ipv6-review: 75; mesh-ip: 134 |
| `5c15b7b780a6` | `internal/exitnode/routing_test.go` | ipv6-review: 191 |
| `cb454ed4a5d7` | `internal/exitnode/routing_test.go` | mesh-ip: 145,154,160; public-ip-review: 145,150 |
| `d7a83a3e0bde` | `internal/exitnode/routing_test.go` | ipv6-review: 292 |
| `cb454ed4a5d7` | `internal/exitnode/warp.go` | ipv6-review: 25,52; public-ip-review: 24,52 |
| `cb454ed4a5d7` | `internal/exitnode/warp_test.go` | ipv6-review: 69; mesh-ip: 23,75; public-ip-review: 49–50,55 |
| `4d6ee2b09357` | `internal/linuxnetwork/firewall.go` | mesh-ip: 58 |
| `4d6ee2b09357` | `internal/linuxnetwork/firewall_test.go` | mesh-ip: 51,60 |
| `190c3a091aba` | `internal/linuxnetwork/routing_linux_test.go` | mesh-ip: 39,41,56,79 |
| `190c3a091aba` | `internal/linuxnetwork/routing_test.go` | mesh-ip: 50 |
| `2b652761be50` | `internal/mesh/devices.go` | ipv6-review: 42 |
| `d0eabd86b516` | `internal/mesh/devices.go` | ipv6-review: 39; mesh-ip: 39 |
| `b10c7aed4a58` | `internal/mesh/full_setup_test.go` | team-domain: 50,60 |
| `946743ea92e6` | `internal/mesh/setup.go` | mesh-ip: 104,113,120 |
| `946743ea92e6` | `internal/mesh/setup_test.go` | email-review: 55,117; mesh-ip: 118 |
| `2b652761be50` | `internal/meshaddr/range.go` | mesh-ip: 6 |
| `ea781f77a063` | `internal/meshaddr/range.go` | ipv6-review: 10,12,14; mesh-ip: 8 |
| `ea781f77a063` | `internal/meshaddr/range_test.go` | ipv6-review: 15–17; mesh-ip: 13–14,18 |
| `3f3cf1062258` | `internal/names/names_test.go` | ipv6-review: 16,19; mesh-ip: 15–18,31,65,67,79,86,102,137 |
| `742dc7419e2d` | `internal/native/control_test.go` | ipv6-review: 224 |
| `ad8473b9e3c5` | `internal/native/control_test.go` | mesh-ip: 21,53,59,140,154,165,169,194 |
| `ad8473b9e3c5` | `internal/native/registration.go` | ipv6-review: 22; mesh-ip: 21 |
| `ad8473b9e3c5` | `internal/native/registration_test.go` | ipv6-review: 112; public-ip-review: 36 |
| `ad8473b9e3c5` | `internal/native/testdata/registration.json` | ipv6-review: 8,11; key-material: 6,10; mesh-ip: 8; public-ip-review: 11; uuid: 4,14 |
| `c6636e5cdc28` | `internal/publication/acme_live_test.go` | mesh-ip: 52 |
| `f7c76cd7c4a7` | `internal/publication/acme_live_test.go` | mesh-ip: 48 |
| `2e86e3b0f2cf` | `internal/publication/audit_test.go` | host-or-username: 32–33,37,75–76,84,96,108,117–118,127,129,272,299–300,448,469,500–501,505,509,555,585,592; mesh-ip: 33,76,84,88,95,118,127,300,501,505,509,513,531,538,543,548,585 |
| `5b1bed73de72` | `internal/publication/cert.go` | mesh-ip: 32–33 |
| `2e86e3b0f2cf` | `internal/publication/publication_test.go` | mesh-ip: 404 |
| `f7c76cd7c4a7` | `internal/publication/publication_test.go` | host-or-username: 92,108,202,248,262,290–291,305,315,341–342,382–383,404,414,447,504,546–548,551,582,627–628; mesh-ip: 342,360,383,404,414,582; public-ip-review: 404 |
| `b74a722ce181` | `internal/reachability/checker_test.go` | mesh-ip: 144 |
| `e61b62905ccc` | `internal/reachability/checker_test.go` | mesh-ip: 35,67 |
| `e61b62905ccc` | `internal/reachability/probe.go` | ipv6-review: 150; mesh-ip: 150 |
| `e61b62905ccc` | `internal/reachability/probe_test.go` | ipv6-review: 52; mesh-ip: 52–53 |
| `2b652761be50` | `internal/routes/routes.go` | ipv6-review: 28 |
| `d0eabd86b516` | `internal/routes/routes.go` | ipv6-review: 27; mesh-ip: 27 |
| `d0eabd86b516` | `internal/routes/routes_test.go` | ipv6-review: 12–13,16; mesh-ip: 16 |
| `d0eabd86b516` | `internal/rules/policy.go` | ipv6-review: 17; mesh-ip: 16 |
| `d0eabd86b516` | `internal/rules/policy_test.go` | ipv6-review: 11,27,49,59,86; mesh-ip: 26,43,48–50,59,66,84 |
| `742dc7419e2d` | `internal/rules/secure_test.go` | mesh-ip: 17,19–21 |
| `d0eabd86b516` | `internal/rules/sync_test.go` | ipv6-review: 172; mesh-ip: 172,181 |
| `2b652761be50` | `internal/secure/bind_test.go` | mesh-ip: 65,81,109–110,118,140–141 |
| `75dc7e3d57e3` | `internal/secure/carrier_linux_test.go` | mesh-ip: 67,85,94,97,101,120,124,128 |
| `16f536ac2c4d` | `internal/secure/exit_test.go` | host-or-username: 18,24–30; mesh-ip: 60 |
| `742dc7419e2d` | `internal/secure/keys.go` | ipv6-review: 17 |
| `742dc7419e2d` | `internal/secure/keys_test.go` | key-material: 88 |
| `742dc7419e2d` | `internal/secure/registry.go` | mesh-ip: 39,153 |
| `2b652761be50` | `internal/secure/registry_test.go` | mesh-ip: 212 |
| `742dc7419e2d` | `internal/secure/registry_test.go` | mesh-ip: 29,41,43,114 |
| `b636c73b00d0` | `internal/secure/registry_test.go` | mesh-ip: 46 |
| `1ae5e436bd00` | `internal/secure/supervisor_test.go` | mesh-ip: 161 |
| `2b652761be50` | `internal/secure/supervisor_test.go` | mesh-ip: 25 |
| `443d4eef4559` | `internal/secure/supervisor_test.go` | mesh-ip: 134,247 |
| `2b652761be50` | `internal/secure/transport_test.go` | mesh-ip: 368,383,396 |
| `742dc7419e2d` | `internal/secure/transport_test.go` | mesh-ip: 187,212,237 |
| `b636c73b00d0` | `internal/secure/transport_test.go` | mesh-ip: 368 |
| `cb454ed4a5d7` | `internal/secureroute/route_test.go` | ipv6-review: 22,52,59–60 |
| `443d4eef4559` | `internal/secureroute/status.go` | ipv6-review: 14 |
| `cb454ed4a5d7` | `internal/secureroute/status.go` | ipv6-review: 15 |
| `d0eabd86b516` | `internal/service/daemon_test.go` | mesh-ip: 27 |
| `190c3a091aba` | `internal/service/inventory_test.go` | mesh-ip: 20 |
| `e61b62905ccc` | `internal/service/reachability_test.go` | mesh-ip: 26,70,73 |
| `3f3cf1062258` | `internal/sshserver/auth_test.go` | mesh-ip: 50–55 |
| `ad8473b9e3c5` | `internal/sshserver/auth_test.go` | mesh-ip: 98 |
| `3f3cf1062258` | `internal/sshserver/handshake_linux_test.go` | email-review: 115; ipv6-review: 229; mesh-ip: 28,30 |
| `ea781f77a063` | `internal/sshserver/handshake_linux_test.go` | ipv6-review: 231 |
| `3f3cf1062258` | `internal/sshserver/identity.go` | ipv6-review: 16; mesh-ip: 15 |
| `3f3cf1062258` | `internal/sshserver/identity_test.go` | ipv6-review: 18,57,60,98,103; mesh-ip: 18,52,60,74,80,86,92,98 |
| `ea781f77a063` | `internal/sshserver/identity_test.go` | ipv6-review: 104 |
| `a1c18fbb645c` | `internal/sshserver/policy_test.go` | email-review: 11 |
| `742dc7419e2d` | `internal/sshserver/secure_test.go` | mesh-ip: 19 |
| `3f3cf1062258` | `internal/sshserver/server.go` | email-review: 154 |
| `3f3cf1062258` | `internal/sshserver/session_linux.go` | email-review: 128 |
| `d59394c6b612` | `internal/warpcli/enrollment.go` | mesh-ip: 26 |
| `2b652761be50` | `internal/warpcli/safety.go` | ipv6-review: 61; public-ip-review: 61 |
| `d59394c6b612` | `internal/warpcli/safety.go` | ipv6-review: 59; mesh-ip: 59,68,73; public-ip-review: 59 |
| `d59394c6b612` | `internal/warpcli/safety_test.go` | host-or-username: 29,39–40,43–52,112,141; mesh-ip: 44–48,51; public-ip-review: 47; uuid: 29 |
| `d59394c6b612` | `internal/warpcli/testdata/mac-registration.txt` | hex-id: 5; host-or-username: 6; uuid: 2–3 |
| `d59394c6b612` | `internal/warpcli/testdata/mac-settings.txt` | hex-id: 14; host-or-username: 24,46; ipv6-review: 14,21,23; mesh-ip: 20; public-ip-review: 14,22,52; team-domain: 24; uuid: 54 |
| `946743ea92e6` | `internal/warpcli/warpcli_test.go` | host-or-username: 120; uuid: 120–121 |
| `11301a187646` | `macos/README.md` | host-or-username: 22–23; mesh-ip: 22–23; personal-email: 22–23; personal-path: 16 |
| `a15443965530` | `macos/README.md` | host-or-username: 22–23; mesh-ip: 22–23; personal-email: 22–23 |
| `d59394c6b612` | `macos/README.md` | mesh-ip: 139 |
| `05e5000b1a19` | `macos/Sources/MeshscaleCore/Fixtures.swift` | ipv6-review: 59 |
| `11301a187646` | `macos/Sources/MeshscaleCore/Fixtures.swift` | email-review: 10,12,14,19; mesh-ip: 10–14 |
| `d59394c6b612` | `macos/Sources/MeshscaleCore/Fixtures.swift` | mesh-ip: 50 |
| `a15443965530` | `macos/Tests/MeshscaleCoreTests/AppModelTests.swift` | mesh-ip: 78–80 |
| `05e5000b1a19` | `macos/Tests/MeshscaleCoreTests/ClientTests.swift` | ipv6-review: 65,69 |
| `11301a187646` | `macos/Tests/MeshscaleCoreTests/ClientTests.swift` | ipv6-review: 39,41; mesh-ip: 80 |
| `558dd8964a3a` | `macos/Tests/MeshscaleCoreTests/ClientTests.swift` | email-review: 105–106; host-or-username: 105–106; personal-email: 105–106 |
| `11301a187646` | `macos/Tests/MeshscaleCoreTests/Fixtures/status-real.json` | email-review: 40; host-or-username: 40; ipv6-review: 11,27,42; mesh-ip: 10,26,41; team-domain: 40; uuid: 3–5,19–21,35–36,49 |
| `d59394c6b612` | `macos/scripts/verify-connectivity.py` | host-or-username: 14; mesh-ip: 14,45; personal-email: 14 |
| `11301a187646` | `macos/scripts/verify-real-data.py` | host-or-username: 37; mesh-ip: 37; personal-email: 37; personal-path: 8 |
| `a15443965530` | `macos/verification/AUDIT-FIXES-2026-10-26.md` | host-or-username: 103; mesh-ip: 103; personal-email: 103 |
| `11301a187646` | `macos/verification/HANDOFF.md` | host-or-username: 4; personal-path: 3–4 |
| `d59394c6b612` | `macos/verification/HANDOFF.md` | host-or-username: 3; mesh-ip: 17,40–41; personal-path: 3 |
| `05e5000b1a19` | `macos/verification/SWIFT-2026-10-26.md` | mesh-ip: 4 |
| `d59394c6b612` | `macos/verification/build-connectivity.log` | host-or-username: 10–12; personal-path: 10–12 |
| `11301a187646` | `macos/verification/build-final.log` | host-or-username: 10–12; personal-path: 10–12 |
| `d59394c6b612` | `macos/verification/connectivity-2026-10-26.log` | email-review: 47–48,64,81,98,115,130–131; hex-id: 9,33; host-or-username: 10,34,47–48,64,81,98,115,130–131; ipv6-review: 50,66,83,100,117,133; mesh-ip: 37,49,65,82,99,116,132; personal-email: 47–48,130–131; team-domain: 64,81,98,115; uuid: 6–7,30–31,42–43,57–59,74–76,91–93,108–110,125–126 |
| `1a28ee020a55` | `spike/cfssh/README.md` | mesh-ip: 10 |
| `4371324fa1b1` | `spike/cfssh/implementation-live.json` | email-review: 16,49,94,100,106,111,123,136,150,173,222,420,459,482,484–485,535; hex-id: 123,147,456; host-or-username: 39,49,62,94,97,106,111,123,133,150,212,222,235,420,459,485,525,535,548; ipv6-review: 49,222,535; mesh-ip: 39,62,82,94,100,106,111,117,123,136,149,173,212,235,255,373,379,385,391,397,403,409,415,420,433,451,458,482,525,548,568; personal-email: 49,62,111,123,150,222,235,420,459,485,535,548; personal-path: 94,106; public-ip-review: 29,202,515; uuid: 15,117,123,154–156,158,189,354,463–465,467,503 |
| `1a28ee020a55` | `spike/cfssh/live-attempt1.json` | email-review: 152,295,461; host-or-username: 152,285,295,308,451,461,474; ipv6-review: 295,461; mesh-ip: 11,116,285,308,328,343,369,374,401,414,451,474,494; personal-email: 295,308,461,474; public-ip-review: 275,441; team-domain: 152; uuid: 7,12,25,177 |
| `1a28ee020a55` | `spike/cfssh/live-attempt2.json` | email-review: 53,210,356,495,702; host-or-username: 53,210,346,356,369,485,495,508,692,702,715; ipv6-review: 356,495,702; mesh-ip: 11,175,346,369,389,404,430,435,462,485,508,528,555,560,574,587,610,615,629,642,655,692,715,735; personal-email: 356,369,495,508,702,715; public-ip-review: 336,475,682; team-domain: 53,210; uuid: 7,12,24–25,49,67,80,84,230,238,574,629 |
| `1a28ee020a55` | `spike/cfssh/live-attempt3.json` | email-review: 53,210,356,435,462,495,560,587,615,642,655,683,710,757; host-or-username: 53,210,346,356,369,485,495,508,747,757,770; ipv6-review: 356,495,757; mesh-ip: 11,175,346,369,389,404,430,435,462,485,508,528,555,560,587,610,615,629,642,655,678,683,697,710,747,770,790; personal-email: 356,369,495,508,757,770; public-ip-review: 336,475,737; team-domain: 53,210; uuid: 7,12,24–25,49,67,80,84,230,238,629,697 |
| `1a28ee020a55` | `spike/cfssh/live.json` | email-review: 53,210,356,435,462,495,560,587,615,642,655,683,710,757; host-or-username: 53,210,346,356,369,485,495,508,747,757,770; ipv6-review: 356,495,757; mesh-ip: 11,175,346,369,389,404,430,435,462,485,508,528,555,560,587,610,615,629,642,655,678,683,710,747,770,790; personal-email: 356,369,495,508,757,770; public-ip-review: 336,475,737; team-domain: 53,210; uuid: 7,12,24–25,49,67,80,84,230,238,629 |
| `1a28ee020a55` | `spike/cfssh/preflight.json` | email-review: 277,384; hex-id: 136,289,396,487,645,650; host-or-username: 277,300,384; ipv6-review: 160,200,208,297,314,322,409,417,511,551,559; mesh-ip: 186,189,294,401,537,540; personal-email: 277; public-ip-review: 170,197,205,311,319,406,414,521,548,556; team-domain: 300,384; uuid: 72,93,96,123,272,379,474,624 |
| `1a28ee020a55` | `spike/cfssh/probe.py` | email-review: 147; host-or-username: 79,147; mesh-ip: 5,75,79,84,103,117,138; personal-email: 79; personal-path: 27; team-domain: 147 |
| `1a28ee020a55` | `spike/cfssh/summary.json` | uuid: 10,66,72,78,156,162,168,262,268,274 |
| `89f3ae4c647b` | `spike/exitnode/README.md` | host-or-username: 6,37,81,86; mesh-ip: 37,81; personal-email: 81; personal-path: 32,49,59; public-ip-review: 50,67,70 |
| `89f3ae4c647b` | `spike/exitnode/cloudflare_probe.py` | mesh-ip: 106–107; public-ip-review: 65; uuid: 64 |
| `89f3ae4c647b` | `spike/exitnode/evidence.json` | key-material: 634–635; mesh-ip: 107,121,135,149,163,179,182–183,185,188,190,192–193,195–196,198,200,202,204,311,325,339,353,367,383,386–387,389,392,397,401–402,405,407–409,516,530,544,558,572,588,591–592,594,597,600–603,605,607,609,615,630,930,932,943; public-ip-review: 23,34,48,62,76,90,106,120,134,148,162,227,238,252,266,280,294,310,324,338,352,366,431,443,457,471,485,499,515,529,543,557,571,628–629,643,661,679,697,715,733,751,769,787,805; uuid: 21,24,28,225,228,232,429,432,436 |
| `89f3ae4c647b` | `spike/exitnode/initial-probe.json` | mesh-ip: 38; public-ip-review: 18,35,38,50,54,60; uuid: 58,61,65 |
| `89f3ae4c647b` | `spike/exitnode/kernel_probe.py` | host-or-username: 4; ipv6-review: 94; mesh-ip: 95,135,146; public-ip-review: 79 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/buffer-applied-readback.json` | public-ip-review: 7,17 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/buffer-restored-readback.json` | public-ip-review: 7,17 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/daemon-restart-final-proof.txt` | personal-path: 1–2 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/direct-checkip.amazonaws.com-r1.json` | hex-id: 2; public-ip-review: 22,78 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/direct-checkip.amazonaws.com-r2.json` | hex-id: 2; public-ip-review: 22,78 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/direct-checkip.amazonaws.com-r3.json` | hex-id: 2; public-ip-review: 22,78 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/direct-p1-r1.json` | public-ip-review: 7,17,368 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/direct-p1-r2.json` | public-ip-review: 7,17,368 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/direct-p1-r3.json` | public-ip-review: 7,17,341 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/direct-p4-r1.json` | public-ip-review: 7,13,19,25,35,911 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/direct-p4-r2.json` | public-ip-review: 7,13,19,25,35,911 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/direct-p4-r3.json` | public-ip-review: 7,13,19,25,35,911 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/direct-speed.cloudflare.com-r1.json` | hex-id: 2; public-ip-review: 22,78 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/direct-speed.cloudflare.com-r2.json` | hex-id: 2; public-ip-review: 22,78 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/direct-speed.cloudflare.com-r3.json` | hex-id: 2; public-ip-review: 22,78 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/excluded-init7/exit-p1-r1.json` | public-ip-review: 7,17,368 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/exit-checkip.amazonaws.com-r1.json` | hex-id: 2; public-ip-review: 22,78 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/exit-checkip.amazonaws.com-r2.json` | hex-id: 2; public-ip-review: 22,78 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/exit-checkip.amazonaws.com-r3.json` | hex-id: 2; public-ip-review: 22,78 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/exit-p1-r1.json` | public-ip-review: 7,17,368 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/exit-p1-r2.json` | public-ip-review: 7,17,368 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/exit-p1-r3.json` | public-ip-review: 7,17,368 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/exit-p4-r1.json` | public-ip-review: 7,13,19,25,35,839 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/exit-p4-r2.json` | public-ip-review: 7,13,19,25,35,911 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/exit-p4-r3.json` | public-ip-review: 7,13,19,25,35,911 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/exit-speed.cloudflare.com-r1.json` | hex-id: 2; public-ip-review: 22,78 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/exit-speed.cloudflare.com-r2.json` | hex-id: 2; public-ip-review: 22,78 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/exit-speed.cloudflare.com-r3.json` | hex-id: 2; public-ip-review: 22,78 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/route-bbr-plain-p1-r1.ss` | mesh-ip: 2,4 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/route-bbr-secure-p1-r1.ss` | ipv6-review: 2,4 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/secure-results.jsonl` | ipv6-review: 2,4–5,7,10,12,14,16–17,19,22,24,26,28–29,31,34,36; mesh-ip: 1,3,6,8–9,11,13,15,18,20–21,23,25,27,30,32–33,35 |
| `cb454ed4a5d7` | `spike/exitnode/live-20261026/wan-results.jsonl` | public-ip-review: 1–12 |
| `4e20f198323b` | `spike/nativewg/README.md` | ipv6-review: 5,14,86,121–122; mesh-ip: 5,14,16,24–25,35,85,121,157–158; public-ip-review: 15,35,88,122; uuid: 12–13,82,120,156–159 |
| `4e20f198323b` | `spike/nativewg/evidence-1280-udp.log` | ipv6-review: 1; mesh-ip: 1,3–23,33–34,39–40; public-ip-review: 2,39 |
| `4e20f198323b` | `spike/nativewg/evidence-1280.log` | ipv6-review: 3; mesh-ip: 3,5–25,31–32; public-ip-review: 4,31; uuid: 1–2 |
| `4e20f198323b` | `spike/nativewg/evidence-1420.log` | ipv6-review: 1; mesh-ip: 1,3–23,33–34,39–40; public-ip-review: 2,39 |
| `4e20f198323b` | `spike/nativewg/evidence-final.log` | ipv6-review: 1; mesh-ip: 1,3–23,29–30,35; public-ip-review: 2,29 |
| `4e20f198323b` | `spike/nativewg/evidence-masque-config.log` | ipv6-review: 3–4; mesh-ip: 3; public-ip-review: 4; uuid: 2 |
| `4e20f198323b` | `spike/nativewg/evidence-masque.log` | mesh-ip: 1–20 |
| `4e20f198323b` | `spike/nativewg/evidence-retained.log` | ipv6-review: 1; mesh-ip: 1,3–23,29–30,35; public-ip-review: 2,29 |
| `4e20f198323b` | `spike/nativewg/evidence-schema.log` | ipv6-review: 11; public-ip-review: 11; uuid: 3 |
| `4e20f198323b` | `spike/nativewg/main.go` | mesh-ip: 213,370,374; public-ip-review: 257,396 |
| `4e20f198323b` | `spike/nativewg/run.sh` | personal-path: 16 |
| `4e20f198323b` | `spike/nativewg/udp-peer.py` | mesh-ip: 4 |
| `f7c76cd7c4a7` | `spike/publication/live-20261026/access-headers.txt` | host-or-username: 3; team-domain: 3 |
| `f7c76cd7c4a7` | `spike/publication/live-20261026/access-policy-proof.json` | host-or-username: 4; uuid: 2–3 |
| `f7c76cd7c4a7` | `spike/publication/live-20261026/after.txt` | host-or-username: 13–17,19–22,27; mesh-ip: 13–22,27; personal-email: 27 |
| `f7c76cd7c4a7` | `spike/publication/live-20261026/before.txt` | host-or-username: 9–13,15–18,23; mesh-ip: 9–18,23; personal-email: 23 |
| `f7c76cd7c4a7` | `spike/publication/live-20261026/certificate.json` | host-or-username: 2; mesh-ip: 3; personal-path: 5–6 |
| `f7c76cd7c4a7` | `spike/publication/live-20261026/final-state.json` | host-or-username: 2,7; mesh-ip: 8; personal-path: 10–11 |
| `f7c76cd7c4a7` | `spike/publication/live-20261026/https-origin-funnel.json` | hex-id: 8; host-or-username: 2,4,6,15; mesh-ip: 16; personal-path: 18–19; uuid: 7 |
| `f7c76cd7c4a7` | `spike/publication/live-20261026/latency.json` | host-or-username: 3 |
| `f7c76cd7c4a7` | `spike/publication/live-20261026/mesh-tls.txt` | host-or-username: 4,8,33,36,46; mesh-ip: 6–8 |
| `f7c76cd7c4a7` | `spike/publication/live-20261026/owner-only-funnel.json` | hex-id: 7; host-or-username: 2,4,15; mesh-ip: 16; personal-path: 18–19; uuid: 6,8 |
| `f7c76cd7c4a7` | `spike/publication/live-20261026/public-funnel.json` | hex-id: 7; host-or-username: 2,4,14; mesh-ip: 15; personal-path: 17–18; uuid: 6 |
| `f7c76cd7c4a7` | `spike/publication/live-20261026/resource-audit.json` | hex-id: 4,9,21,33,51; host-or-username: 3,10,22,28,34,40,46,52,58; mesh-ip: 12; uuid: 27,39,45,57 |
| `f845a0f0d899` | `spike/secureperf/README.md` | host-or-username: 7; ipv6-review: 10,26; mesh-ip: 7,25; personal-path: 76 |
| `f845a0f0d899` | `spike/secureperf/evidence/cpu-evidence.json` | host-or-username: 2 |
| `f845a0f0d899` | `spike/secureperf/evidence/fragment-evidence.json` | ipv6-review: 223,299,375,451,528,605; mesh-ip: 10,81,152 |
| `f845a0f0d899` | `spike/secureperf/evidence/handshake-evidence.json` | ipv6-review: 225–226,232–233,239–240,246–247,253–254,260–261,267–268,274–275,281–282,288–289,295–296,302–303,309–310,316–317,323–324,330–331; mesh-ip: 9–10,16–17,23–24,30–31,37–38,44–45,51–52,58–59,65–66,72–73,79–80,86–87,93–94,100–101,107–108,114–115,121–122,128–129,135–136,142–143,149–150,156–157,163–164,170–171,177–178,184–185,191–192,198–199,205–206,212–213 |
| `f845a0f0d899` | `spike/secureperf/evidence/metadata.json` | host-or-username: 6; mesh-ip: 9–10 |
| `f845a0f0d899` | `spike/secureperf/evidence/ss-samples.json` | ipv6-review: 3–6; mesh-ip: 2 |
| `f845a0f0d899` | `spike/secureperf/evidence/tcp-results.jsonl` | ipv6-review: 3–4,7–8,11–12,15–16,19–20,23–24,27–28,31–32,35–36,39–40,43–44,47–60,67–78,81–82,85–86,89–90,93–94,97–98,101–102; mesh-ip: 1–2,5–6,9–10,13–14,17–18,21–22,25–26,29–30,33–34,37–38,41–42,45–46,79–80,83–84,87–88 |
| `f845a0f0d899` | `spike/secureperf/evidence/udp-evidence.json` | mesh-ip: 7,34,61,88,115,142,169,196,223,250,277,304,331,358,385,412,439,466,493,520,547,574,601,628,655,682,709 |
| `3f3cf1062258` | `test/docker/DNS.md` | mesh-ip: 40–41,48–49,83–84,92–93,101–102,109,124,139,146,153,160; personal-path: 3,170; uuid: 83–84,115–117,130–132 |
| `946743ea92e6` | `test/docker/README.md` | email-review: 27,56; host-or-username: 27,56; mesh-ip: 29,34,37,53–54,56–57; personal-path: 3,8; team-domain: 27,56 |
| `f5534c42bceb` | `test/docker/README.md` | mesh-ip: 136–137 |
| `d0eabd86b516` | `test/docker/RULES.md` | ipv6-review: 97,107; mesh-ip: 65–67,71,79,97,107,132,142–143,186; personal-path: 3; uuid: 90,100,161,164,167 |
| `d0eabd86b516` | `test/docker/SERVICE.md` | email-review: 139,152,206,210; host-or-username: 139,152,167,206,210; ipv6-review: 131,164,181,189; mesh-ip: 11,27–28,84,110,126,130,161,230,232,234; personal-email: 139,152,206,210; personal-path: 25,48–49,95; public-ip-review: 178,186; team-domain: 167; uuid: 136,143,147,195,202,212 |
| `3f3cf1062258` | `test/docker/SSH.md` | email-review: 117–121; host-or-username: 117–121; ipv6-review: 69,86; mesh-ip: 7–8,32,35,38,43–44,47–48,53,61,66,72,79,85,98,105,116–121; personal-path: 10,13,55,63; team-domain: 117–121; uuid: 117–121 |
| `946743ea92e6` | `test/docker/e2e.sh` | personal-path: 9 |
| `d0eabd86b516` | `test/docker/rules-gateway.json` | ipv6-review: 19,39,59,79; mesh-ip: 19,39,59,79; uuid: 3,23,43,63 |
| `d0eabd86b516` | `test/docker/rules-policy.json` | ipv6-review: 28; mesh-ip: 8–27 |
| `ad8473b9e3c5` | `test/native/Dockerfile` | personal-path: 5 |
| `ad8473b9e3c5` | `test/native/README.md` | mesh-ip: 54,61–64,67–69; personal-path: 11,18,27–28,39–40; uuid: 84 |
| `ad8473b9e3c5` | `test/native/REPORT.md` | mesh-ip: 44–45,49–50,61,64; uuid: 70 |
| `ad8473b9e3c5` | `test/native/evidence.log` | ipv6-review: 16,25–26,50,92; mesh-ip: 16,21,28–29,32–33,35–36,38–39,41,50,54–55,57,63,76–79,83–86,92,99–100 |

## Commit metadata and binary evidence

84 commits use a non-noreply author or committer email. Review consent or replace metadata when publishing a fresh snapshot. Commit locations (addresses omitted): `d07c1ef3b3ca`, `5d20c0b1c8c3`, `39f153fdcfd6`, `6e37bf7e31bb`, `035379a5907c`, `2a7c9d75cbd2`, `2e86e3b0f2cf`, `a15443965530`, `bb7fa666f2c6`, `21b12dfbd479`, `999c73c5fe79`, `2b838a78d589`, `d7a83a3e0bde`, `484ae1f604ff`, `074b2a2f4d30`, `353675407301`, `c4b5db1c754a`, `250b015455b8`, `79ad45f36a08`, `ea781f77a063`, `b74a722ce181`, `7698d8fd5658`, `afb8eb25c91e`, `3e36270516d5`, `64a6153bb1b5`, `c01bf49fcb4a`, `75dc7e3d57e3`, `e59503650d7b`, `f87eb06537b7`, `b636c73b00d0`, `e3f15d63c9a4`, `cafccda08e09`, `c6636e5cdc28`, `a1c18fbb645c`, `443d4eef4559`, `f7c76cd7c4a7`, `72c2cfd27021`, `5b1bed73de72`, `f7240c343dc8`, `1c8d79b0cac2`, `4371324fa1b1`, `548db5e2e83f`, `800ab690711b`, `8522cc9daa0b`, `d78e2572893d`, `0d949279f10a`, `190c3a091aba`, `eee61e5a6bc8`, `655a6d1dd314`, `3b166a2e4111`, `05e5000b1a19`, `1a28ee020a55`, `e61b62905ccc`, `5c15b7b780a6`, `5b83d5d8d37a`, `cb454ed4a5d7`, `1ae5e436bd00`, `f845a0f0d899`, `16f536ac2c4d`, `2b652761be50`, `89f3ae4c647b`, `742dc7419e2d`, `6c20e96aeb4d`, `4d6ee2b09357`, `558dd8964a3a`, `d59394c6b612`, `b10c7aed4a58`, `d0eabd86b516`, `cd49ffe6f144`, `11301a187646`, `ad8473b9e3c5`, `cb2403670c3a`, `aa0c8dafac57`, `a1453638c783`, `4e20f198323b`, `0202e8bb038d`, `3f3cf1062258`, `f5534c42bceb`, `946743ea92e6`, `e7c155fda51b`, `926fe8b9e132`, `7ee3b2b081a0`, `f2a05f633cde`, `9136fdb97a48`.

All 106 tracked PNG screenshots were opened for visual review. Account-bearing screenshots used a real mail-domain fixture address; 96 were removed, and the ten signed-out/sign-in snapshots were retained. Four tracked compressed packet captures were removed. Every removed binary/log/resource path is listed in [removed-artifacts.md](removed-artifacts.md); those historical binary objects must be excluded from the published history as well.
