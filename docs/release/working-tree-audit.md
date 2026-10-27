# Working-tree findings for the other release streams

These are S1's pre-edit scan locations, not a claim that another worker has left them unresolved. S1 did not edit these files. Re-check after the owning stream commits; line numbers may move. Values are intentionally omitted. Author/public project identities and deliberately synthetic fixtures need contextual review rather than blanket deletion.

| Severity | Area | Finding and required follow-up |
| --- | --- | --- |
| P1 | Live docs, Swift fixtures, WARP fixtures, `test/` evidence below | Replace personal emails/team names, real host/endpoint identifiers and captured UUIDs/public keys with synthetic examples before publication. |
| P2 | `app/frontend/src/mock.ts`, Swift review fixtures | Non-reserved mail-domain fixture must become an `example.com` identity before regenerating removed screenshots. |
| P2 | Broken relative links below | Replace references to removed evidence with maintained guides or the removal manifest. |
| P2 | `control/package.json`, `app/frontend/package.json` | npm reports local project roots as UNLICENSED because package metadata has no license field; repository LICENSE is MIT. Owners should set the metadata consistently. |
| P3 | `internal/auth/client.go:17` | OAuth public client ID is intentionally distributable, not a secret; clarify its private-client usability restriction, not credential rotation. |

Ignored private environment/registration/SSH state remains local and must not be shipped. Do not delete it as a release hygiene shortcut: it may be required for authorized teardown. No production resources were touched by S1.

## Locations to review

| File | Type and original lines |
| --- | --- |
| `app/DESIGN.md` | email-review: 63,118 |
| `app/frontend/README.md` | personal-path: 12,13,25,33 |
| `app/frontend/preview.html` | email-review: 9 |
| `app/frontend/src/mock.ts` | email-review: 7,9,11,16 |
| `cmd/meshscale/doctor_network.go` | public-ip: 63 |
| `cmd/meshscale/login_setup_test.go` | email-review: 153 |
| `cmd/meshscale/publication_test.go` | host-or-username: 30,132,139 |
| `cmd/meshscale/status_test.go` | host-or-username: 365 |
| `control/test/auth.test.ts` | team-domain: 38 |
| `docs/admin-console.md` | host-or-username: 3 |
| `docs/cert.md` | host-or-username: 10,12,13,20,80,125,131 |
| `docs/cloudflare-ssh.md` | email-review: 85; hex-id: 264; host-or-username: 82,85,87,89,94,98,112,355,356,357,364; personal-email: 85,364; uuid: 100,101,102,107,108,109,117,332,333,334,335,336,337,338,339,340,341 |
| `docs/devices.md` | email-review: 65; host-or-username: 64,65; personal-email: 65; uuid: 77,78 |
| `docs/exit-nodes.md` | host-or-username: 59,66,81,84,87,92,142,217,393,394,395,503,530,604,607,609,610,632,640,643,649,652,653,677,678,690,696,700,713,728,737,750,752,757; personal-email: 503,604,652; public-ip: 87,88,90,96,97,98,99,108,478,479,480,481,608,643,679,682,683,684,685,688,719,731,732,754; uuid: 85,478,479,480,481 |
| `docs/funnel.md` | host-or-username: 5,12,45,46,57,69,96,97,98,99,151 |
| `docs/install.md` | personal-path: 184 |
| `docs/linux-host.md` | host-or-username: 7,42,129,147,148,149,154,155; personal-email: 154,155; public-ip: 157,187 |
| `docs/performance.md` | host-or-username: 23 |
| `docs/publication-live.md` | hex-id: 18,76,90,91,92; host-or-username: 3,15,17,22,27,28,30,31,36,39,40,46,49,50,51,57,65,75,98,104,105; personal-email: 105; personal-path: 43,78; team-domain: 30; uuid: 90,91,92 |
| `docs/secure.md` | email-review: 26,351; host-or-username: 89,161,252,310,315,324,353,372,387,388,413,460,472,597,677,688; key-material: 354; personal-email: 372; personal-path: 90; uuid: 353 |
| `docs/setup.md` | email-review: 192; hex-id: 148; host-or-username: 182,192; personal-email: 192; team-domain: 56,182 |
| `docs/ssh.md` | uuid: 106 |
| `docs/status-verification.md` | host-or-username: 56,113,115; personal-email: 115; public-ip: 112 |
| `internal/cfapi/publication_test.go` | host-or-username: 26,29,38,46,68 |
| `internal/cloudflaressh/host.go` | email-review: 146,266 |
| `internal/cloudflaressh/host_test.go` | email-review: 28 |
| `internal/exitnode/firewall.go` | public-ip: 129 |
| `internal/exitnode/firewall_test.go` | public-ip: 194,202 |
| `internal/exitnode/manager_test.go` | public-ip: 110,118 |
| `internal/exitnode/routing_test.go` | public-ip: 147,152 |
| `internal/exitnode/warp.go` | public-ip: 24,52 |
| `internal/exitnode/warp_test.go` | public-ip: 49,50,55 |
| `internal/mesh/full_setup_test.go` | team-domain: 50,60 |
| `internal/mesh/setup_test.go` | email-review: 59,123 |
| `internal/native/registration_test.go` | public-ip: 36 |
| `internal/native/testdata/registration.json` | key-material: 6,10; public-ip: 11; uuid: 4,14 |
| `internal/publication/audit_test.go` | host-or-username: 32,33,37,75,76,84,96,108,117,118,127,129,272,299,300,448,469,500,501,505,509,555,585,592 |
| `internal/publication/publication_test.go` | host-or-username: 132,148,246,292,306,334,335,349,359,385,386,426,427,448,458,491,548,590,591,592,595,626,675,676; public-ip: 448 |
| `internal/secure/exit_test.go` | host-or-username: 18,24,25,26,27,28,29,30 |
| `internal/sshserver/handshake_linux_test.go` | email-review: 117 |
| `internal/sshserver/policy_test.go` | email-review: 11 |
| `internal/sshserver/server.go` | email-review: 157 |
| `internal/sshserver/session_linux.go` | email-review: 128 |
| `internal/warpcli/safety.go` | public-ip: 61 |
| `internal/warpcli/safety_test.go` | host-or-username: 29,39,40,43,44,45,46,47,48,49,50,51,52,114,143; public-ip: 47 |
| `internal/warpcli/testdata/mac-registration.txt` | hex-id: 5; host-or-username: 6; uuid: 2,3 |
| `internal/warpcli/testdata/mac-settings.txt` | hex-id: 14; host-or-username: 24,46; public-ip: 14,22,52; team-domain: 24; uuid: 54 |
| `internal/warpcli/warpcli_test.go` | host-or-username: 153 |
| `macos/README.md` | host-or-username: 22,23; personal-email: 22,23; personal-path: 17 |
| `macos/Tests/MeshscaleCoreTests/ClientTests.swift` | email-review: 170,171; host-or-username: 149,150; personal-email: 149,150 |
| `macos/Tests/MeshscaleCoreTests/Fixtures/status-real.json` | email-review: 40; host-or-username: 40; team-domain: 40; uuid: 3,4,5,19,20,21,35,36,49 |
| `macos/Tests/MeshscaleCoreTests/ReviewFixture.swift` | email-review: 11,13,15,20 |
| `macos/scripts/verify-connectivity.py` | host-or-username: 14; personal-email: 14 |
| `macos/scripts/verify-real-data.py` | host-or-username: 37; personal-email: 37; personal-path: 8 |
| `test/docker/DNS.md` | personal-path: 3,170 |
| `test/docker/README.md` | email-review: 27,56; host-or-username: 27,56; personal-path: 3,8; team-domain: 27,56 |
| `test/docker/RULES.md` | personal-path: 3 |
| `test/docker/SERVICE.md` | email-review: 139,152,206,210; host-or-username: 139,152,167,206,210; personal-email: 139,152,206,210; personal-path: 25,48,49,95; public-ip: 178,186; team-domain: 167 |
| `test/docker/SSH.md` | email-review: 117,118,119,120,121; host-or-username: 117,118,119,120,121; personal-path: 10,13,55,63; team-domain: 117,118,119,120,121 |
| `test/docker/e2e.sh` | personal-path: 9 |
| `test/native/Dockerfile` | personal-path: 5 |
| `test/native/README.md` | personal-path: 11,18,27,28,39,40 |

## Cross-stream broken relative links

The S1 scanner checks path existence and Markdown heading targets. These links refer to removed account-bearing evidence or a removed verification manifest. Update the owning page; do not restore private evidence solely to satisfy a link.

| File and line | Target |
| --- | --- |
| `app/frontend/README.md:40` | `screenshots/verification.json` |
| `docs/cloudflare-ssh.md:80` | `../spike/cfssh/implementation-live.json` |
| `docs/cloudflare-ssh.md:284` | `../spike/cfssh/probe.py` |
| `docs/cloudflare-ssh.md:285` | `../spike/cfssh/preflight.json` |
| `docs/cloudflare-ssh.md:286` | `../spike/cfssh/live-attempt1.json` |
| `docs/cloudflare-ssh.md:287` | `../spike/cfssh/live-attempt2.json` |
| `docs/cloudflare-ssh.md:288` | `../spike/cfssh/live-attempt3.json` |
| `docs/cloudflare-ssh.md:289` | `../spike/cfssh/live.json` |
| `docs/cloudflare-ssh.md:290` | `../spike/cfssh/summary.json` |
| `docs/exit-nodes.md:112` | `../spike/exitnode/evidence.json` |
| `docs/publication-live.md:69` | `../spike/publication/live-20261026/latency.json` |
| `docs/publication-live.md:99` | `../spike/publication/live-20261026/resource-audit.json` |
| `docs/publication-live.md:109` | `../spike/publication/live-20261026/before.txt` |
| `docs/publication-live.md:110` | `../spike/publication/live-20261026/after.txt` |
| `docs/publication-live.md:111` | `../spike/publication/live-20261026/mesh-tls.txt` |
| `docs/publication-live.md:112` | `../spike/publication/live-20261026/access-headers.txt` |
| `docs/publication-live.md:113` | `../spike/publication/live-20261026/access-policy-proof.json` |
| `docs/publication-live.md:114` | `../spike/publication/live-20261026/certificate.json` |
| `macos/README.md:151` | `verification/AUDIT-FIXES-2026-10-26.md` |
| `macos/README.md:183` | `verification/HANDOFF.md` |

The roadmap retains the prior onboarding heading anchor for compatibility. The copied design guidance with the missing license reference was removed within S1; the ignored native research checkouts are not tracked or bundled. No copied implementation code requiring additional attribution was identified in tracked spike source; this is a source review, not a legal opinion.

## Final shared-tree recheck

The subsequent relative-link scan checked 335 links and found only `app/frontend/README.md:42` still pointing at `screenshots/verification.json`; other streams repaired the removed-evidence references during this review. S1-owned links all resolve. The earlier table is retained as the pre-edit handoff inventory.

The final tracked/nonignored gitleaks scan has two findings: `internal/publication/process_test.go:21` is synthetic test input, while `internal/warpcli/testdata/mac-registration.txt:4` is a live registration public identity. No S1-owned file is flagged. Personal-name/team/context matches still warrant review in the files below; many unit-test hostname matches are synthetic context rather than credentials. A fresh snapshot avoids publishing the superseded real values from history even when the tip is now redacted.

| File | Remaining candidate type and lines |
| --- | --- |
| `cmd/meshscale/publication_test.go` | host-or-username: 30,132,139 |
| `cmd/meshscale/status_test.go` | host-or-username: 365 |
| `docs/cert.md` | host-or-username: 10,12,13,20,80 |
| `docs/funnel.md` | host-or-username: 5,12,45,46,57,69,96,97,98,99,154 |
| `docs/install.md` | personal-path: 192 |
| `internal/cfapi/publication_test.go` | host-or-username: 26,29,38,46,68 |
| `internal/publication/audit_test.go` | host-or-username: 32,33,37,75,76,84,96,108,117,118,127,129,272,299,300,448,469,500,501,505,509,555,585,592,603,622,662 |
| `internal/publication/publication_test.go` | host-or-username: 133,150,248,294,308,336,337,351,361,387,388,428,429,450,460,493,551,593,594,595,598,629,678,679 |
| `internal/secure/exit_test.go` | host-or-username: 18,24,25,26,27,28,29,30 |
| `internal/warpcli/safety_test.go` | host-or-username: 29,39,40,43,44,45,46,47,48,49,50,51,52,114,143 |
| `internal/warpcli/testdata/mac-registration.txt` | host-or-username: 6 |
| `internal/warpcli/testdata/mac-settings.txt` | host-or-username: 24,46; personal-team: 24 |
| `internal/warpcli/warpcli_test.go` | host-or-username: 153 |
| `test/docker/SERVICE.md` | personal-path: 27,50,51,97 |
| `test/docker/SSH.md` | personal-path: 57,65 |
| `test/native/Dockerfile` | personal-path: 5 |

The last post-commit scan checked 336 relative links with **zero missing paths or heading targets**. The frontend manifest reference was repaired by its owning stream. Earlier link tables are historical handoff locations, not unresolved defects.
