# S1 validation record

The shared development tree was checked on 2026-10-26 after concurrent edits settled:

| Check | Result |
| --- | --- |
| `go vet ./...` | Passed |
| `GOOS=darwin go vet ./...` | Passed |
| `go test -race -count=1 ./...` | Passed on retry after concurrent edits |
| `~/go/bin/staticcheck ./...` | Passed |
| `cd control && npm test && npx tsc --noEmit` | Passed: 78 tests; an earlier run timed out under concurrent load |
| `cd spike/nativewg && go test ./... && go vet ./...` | Passed; compile-only module, no test files |
| Secure-performance Python unit tests | Passed: three tests |
| Issue-form YAML parsing | Passed |
| `git diff --check` | Passed |
| `gofmt -l` over tracked/new Go files | Empty |
| Literal `gofmt -l .` | Reports ignored upstream code under `spike/nativewg/research/`; no tracked formatting issue. Third-party research copies were not reformatted for release hygiene |
| Relative Markdown link scan | Passed: 336 relative links, zero missing paths or heading targets after other streams repaired references |
| Gitleaks history + filesystem + final tracked-tree scans | Reviewed; zero S1-owned findings. See `history-audit.md` for classifications and remaining cross-stream fixture finding |
| Go dependency reports/license-text save | Passed for Linux ARM64; Darwin ARM64 report also passed |
| npm installed-dependency license summaries | Completed for control and frontend; tooling copyleft documented in `licenses.md` |

All 106 tracked PNGs were opened for visual review; 96 account-bearing snapshots were removed. Go checks on Linux do not validate SwiftUI builds. S1 made no production service, route/firewall, vendor-account, or credential changes. These are development-tree observations; the orchestrator must validate the final committed release tree and artifacts after all streams finish.
