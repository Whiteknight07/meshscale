#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Rendering and fixtures are compiled only into the test bundle.
MESHSCALE_SNAPSHOT_DIRECTORY="$PWD/screenshots" ./scripts/swift.sh test --filter SnapshotTests/testExportSnapshots
