#!/bin/bash
# Keep SwiftPM configuration and caches inside this checkout on the build Mac.
set -euo pipefail
cd "$(dirname "$0")/.."
subcommand="${1:?Usage: scripts/swift.sh <build|test> [options]}"
shift
exec swift "$subcommand" \
  --cache-path "$PWD/.build/cache" \
  --config-path "$PWD/.build/config" \
  --security-path "$PWD/.build/security" \
  --manifest-cache local "$@"
