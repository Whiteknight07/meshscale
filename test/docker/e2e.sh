#!/usr/bin/env bash
set -euo pipefail
# Run from any directory. Only Docker changes networking; WARP never runs here.
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo"
arch=${GOARCH:-$(go env GOARCH)}
image=meshscale-e2e
container=meshscale-node-1
credentials=${MESHSCALE_TEST_CREDENTIALS:-${XDG_CONFIG_HOME:-$HOME/.config}/meshscale/dev.env}
if [[ ! -r "$credentials" ]]; then
    echo "Missing credentials file: $credentials" >&2
    exit 1
fi
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -o "$repo/test/docker/meshscale" ./cmd/meshscale
trap 'rm -f "$repo/test/docker/meshscale"' EXIT
docker build --platform "linux/$arch" -t "$image" "$repo/test/docker"
if docker container inspect "$container" >/dev/null 2>&1; then
    # Preserve registration on repeats, and use the freshly built CLI.
    [[ $(docker inspect --format '{{.HostConfig.NetworkMode}}' "$container") == bridge ]] || { echo "Expected default bridge network" >&2; exit 1; }
    docker cp "$repo/test/docker/meshscale" "$container:/usr/local/bin/meshscale"
    docker start "$container" >/dev/null
else
    docker run -d --name "$container" --hostname meshscale-docker-test \
        --network bridge --cap-add NET_ADMIN --device /dev/net/tun \
        --env-file "$credentials" "$image" >/dev/null
fi
ready=false
for ((i=0; i<60; i++)); do
    if docker exec "$container" warp-cli --accept-tos --help >/dev/null 2>&1 && \
       docker exec "$container" test -S /run/cloudflare-warp/warp_service; then
        ready=true
        break
    fi
    sleep 1
done
if [[ "$ready" != true ]]; then
    echo "warp-svc did not create its IPC socket; inspect docker logs $container" >&2
    exit 1
fi
docker exec "$container" meshscale up --hostname meshscale-docker-test
docker exec "$container" meshscale ip
docker exec "$container" meshscale status
echo "Left $container running on the default bridge network."
