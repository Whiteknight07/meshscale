FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iproute2 openssh-client curl passwd procps && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1001 -s /bin/bash testuser
COPY --chmod=0755 meshscale /usr/local/bin/meshscale
ENV HOME=/home/testuser XDG_CONFIG_HOME=/state/config
