#!/usr/bin/env bash
# k9x_satan — build and run helper (single container, no pod needed)
# Run from any directory on the Podman host (no sudo needed — script handles it).
#
# Builds and runs directly from this git-cloned repo — no packed tarball,
# no staging/extraction step (that was the old pack.sh+scp.sh workflow for
# deploying to a private RHEL host via scp; here the repo is already local
# via git, so build context is just this project's own root).
#
# Commands:
#   build   — build the k9x-satan container image
#   start   — start the container (port 6660, localhost-only)
#   stop    — stop the container
#   logs    — tail logs
#   all     — build + start

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE="k9x-satan:latest"
CONTAINER="k9x_satan"
SATAN_DATA_HOST_DIR="${HOME}/containers/volumes/k9x-satan"

cmd="${1:-help}"

case "$cmd" in

  build)
    echo "Building $IMAGE ..."
    cd "$PROJECT_DIR"
    # K9AIF_CACHE_VERSION busts the Containerfile's git-clone layer cache on
    # every build — without this, podman reuses the cached clone from
    # whatever framework commit was live the FIRST time this ran, forever,
    # no matter how many new commits get pushed to k9-aif-framework
    # afterward. A timestamp guarantees this layer (and the pip install
    # layer that follows it) always re-runs fresh, at the cost of that one
    # layer never being cache-accelerated.
    sudo podman build \
      --build-arg K9AIF_CACHE_VERSION="$(date +%s)" \
      -f ubuntu/Containerfile -t "$IMAGE" .
    echo "Build complete: $IMAGE"
    ;;

  start)
    echo "Starting $CONTAINER on 127.0.0.1:6660 ..."
    sudo podman rm -f "$CONTAINER" 2>/dev/null || true
    # Host-backed volume for attack history (app.py persists history.json
    # here) — without this, history.json lives only inside the container's
    # writable layer and a podman rm/rebuild wipes it. World-writable
    # because the container runs as UID 1001, which has no reliable
    # identity on the host side of a bind mount.
    sudo mkdir -p "$SATAN_DATA_HOST_DIR"
    sudo chmod 777 "$SATAN_DATA_HOST_DIR"
    sudo podman run -d --name "$CONTAINER" \
      --restart=always \
      --memory=16g --cpus=8 \
      -p 127.0.0.1:6660:6660 \
      -v "$SATAN_DATA_HOST_DIR":/app/data:Z \
      -e K9_ENV=development \
      -e SATAN_GOVERNANCE=noop \
      -e SATAN_LOCK_CONFIG=true \
      -e SATAN_WORKER_POOL_SIZE=10 \
      "$IMAGE"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  k9x_satan"
    echo "  Web UI:  http://127.0.0.1:6660/  (localhost-only — reached via"
    echo "           the Cloudflare Tunnel at satan.k9x.ai, not the LAN IP)"
    echo "  Health:  http://127.0.0.1:6660/api/health"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    ;;

  stop)
    echo "Stopping $CONTAINER ..."
    sudo podman stop "$CONTAINER" 2>/dev/null || true
    echo "Stopped."
    ;;

  logs)
    sudo podman logs -f "$CONTAINER"
    ;;

  all)
    "$0" build
    "$0" start
    ;;

  help|*)
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  build   — build the Podman image ($IMAGE)"
    echo "  start   — start the container (port 6660, localhost-only)"
    echo "  stop    — stop the container"
    echo "  logs    — tail logs"
    echo "  all     — build + start"
    ;;

esac
