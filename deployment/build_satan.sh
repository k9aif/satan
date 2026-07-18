cd /home/ravinata/ai/k9x-ecosystem/satan
sudo rm -rf k9x_satan
tar -xzf k9x_satan.tar.gz

# K9AIF_CACHE_VERSION busts the Dockerfile's git-clone layer cache on every
# build — without this, podman reuses the cached clone from whatever
# framework commit was live the FIRST time this ran, forever, no matter how
# many new commits get pushed to k9-aif-framework afterward. A timestamp
# guarantees this layer (and the pip install layer that follows it) always
# re-runs fresh, at the cost of that one layer never being cache-accelerated.
sudo podman build \
  --build-arg K9AIF_CACHE_VERSION="$(date +%s)" \
  -f k9x_satan/deployment/Dockerfile -t k9x-satan:latest .
sudo podman stop k9x_satan 2>/dev/null || true
sudo podman rm   k9x_satan 2>/dev/null || true

# Host-backed volume for attack history (app.py persists history.json here) —
# without this, history.json lives only inside the container's writable
# layer and a `podman rm`/rebuild (this script does both, every run) wipes it.
# world-writable because the container runs as UID 1001, which has no
# reliable identity on the RHEL host side of a bind mount.
SATAN_DATA_HOST_DIR=/home/container_storage/volumes/k9x-ecosystem/k9x-satan
sudo mkdir -p "$SATAN_DATA_HOST_DIR"
sudo chmod 777 "$SATAN_DATA_HOST_DIR"

sudo podman run -d --name k9x_satan \
  --restart=always \
  --memory=16g --cpus=8 \
  -p 127.0.0.1:6660:6660 \
  -v "$SATAN_DATA_HOST_DIR":/app/data:Z \
  -e K9_ENV=development \
  -e SATAN_GOVERNANCE=noop \
  -e SATAN_LOCK_CONFIG=true \
  -e SATAN_WORKER_POOL_SIZE=10 \
  k9x-satan:latest
