cd /home/ravinata/ai/k9x-ecosystem/satan
sudo rm -rf k9x_satan
tar -xzf k9x_satan.tar.gz
sudo podman build -f k9x_satan/deployment/Dockerfile -t k9x-satan:latest .
sudo podman stop k9x_satan 2>/dev/null || true
sudo podman rm   k9x_satan 2>/dev/null || true
sudo podman run -d --name k9x_satan \
  --restart=always \
  --memory=16g --cpus=8 \
  -p 127.0.0.1:6660:6660 \
  -e K9_ENV=development \
  -e SATAN_GOVERNANCE=noop \
  -e SATAN_LOCK_CONFIG=true \
  -e SATAN_WORKER_POOL_SIZE=10 \
  k9x-satan:latest
