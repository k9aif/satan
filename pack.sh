#!/bin/bash
# Package k9x_satan for deployment — includes Dockerfile.
#
# Mirrors k9x_studio/pack.sh's mechanics, but simpler: k9_aif_abb comes from
# `pip install k9-aif` inside the container (see deployment/Dockerfile and
# requirements.txt), not a bundled framework checkout — verified against the
# published PyPI package before switching to this approach. Nothing from
# k9-aif-framework needs to travel in this tarball at all.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT="$(dirname "$SCRIPT_DIR")"          # k9x-ecosystem/

tar -czf "$SCRIPT_DIR/k9x_satan.tar.gz" \
  -C "$PARENT" \
  --exclude="__pycache__" \
  --exclude="*/__pycache__" \
  --exclude="k9x_satan/.venv" \
  --exclude="k9x_satan/.git" \
  --exclude="k9x_satan/.env" \
  --exclude="k9x_satan/runtime" \
  --exclude="k9x_satan/k9x_satan.tar.gz" \
  -s '/^k9x_satan/k9x_satan/' \
  k9x_satan \
  k9x_satan/deployment/Dockerfile

echo "Done → $SCRIPT_DIR/k9x_satan.tar.gz ($(du -sh "$SCRIPT_DIR/k9x_satan.tar.gz" | cut -f1))"
