#!/bin/bash
# Measurement runs in protocol order (PROTOCOL.md section 6 + deviation 1). Resumable:
# re-running skips documents already recorded. Sequential: one GPU.
set -u
cd "$(dirname "$0")"
V=~/ai/k9x-publication/IEEE_Access/v8/experiments/langgraph_comparison/.venv/bin/python
for args in "--config F --run 1" "--config P --run 1" "--config G --run 1" \
            "--config F --run 2 --subset" "--config F --run 3 --subset"; do
  echo "=== $args  $(date '+%a %H:%M:%S')"
  $V run_eval.py $args 2>&1 | grep -E "^[FPG] r[0-9]" | tail -n +1
done
echo "=== done $(date '+%a %H:%M:%S')"
$V analyze.py
