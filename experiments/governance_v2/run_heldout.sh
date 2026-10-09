#!/bin/bash
# Deviation 5: waits for run_all.sh to finish, then generates the held-out corpus and runs
# P before the fix, P after, F after. Switches the editable framework checkout once, in between.
set -u
cd "$(dirname "$0")"
V=~/ai/k9x-publication/IEEE_Access/v8/experiments/langgraph_comparison/.venv/bin/python
FW=~/ai/k9-aif-framework
while pgrep -f "run_all.sh" >/dev/null || pgrep -f "run_eval.py" >/dev/null; do sleep 60; done
echo "=== D4 finished $(date '+%a %H:%M:%S'); re-running Guardian-unavailable documents (deviation 6, same code)"
for f in $($V rerun_unavailable.py | awk '{print $1}'); do
  cfg=${f%%_*}; run=$(echo "$f" | sed -E 's/.*_run([0-9]+)\.jsonl/\1/')
  sub=""; [ "$run" != "1" ] && sub="--subset"
  $V run_eval.py --config $cfg --run $run $sub 2>&1 | grep -E "^[FPG] r[0-9]"
done
echo "=== generating held-out corpus $(date '+%a %H:%M:%S')"
OLLAMA_BASE_URL=${OLLAMA_BASE_URL:?set OLLAMA_BASE_URL} $V gen_heldout.py || exit 1
echo "=== framework at $(git -C $FW rev-parse --short HEAD) (before fix)"
$V run_eval.py --config P --run 1 --corpus corpus_heldout --tag heldout_before 2>&1 | grep -E "^[FPG] r[0-9]"
git -C $FW merge --ff-only d4-check-gaps || exit 1
echo "=== framework at $(git -C $FW rev-parse --short HEAD) (after fix) $(date '+%a %H:%M:%S')"
$V run_eval.py --config P --run 1 --corpus corpus_heldout --tag heldout_after 2>&1 | grep -E "^[FPG] r[0-9]"
$V run_eval.py --config F --run 1 --corpus corpus_heldout --tag heldout_after 2>&1 | grep -E "^[FPG] r[0-9]"
echo "=== done $(date '+%a %H:%M:%S')"
$V analyze.py && $V make_tables.py >/dev/null
