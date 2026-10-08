#!/bin/bash
# Timing/harness trial (run 0, not committed): 8 benign (one per type) + 13 paraphrase attacks, config F.
cd "$(dirname "$0")"
V=~/ai/k9x-publication/IEEE_Access/v8/experiments/langgraph_comparison/.venv/bin/python
for o in benign_auto_01 benign_water_01 benign_medical_01 benign_theft_01 benign_travel_01 benign_renewal_01 benign_fire_01 benign_liability_01 _w2_p0; do
  $V run_eval.py --config F --run 0 --only "$o" 2>&1 | grep -E "^F r0"
done
