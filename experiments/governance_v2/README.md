# Governance evaluation v2 (IEEE Access resubmission, Section VII-F)

Archived here so the paper's governance results can be reproduced from a tagged, DOI-archived
release. Start with `PROTOCOL.md` (design, metrics, and deviations 1-7, each with its reason and date).

| Path | What |
|---|---|
| `corpus/` | frozen corpus: 104 attacks (13 classes x 4 wordings x 2 placements), 104 benign; `SHA256SUMS`, `manifest.json` |
| `corpus_heldout/` | held-out corpus (seed 20261004): 103 attacks, 104 benign; `model_wordings.json` is the wording model's raw output |
| `run_eval.py` | runs one configuration (F = pattern checks + Guardian, P = pattern checks, G = Guardian) over a corpus |
| `analyze.py`, `make_tables.py` | `results/*.jsonl` -> `results/summary.json`, `SUMMARY.md`, `tables.tex` (Wilson 95% intervals over documents) |
| `rerun_unavailable.py` | deviation 6: Guardian-outage blocks archived as `*.unavailable.jsonl` and re-run |
| `results/` | one JSON line per document per run; logs |

Code measured: k9-aif `4af1151` (frozen corpus; held-out before the fixes) and `d25ca44` (held-out
after the fixes), both contained in k9-aif v1.15.0. Models: `qwen3.8:27b` (agents, thinking off),
`granite4.1-guardian:8b` (Guardian), via Ollama.

Reproduce: `OLLAMA_BASE_URL=http://<host>:11434 python run_eval.py --config F --run 1`, then
`python analyze.py && python make_tables.py`. The shell scripts (`run_all.sh`, `run_heldout.sh`,
`trial.sh`) are kept as the record of how the runs were launched and name the original machine's paths.
The Ollama host address in archived error messages is redacted to `<ollama-host>`; no measured value is
affected (`analyze.py` reproduces `summary.json` byte for byte).
