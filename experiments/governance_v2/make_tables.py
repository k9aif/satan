# SPDX-License-Identifier: Apache-2.0
"""results/summary.json (from analyze.py) -> results/tables.tex for the manuscript.

  python analyze.py && python make_tables.py
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"

CLASSES = [
    ("direct_injection", "Direct injection"), ("html_comment_injection", "Hidden-comment injection"),
    ("roleplay_jailbreak", "Role-play jailbreak"), ("social_engineering", "Social engineering"),
    ("pii_exfiltration", "PII exfiltration"), ("phishing_lookalike_link", "Look-alike link"),
    ("phishing_brand_subdomain", "Brand-in-subdomain link"), ("debt_chatbot_lure", "Debt-chatbot lure"),
    ("paraphrased_override", "Paraphrased override"), ("agent_impersonation", "Agent impersonation"),
    ("oversized_payload", "Oversized payload"), ("system_prompt_extraction", "System-prompt extraction"),
    ("credential_planting", "Credential planting"),
]
WORDINGS = [("known", "Known phrasing"), ("paraphrase", "Paraphrase"), ("obfuscated", "Obfuscated"),
            ("indirect", "Indirect (quoted/table/note)")]
CONFIGS = [("F_production_run1", "F: pattern checks + Guardian"), ("P_production_run1", "P: pattern checks only"),
           ("G_production_run1", "G: Guardian only"), ("F_strict_run1_derived", "F, PII blocking at egress")]


def pct(x, ci=True):
    if not x or x.get("rate") is None:
        return "--"
    s = f"{x['rate'] * 100:.1f}"
    if ci:
        s += f" [{x['ci95'][0] * 100:.0f}, {x['ci95'][1] * 100:.0f}]"
    return s


def frac(x):
    return "--" if not x or x.get("n") in (None, 0) else f"{x['k']}/{x['n']}"


def main():
    s = json.loads((RESULTS / "summary.json").read_text())
    out = []
    # Table A: configurations
    out += [r"\begin{table*}[!t]", r"\renewcommand{\arraystretch}{1.15}",
            r"\caption{Governance Evaluation: Detection and False Blocks per Configuration (\%, Wilson 95\% Interval)}",
            r"\label{tab:adversarial}", r"\centering", r"\footnotesize",
            r"\begin{tabular}{lcccc}", r"\toprule",
            r"\textbf{Configuration} & \textbf{Attacks blocked} & \textbf{Stopped before agents} & "
            r"\textbf{Benign blocked} & \textbf{Benign flagged only} \\", r"\midrule"]
    for key, label in CONFIGS:
        x = s.get(key)
        if not x:
            continue
        out.append(f"{label} & {pct(x['detection'])} & {pct(x['detected_before_agents'])} & "
                   f"{pct(x['false_positive'])} & {pct(x['benign_flagged_not_blocked'])} \\\\")
    out += [r"\bottomrule",
            r"\multicolumn{5}{l}{\scriptsize 104 attack and 104 benign documents per configuration; "
            r"\texttt{qwen3.8:27b} agents, \texttt{granite4.1-guardian:8b}; one run each.} \\",
            r"\end{tabular}", r"\end{table*}", ""]
    # Table B: per class and wording
    cols = [k for k, _ in CONFIGS[:3] if k in s]
    out += [r"\begin{table}[!t]", r"\renewcommand{\arraystretch}{1.1}",
            r"\caption{Attacks Blocked per Class and Wording (of 8 per Class, 26 per Wording)}",
            r"\label{tab:perclass}", r"\centering", r"\footnotesize",
            r"\begin{tabular}{l" + "c" * len(cols) + "}", r"\toprule",
            r"\textbf{Attack} & " + " & ".join(r"\textbf{" + k[0] + "}" for k in cols) + r" \\", r"\midrule"]
    for key, label in CLASSES:
        out.append(label + " & " + " & ".join(frac(s[k]["per_class"].get(key)) for k in cols) + r" \\")
    out.append(r"\midrule")
    for key, label in WORDINGS:
        out.append(label + " & " + " & ".join(frac(s[k]["per_wording"].get(key)) for k in cols) + r" \\")
    out += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]
    # Per-check counts (F) as a sentence fragment for the text
    f = s.get("F_production_run1")
    if f:
        checks = ", ".join(f"{k} {v}" for k, v in f["blocking_check"].items())
        out.append(f"% F blocking checks: {checks}")
        out.append(f"% F false-positive checks: {f['false_positive_check']}")
        out.append(f"% F missed: {f['missed_attacks']}")
        out.append(f"% F false-positive documents: {f['false_positive_documents']}")
    v = s.get("variation_F_production")
    if v:
        out.append(f"% run-to-run: {v['documents_differing']} of {v['documents_compared']} differ over {v['runs']} runs: {v['differing']}")
    (RESULTS / "tables.tex").write_text("\n".join(out) + "\n")
    print("\n".join(out))


if __name__ == "__main__":
    main()
