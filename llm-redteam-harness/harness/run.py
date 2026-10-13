"""Run every attack against every defence profile and write CSV + Markdown + chart.

    python -m harness.run                                   # offline simulated model
    python -m harness.run --backend anthropic --runs 5      # real model (needs ANTHROPIC_API_KEY)
    python -m harness.run --backend openai --model llama3.1 # Ollama / any OpenAI-compatible server
"""
import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.backends import make_backend  # noqa: E402
from app.target import TargetApp  # noqa: E402
from attacks import ATTACKS, BENIGN  # noqa: E402
from defences.config import NAMES, DefenceConfig  # noqa: E402
from harness.report import write_chart, write_markdown  # noqa: E402


def profiles():
    p = [("baseline", DefenceConfig.none())]
    p += [(n, DefenceConfig.only(n)) for n in NAMES]
    p.append(("all_defences", DefenceConfig.all()))
    return p


def evaluate(backend, runs=1):
    rows = []
    for pname, cfg in profiles():
        app = TargetApp(backend, cfg)
        for case in ATTACKS + BENIGN:
            hits = sum(bool(case.check(app.respond(case.prompt))) for _ in range(runs))
            rows.append({"profile": pname, "id": case.id, "owasp": case.owasp, "category": case.category,
                         "title": case.title, "kind": case.kind, "rate": hits / runs})
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="mock", choices=["mock", "anthropic", "openai"])
    ap.add_argument("--model")
    ap.add_argument("--base-url")
    ap.add_argument("--runs", type=int, default=1, help="repeats per case (use >1 for real, non-deterministic models)")
    ap.add_argument("--out", default="results")
    a = ap.parse_args()

    backend = make_backend(a.backend, a.model, a.base_url)
    rows = evaluate(backend, a.runs)
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "results.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    meta = {"backend": backend.name, "model": getattr(backend, "model", "-"), "runs": a.runs}
    md = write_markdown(rows, meta, os.path.join(a.out, "summary.md"))
    write_chart(rows, os.path.join(a.out, "asr_by_category.png"), meta)
    print(md)


if __name__ == "__main__":
    main()
