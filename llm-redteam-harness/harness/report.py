import datetime
from collections import OrderedDict, defaultdict


def _mean(xs):
    xs = list(xs)
    return sum(xs) / len(xs) if xs else 0.0


def _pct(x):
    return f"{x * 100:.0f}%"


def by_category(rows, profile):
    d = OrderedDict()
    for r in rows:
        if r["profile"] == profile and r["kind"] == "attack":
            d.setdefault((r["owasp"], r["category"]), []).append(r["rate"])
    return {k: _mean(v) for k, v in d.items()}


def overall(rows, profile, kind="attack"):
    return _mean(r["rate"] for r in rows if r["profile"] == profile and r["kind"] == kind)


def write_markdown(rows, meta, path):
    L = [f"# Results ({datetime.date.today().isoformat()})", "",
         f"Backend: `{meta['backend']}` | model: `{meta['model']}` | runs per case: {meta['runs']}", ""]
    if meta["backend"] == "mock":
        L += ["> **Simulated backend.** These numbers come from a deterministic rule-based stand-in for a naive LLM. "
              "They show how the harness measures attacks and defences; they are not measurements of any real model.", ""]
    n_att = len({r["id"] for r in rows if r["kind"] == "attack"})
    L += [f"## Attack success rate (ASR) by OWASP category ({n_att} attacks, lower is better)", "",
          "| OWASP | Category | Baseline | All defences |", "|---|---|---|---|"]
    base, full = by_category(rows, "baseline"), by_category(rows, "all_defences")
    for k in base:
        L.append(f"| {k[0]} | {k[1]} | {_pct(base[k])} | {_pct(full[k])} |")
    L.append(f"| | **Overall** | **{_pct(overall(rows, 'baseline'))}** | **{_pct(overall(rows, 'all_defences'))}** |")

    profs = list(OrderedDict.fromkeys(r["profile"] for r in rows))
    L += ["", "## Defence ablation (each defence on its own)", "",
          "| Profile | Overall ASR | Benign pass rate |", "|---|---|---|"]
    for p in profs:
        L.append(f"| {p} | {_pct(overall(rows, p))} | {_pct(overall(rows, p, 'benign'))} |")

    L += ["", "## Per-attack results (baseline -> all defences)", "",
          "| ID | Attack | Baseline | All defences |", "|---|---|---|---|"]
    ids = defaultdict(dict)
    for r in rows:
        if r["kind"] == "attack" and r["profile"] in ("baseline", "all_defences"):
            ids[(r["id"], r["title"])][r["profile"]] = r["rate"]
    for (i, t), v in ids.items():
        L.append(f"| {i} | {t} | {_pct(v['baseline'])} | {_pct(v['all_defences'])} |")

    surv = [f"{i} ({t})" for (i, t), v in ids.items() if v["all_defences"] > 0]
    L += ["", "## Attacks that still succeed with all defences on", ""]
    L += [f"- {s}" for s in surv] or ["- none"]
    text = "\n".join(L) + "\n"
    with open(path, "w") as f:
        f.write(text)
    return text


def write_chart(rows, path, meta):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return
    base, full = by_category(rows, "baseline"), by_category(rows, "all_defences")
    labels = [f"{k[0]}\n{k[1]}" for k in base]
    x = range(len(labels))
    fig, ax = plt.subplots(figsize=(11, 4.8))
    ax.bar([i - 0.2 for i in x], [v * 100 for v in base.values()], 0.4, label="Baseline", color="#c0392b")
    ax.bar([i + 0.2 for i in x], [v * 100 for v in full.values()], 0.4, label="All defences", color="#2e86c1")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, fontsize=7)
    ax.set_ylabel("Attack success rate (%)")
    ax.set_ylim(0, 105)
    ax.set_title(f"LLM red-team harness - ASR by OWASP LLM Top 10 category ({meta['backend']} backend)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=150)
