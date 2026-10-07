"""Markdown report rendering for SJI experiment results."""
from __future__ import annotations


def render_report(meta: dict, per_spec: list[dict], summary: dict) -> str:
    lines = ["# SJI Experiment Report", ""]
    lines += [f"- generated: {meta.get('timestamp')}", f"- specs: {meta.get('n_specs')}",
              f"- seed: {meta.get('seed')}",
              f"- runners: {', '.join(meta.get('runners', []))}",
              f"- transforms: {', '.join(meta.get('transforms', []))}", ""]

    lines += ["## Summary (per runner x transform)", "",
              "| runner | transform | class | n | flip rate | systematic | margin-cross | mean JS | mean |dTop| |",
              "|---|---|---|---|---|---|---|---|---|"]
    for key, s in sorted(summary.items()):
        runner, tname = key
        lines.append(
            f"| {runner} | {tname} | {s.get('class','')} | {s['n']} "
            f"| {s['flip_rate']:.1%} | {s['systematic_flip_rate']:.1%} "
            f"| {s['margin_crossing_rate']:.1%} | {s['mean_js']:.4f} | {s['mean_abs_delta_top']:.4f} |")
    lines.append("")

    lines += ["## Per-spec findings (flips only)", ""]
    any_flip = False
    for entry in per_spec:
        for tr in entry["transform_results"]:
            if not (tr.get("flip") or tr.get("margin_crossing")):
                continue
            any_flip = True
            a = tr["analysis"]
            lines.append(
                f"### {entry['spec_id']} @ {entry['runner']} — {tr['transform']}\n"
                f"- base: `{a['base_decision']}` (margin {a['base_margin']}) "
                f"-> trans: `{a['trans_decision']}` (margin {a['trans_margin']})\n"
                f"- flip={a['flip']} systematic={a['systematic_flip']} "
                f"margin_crossing={a['margin_crossing']} JS={a['js_divergence']}\n"
                f"- U2A: base_entropy={a['u2a']['base_entropy']} "
                f"trans_entropy={a['u2a']['trans_entropy']}\n")
    if not any_flip:
        lines.append("_No flips or margin crossings observed._")

    lines += ["## Baselines", ""]
    seen = set()
    for entry in per_spec:
        k = (entry["runner"], entry["spec_id"])
        if k in seen:
            continue
        seen.add(k)
        b = entry["baseline"]
        lines.append(f"- `{entry['spec_id']}` @ {entry['runner']}: "
                     f"decision `{b['decision']}`, margin {b['margin']:.4f}, "
                     f"entropy {b['entropy']:.4f}")
    return "\n".join(lines) + "\n"
