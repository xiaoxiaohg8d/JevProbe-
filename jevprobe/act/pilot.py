"""Sprint 4-E: Phase 3 ACT pilot (<=50 cases; 5 surfaces x 5 frozen dimensions).

Pipeline per case: transform (Qwen3-32B/template) -> original x5 + modified x5
judged -> differential (frozen metrics) -> record v2.4 + registry entry.
All cases logged (executed/failed/unstable). Report: phase3_act_pilot_report.md.
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from jevprobe.act import runner  # noqa: E402
from jevprobe.act.surfaces import (  # noqa: E402
    DIM_STRATEGIES, SURFACES, make_judge, spec_factory,
)
from jevprobe.act.transformer import transform  # noqa: E402

EXPERIMENTS = ROOT / "experiments"
REPORTS = ROOT / "reports"
TRIALS = 5


def main(trials: int = TRIALS) -> int:
    EXPERIMENTS.mkdir(exist_ok=True)
    REPORTS.mkdir(exist_ok=True)
    reg_path = EXPERIMENTS / "registry.json"
    registry = json.loads(reg_path.read_text(encoding="utf-8")) if reg_path.exists() else {"cases": []}
    known = {c["case_id"] for c in registry["cases"]}

    rec_path = EXPERIMENTS / "pilot_records.jsonl"
    records = [json.loads(line) for line in rec_path.read_text(encoding="utf-8").splitlines()
               if line.strip()] if rec_path.exists() else []
    entries = registry["cases"]
    case_n = 0
    for surf in SURFACES:
        judge = make_judge(surf["judge_kind"], surf)
        for dim, strat in DIM_STRATEGIES:
            case_n += 1
            case_id = f"C-{case_n:03d}"
            if case_id in known:
                print(f"skip {case_id} (registry already has it)"); continue
            inputs = EXPERIMENTS / "pilot_inputs"
            inputs.mkdir(exist_ok=True)
            input_path = inputs / f"{case_id}.json"
            if input_path.exists():
                saved = json.loads(input_path.read_text(encoding="utf-8"))
                if (saved["repo"], saved["surface_id"], saved["strategy"], saved["original_context"]) != (
                    surf["repo"], surf["surface_id"], strat, surf["base_context"]):
                    raise ValueError(f"{case_id}: saved input conflicts with current configuration")
                tr = {"original_context": saved["original_context"],
                      "modified_context": saved["modified_context"], "dimension": saved["dimension"],
                      "strategy": saved["strategy"], "visibility": saved["visibility"],
                      "error": saved.get("generation_error")}
            else:
                tr = transform(surf["base_context"], strat, use_llm=True)
            case = {"case_id": case_id, "repo": surf["repo"],
                    "surface_id": surf["surface_id"], "surface_type": surf["surface_type"],
                    "source_type": surf["source_type"], "location": surf["injection_location"],
                    "dimension": tr["dimension"], "strategy": tr["strategy"],
                    "visibility": tr["visibility"],
                    "semantic_preservation": _preservation(tr),
                    "attack_goal": "behavior_change",
                    "original_context": tr["original_context"],
                    "modified_context": tr["modified_context"],
                    "generation_error": tr["error"],
                    "spec_factory": lambda ctx, s=surf: spec_factory(s, ctx)}
            # Persist exact generator output BEFORE judgment. Never regenerate a
            # lost stochastic variant and pass it off as the original case.
            _atomic_text(input_path, json.dumps(
                {k: v for k, v in case.items() if k != "spec_factory"},
                ensure_ascii=False, indent=2))
            if tr["error"] or not tr["modified_context"]:
                entry = runner._registry_entry(case, status="failed",
                                               decision_before=None, decision_after=None,
                                               divergence=False,
                                               failure_reason=tr["error"] or "empty transform")
                registry["cases"].append(entry)
                _save(reg_path, registry, records)
                print(f"{case_id} {surf['repo']:17s} {strat:22s} FAILED: {entry['failure_reason']}")
                continue
            rec, entry = runner.run_case(case, judge, trials=trials)
            if rec:
                records.append(rec)
            registry["cases"].append(entry)
            print(f"{case_id} {surf['repo']:17s} {strat:22s} {entry['status']:9s} "
                  f"{entry['decision_before']} -> {entry['decision_after']} "
                  f"diverge={entry['divergence']}")
            _save(reg_path, registry, records)
            time.sleep(0.4)  # be gentle to the gateway
    _save(reg_path, registry, records)
    _report(records, [e for e in entries if "phase4_run_id" not in e])
    return 0


def _preservation(tr: dict) -> str:
    # contract-based labeling (guideline v2 semantic_preservation field)
    return {"instructional_influence": "not_preserved",
            "metadata_manipulation": "partially_preserved",
            "context_augmentation": "partially_preserved",
            "semantic_framing": "preserved",
            "information_ordering": "preserved"}.get(tr["dimension"], "unknown")


def _save(reg_path: Path, registry: dict, records: list[dict]):
    # Save detail first: interrupted writes may leave an orphan detail, but
    # must not mark a case completed before its detail is durably written.
    rec_path = ROOT / "experiments" / "pilot_records.jsonl"
    _atomic_text(rec_path, "".join(json.dumps(r, ensure_ascii=False) + "\n"
                                 for r in records))
    _atomic_text(reg_path, json.dumps(registry, ensure_ascii=False, indent=1))


def _atomic_text(path: Path, text: str):
    import os
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                     prefix=path.name + ".", delete=False) as f:
        temp_path = Path(f.name)
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    try:
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)


def _report(records: list[dict], entries: list[dict]):
    executed = [e for e in entries if e["status"] == "executed"]
    unstable = [e for e in entries if e["status"] == "unstable"]
    failed = [e for e in entries if e["status"] == "failed"]
    diverged = [e for e in executed if e["divergence"]]

    def dist(key):
        d = {}
        for e in entries:
            d[e[key]] = d.get(e[key], 0) + 1
        return d

    flips = [e for e in diverged if e["status"] == "executed"]
    lines = ["# Phase 3 ACT Pilot Report (RQ3 first closed loop)", "",
             f"- generated: {datetime.now(timezone.utc).isoformat()}",
             f"- judge tracks: jev-1.13.0@zhizengzeng (LLM surfaces) / real functions (controls)",
             f"- repeatability: 5+5 runs per case (frozen protocol)", "",
             "## 1. Objects", "",
             "| surface | judge | source | selection reason |", "|---|---|---|---|"]
    for s in SURFACES:
        lines.append(f"| {s['key']} | {s['judge_kind']} | {s['source_type']} | {s['select_reason']} |")
    lines += ["", "## 2-4. Case statistics", "",
              f"- cases total: {len(entries)} (executed {len(executed)} / unstable {len(unstable)} / failed {len(failed)})",
              f"- dimension distribution: {json.dumps(dist('dimension'), ensure_ascii=False)}",
              f"- strategy distribution: {json.dumps(dist('strategy'), ensure_ascii=False)}",
              f"- visibility distribution: {json.dumps(dist('visibility'), ensure_ascii=False)}", "",
              "## 5-6. Divergence results (choice surfaces: DFR + USS)", ""]
    dfr = len(diverged) / len(executed) if executed else 0.0
    lines += [f"- **DFR (decision flip rate, executed)**: {len(diverged)}/{len(executed)} = {dfr:.1%}",
              f"- unstable rate: {len(unstable)}/{len(entries)}",
              "", "| case | repo | dimension | strategy | visibility | before | after | flip | flip_consistency |",
              "|---|---|---|---|---|---|---|---|---|"]
    for e in entries:
        rec = next((r for r in records if r.get("surface_id") == e["surface_id"]
                    and r["strategy"] == e["strategy"]), None)
        fc = rec["repeatability"].get("flip_consistency", "-") if rec else "-"
        lines.append(f"| {e['case_id']} | {e['repo']} | {e['dimension']} | {e['strategy']} "
                     f"| {e['visibility']} | {e['decision_before']} | {e['decision_after']} "
                     f"| {e['divergence']} | {fc} |")
    lines += ["", "## 7. Failed cases", ""]
    missing = [e["case_id"] for e in entries if e["status"] != "failed" and
               not any(r.get("surface_id") == e["surface_id"] and
                       r.get("strategy") == e["strategy"] for r in records)]
    lines += [f"- historical cases missing detailed records: {', '.join(missing) or 'none'}",
              "- Registry decisions alone do not establish reproducible L1 evidence.",
              "- LLM contracts are abstract substitutes; native target consumers were not run in this pilot."]
    for e in failed:
        lines.append(f"- {e['case_id']} {e['repo']}/{e['strategy']}: {e['failure_reason']}")
    if not failed:
        lines.append("- none")
    lines += ["", "## 8. Next-stage suggestions", "",
              "- expand to Sprint-4 queue repos (guardrails/nemo/llm-guard real-code drivers)",
              "- add score/uncertainty/ranking surfaces for TCR/USS/RDR coverage",
              "- GLM-generator cross-check for generator-robustness axis (appendix)",
              "- Phase 4: e2e behavioral validation on diverged cases (L3/L4)"]
    (REPORTS / "phase3_act_pilot_report.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8")
    print("report written: reports/phase3_act_pilot_report.md")


if __name__ == "__main__":
    raise SystemExit(main())
