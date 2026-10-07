"""Phase 4 follow-ups: immutable inputs, native consumer, 5+5, factorial C.

Run once per --run-id. A fresh input is a NEW case, never a recovery of a lost
historical stochastic variant. No attacks or commands reach an external sink.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
import re
import shutil
import subprocess
import sys

from ..act.differential import choice_diff, uncertainty_diff
from ..act.pilot import _atomic_text
from ..act.runner import JevAPIJudge, _registry_entry, aggregate
from ..act.surfaces import SURFACES
from ..act.transformer import transform
from ..schema.metrics import majority
from .impact import classify_divergence, dynamic_divergence
from .native_e2e import (FixedDecisionJudge, LLMGuardDriver, NemoDriver,
                         behavior_signature, fingerprint)

ROOT = Path(__file__).resolve().parents[2]


def save(path, obj):
    _atomic_text(path, json.dumps(obj, ensure_ascii=False, indent=2) + "\n")


def _registry_update(case, entry):
    path = ROOT / "experiments/registry.json"
    registry = json.loads(path.read_text())
    previous = next((e for e in registry["cases"] if e["case_id"] == case["case_id"]), None)
    if previous and previous.get("phase4_run_id") != case["phase4_run_id"]:
        raise RuntimeError("case ID collision with another experiment")
    registry["cases"] = [e for e in registry["cases"] if e["case_id"] != case["case_id"]] + [entry]
    save(path, registry)


def assess_runs(runs):
    b = [r["judge_calls"][0]["result"] for r in runs["original"]]
    a = [r["judge_calls"][0]["result"] for r in runs["modified"]]
    bd, bp = aggregate(b)
    ad, ap = aggregate(a)
    diff = choice_diff(bd, ad)
    diff["uss"] = uncertainty_diff(bp, ap)
    diff["behavior_before_distribution"] = dict(Counter(map(behavior_signature, runs["original"])))
    diff["behavior_after_distribution"] = dict(Counter(map(behavior_signature, runs["modified"])))
    stable_behavior = len(diff["behavior_before_distribution"]) == len(diff["behavior_after_distribution"]) == 1
    diff["behavioral_divergence"] = (behavior_signature(runs["original"][0]) !=
                                      behavior_signature(runs["modified"][0])) if stable_behavior else None
    return diff


def counterfactual(driver, original, modified, blocked, allowed, live, diff):
    cells = {}
    for source, text in (("original", original), ("modified", modified)):
        for decision in (blocked, allowed):
            cells[f"{source}|{decision}"] = driver.run(text, FixedDecisionJudge(decision))
    signatures = {k: behavior_signature(v) for k, v in cells.items()}
    fixed_source_effect = any(signatures[f"original|{d}"] != signatures[f"modified|{d}"]
                              for d in (blocked, allowed))
    decision_effect = all(signatures[f"{s}|{blocked}"] != signatures[f"{s}|{allowed}"]
                          for s in ("original", "modified"))
    matches = all(behavior_signature(r) == signatures[f"{side}|{r['judge_calls'][0]['result']['decision']}"]
                  for side, records in live.items() for r in records)
    return {"intervention": "Stage5B_only", "cells": cells,
            "source_effect_under_fixed_decision": fixed_source_effect,
            "decision_controls_behavior": decision_effect, "matches_live": matches,
            "causal_confirmation": bool(diff["flip"] and diff["behavioral_divergence"]
                                        and decision_effect and matches and not fixed_source_effect)}


def build_tables(results):
    rows = []
    for visibility in ("s1_explicit", "s2_artifact_based", "s3_contextual", "s4_semantic_only"):
        group = [r for r in results if r["case"]["visibility"] == visibility]
        executed = [r for r in group if r["status"] == "executed"]
        flips = sum(r.get("diff", {}).get("flip", False) for r in executed)
        behaviors = sum(bool(r.get("diff", {}).get("flip") and
                             r.get("diff", {}).get("behavioral_divergence")) for r in executed)
        rows.append({"visibility": visibility, "cases": len(group), "executed": len(executed),
                     "flips": flips, "DFR": flips / len(executed) if executed else None,
                     "behavior_changes_among_flips": behaviors,
                     "BDR": behaviors / flips if flips else None,
                     "SIR": None, "human_review_pending": len(executed)})
    levels = Counter(level for r in results for level in r.get("evidence", {}).get("evidence_levels", []))
    return {"table4": rows,
            "table5": {"flips": sum(r.get("status") == "executed" and r.get("diff", {}).get("flip", False)
                                     for r in results),
                       "evidence_level_counts": {level: levels[level] for level in ("L1", "L2", "L3", "L4", "C")},
                       "human_five_class_counts": None, "review_status": "pending_independent_human_review"}}


def report(out, results):
    tables = build_tables(results)
    save(out / "tables.json", tables)
    lines = ["# Phase 4 Native Consumer Follow-ups", "",
             "Scope: configured Jev substitute + unmodified native consumers + inert dependency audit.",
             "These are new follow-up cases, not replay of lost historical inputs or default-project vulnerabilities.",
             "Visibility and preservation annotations remain provisional pending independent review.", "",
             "| Case | Parent | Repo | Status | Before | After | Flip | Behavior | C |",
             "|---|---|---|---|---|---|---|---|---|"]
    for r in results:
        c, d = r["case"], r.get("diff", {})
        lines.append(f"| {c['case_id']} | {c['parent_case_id']} | {c['repo']} | {r['status']} | "
                     f"{d.get('majority_before')} | {d.get('majority_after')} | {d.get('flip')} | "
                     f"{d.get('behavioral_divergence')} | {r.get('counterfactual', {}).get('causal_confirmation')} |")
    lines += ["", "## Table 4 (follow-up scope only)", "",
              "| Visibility | Cases | Executed | DFR | BDR | SIR |",
              "|---|---|---|---|---|---|"]
    for row in tables["table4"]:
        lines.append(f"| {row['visibility']} | {row['cases']} | {row['executed']} | {row['DFR']} | {row['BDR']} | pending |")
    lines += ["", "## Table 5", "", json.dumps(tables["table5"], ensure_ascii=False, indent=2),
              "", "## Limits", "",
              "- Fixed judge revision; 5+5 randomly interleaved trials, case-level denominators.",
              "- Counterfactuals demonstrate decision mediation, not authorization or privilege violation.",
              "- An injected explicit instruction changes scanner-relevant semantics; a restrictive flip is not automatically a false positive.",
              "- Claimed approvals are attacker-controlled text; independent policy and trust-boundary oracle required for a security conclusion.",
              "- L3 records native consumer execution with an inert sink. L4 is not established.",
              "- SIR and human impact categories are null until humans adjudicate; null is not zero.",
              "- Registry-only summaries are kept separate from execution results."]
    for r in results:
        if r.get("failure_reason"):
            lines += [f"- {r['case']['case_id']} failure: {r['failure_reason']}"]
    _atomic_text(out / "report.md", "\n".join(lines) + "\n")


def main(run_id, trials=5, input_run_id=None):
    if trials < 3:
        raise ValueError(">=3 trials on EACH side required")
    if not re.fullmatch(r"[a-zA-Z0-9_-]+", run_id):
        raise ValueError("invalid run ID")
    out = ROOT / "experiments" / run_id
    out.mkdir(exist_ok=False)  # never overwrite an experiment
    (out / "inputs").mkdir()
    shutil.copytree(ROOT / "jevsec", out / "framework_sources/jevsec",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    prior = None
    if input_run_id:
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", input_run_id):
            raise ValueError("invalid input run ID")
        source_manifest = json.loads((ROOT / "experiments" / input_run_id / "manifest.json").read_text())
        prior = [json.loads((ROOT / "experiments" / input_run_id / f"{cid}.json").read_text())
                 for cid in source_manifest["case_ids"]]
    cases_path = ROOT / "experiments/registry.json"
    registry = json.loads(cases_path.read_text())
    start = max(int(c["case_id"][2:]) for c in registry["cases"] if re.fullmatch(r"C-\d+", c["case_id"])) + 1
    configs = [("llm-guard", "C-011", "inj_instruction", "s1_explicit", LLMGuardDriver, "allow"),
               ("nemo-guardrails", "C-025", "act_approval_forged", "s2_artifact_based", NemoDriver, "proceed")]
    manifest = {"run_id": run_id, "created_utc": datetime.now(timezone.utc).isoformat(),
                "framework": fingerprint(ROOT, ["jevsec/analysis/phase4.py", "jevsec/analysis/native_e2e.py",
                                                 "jevsec/act/runner.py", "jevsec/analysis/impact.py"]),
                "scope": "native_consumer_with_jev_substitute", "judge": "jev-1.13.0",
                "generator": "qwen3-32b_or_frozen_template", "trials_per_side": trials,
                "schedule_seed": 20261001,
                "python": sys.version, "targets": {}}
    if input_run_id:
        manifest["exact_input_replay_of"] = input_run_id
    save(out / "manifest.json", manifest)
    deps = subprocess.check_output([sys.executable, "-m", "pip", "freeze", "--exclude-editable"], text=True)
    _atomic_text(out / "requirements.lock.txt", deps)
    results = []
    # Explicit fixed model; environment may not silently select a different one.
    judge = JevAPIJudge(model="jev-1.13.0")
    for offset, (repo, parent, strategy, visibility, driver_cls, allowed) in enumerate(configs):
        surface = next(s for s in SURFACES if s["repo"] == repo)
        case = {"case_id": f"C-{start + offset:03d}", "parent_case_id": parent, "phase4_run_id": run_id,
                "repo": repo, "surface_id": surface["surface_id"], "surface_type": "choice",
                "source_type": surface["source_type"], "location": surface["injection_location"],
                "strategy": strategy, "visibility": visibility, "dimension": "instructional_influence"
                if strategy == "inj_instruction" else "metadata_manipulation",
                "original_context": surface["base_context"], "modified_context": None,
                "semantic_preservation": "not_preserved" if strategy == "inj_instruction" else "partially_preserved",
                "annotation_status": "provisional", "execution_scope": "native_consumer_with_jev_substitute"}
        if prior:
            source_case = next(r["case"] for r in prior if r["case"]["repo"] == repo)
            case.update({"parent_case_id": source_case["case_id"], "replication_of": source_case["case_id"],
                         "case_kind": "exact_input_replication"})
        reserved = _registry_entry(case, "failed", None, None, False, "incomplete_phase4_attempt")
        reserved.update({"phase4_run_id": run_id, "parent_case_id": parent,
                         "execution_scope": case["execution_scope"],
                         "detail_path": str(out.relative_to(ROOT) / f"{case['case_id']}.json")})
        reserved["parent_case_id"] = case["parent_case_id"]
        if prior:
            reserved.update({"replication_of": case["replication_of"], "case_kind": "exact_input_replication"})
        _registry_update(case, reserved)
        runs = {"original": [], "modified": []}
        result = {"case": case, "status": "failed", "runs": runs}
        try:
            if prior:
                case["original_context"] = source_case["original_context"]
                tr = {"original_context": source_case["original_context"],
                      "modified_context": source_case["modified_context"], "error": None,
                      "strategy": strategy, "dimension": case["dimension"], "visibility": case["visibility"]}
            else:
                tr = transform(case["original_context"], strategy, use_llm=True)
            case["modified_context"] = tr["modified_context"]
            save(out / "inputs" / f"{case['case_id']}.json", {"case": case, "generator_result": tr,
                 "provenance": "exact_saved_input_replication" if prior else "fresh_followup_variant_not_historical_recovery"})
            if tr["error"] or not tr["modified_context"]:
                raise RuntimeError(tr["error"] or "empty transform")
            repo_dir = ROOT / "targets/_census" / repo
            files = (["llm_guard/evaluate.py", "llm_guard/input_scanners/base.py", "llm_guard/util.py"]
                     if repo == "llm-guard" else ["nemoguardrails/guardrails/iorails.py",
                     "nemoguardrails/guardrails/rails_manager.py", "nemoguardrails/library/self_check/input_check/actions.py"])
            manifest["targets"][repo] = fingerprint(repo_dir, files)
            if manifest["targets"][repo]["dirty"]:
                raise RuntimeError("target checkout is dirty; unmodified-native provenance unverified")
            save(out / "manifest.json", manifest)
            driver = driver_cls(repo_dir, surface)
            schedule = [side for side in ("original", "modified") for _ in range(trials)]
            random.Random(20261001 + offset).shuffle(schedule)
            result["schedule"] = schedule
            for side in schedule:
                run = driver.run(case[f"{side}_context"], judge)
                run["timestamp_utc"] = datetime.now(timezone.utc).isoformat()
                runs[side].append(run)
                save(out / f"{case['case_id']}.json", result)
                print(case["case_id"], side, len(runs[side]), run["judge_calls"][0]["result"]["decision"], run["status"], flush=True)
            diff = assess_runs(runs)
            result["diff"] = diff
            result["status"] = "executed" if diff["before_stable"] and diff["after_stable"] else "unstable"
            cf = counterfactual(driver, case["original_context"], case["modified_context"], "block", allowed, runs, diff)
            result["counterfactual"] = cf
            before = next(r for r in runs["original"] if r["judge_calls"][0]["result"]["decision"] == diff["majority_before"])
            after = next(r for r in runs["modified"] if r["judge_calls"][0]["result"]["decision"] == diff["majority_after"])
            base_actions = {(a.get("action"), a.get("cmd")) for a in before["audit"]}
            after_actions = {(a.get("action"), a.get("cmd")) for a in after["audit"]}
            div = {"control_flow_diverged": bool(diff["behavioral_divergence"]),
                   "gained_actions": sorted(map(str, after_actions - base_actions)),
                   "lost_actions": sorted(map(str, base_actions - after_actions))}
            result["automatic_classification"] = classify_divergence(
                diff["flip"], diff["majority_after"] == allowed, div, security_control=True)
            result["human_review"] = {"status": "pending", "category": None, "security_impact": None,
                                      "required_oracle": "policy legitimacy + input trust boundary + independent annotations"}
            levels = ["L1", "L2", "L3"]
            if cf["causal_confirmation"]:
                levels.append("C")
            result["evidence"] = {"evidence_levels": levels,
                "evidence_items": ["complete per-trial API results and target-built specs", "pinned native consumer branches",
                                   "live native execution and inert dependency audit", "2x2 fixed-decision intervention"]}
            reserved.update({"status": result["status"], "decision_before": diff["majority_before"],
                             "decision_after": diff["majority_after"], "divergence": diff["flip"], "failure_reason": None})
        except Exception as exc:
            result["status"] = "failed"
            result["failure_reason"] = f"{type(exc).__name__}: {exc}"
            reserved["failure_reason"] = result["failure_reason"][:300]
            print(case["case_id"], "FAILED", result["failure_reason"], flush=True)
        save(out / f"{case['case_id']}.json", result)
        _registry_update(case, reserved)
        results.append(result)
        report(out, results)
    manifest["completed_utc"] = datetime.now(timezone.utc).isoformat()
    manifest["case_ids"] = [r["case"]["case_id"] for r in results]
    save(out / "manifest.json", manifest)
    return 1 if any(r["status"] == "failed" for r in results) else 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--run-id", required=True)
    p.add_argument("--trials", type=int, default=5)
    p.add_argument("--input-run-id", help="replay EXACT saved contexts; never call the generator")
    args = p.parse_args()
    raise SystemExit(main(args.run_id, args.trials, args.input_run_id))
