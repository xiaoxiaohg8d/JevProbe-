"""Offline evidence verification. No model, API, GPU, or target import needed."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from .phase4 import assess_runs, build_tables
from .native_e2e import behavior_signature


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(path: Path):
    manifest = json.loads((path / "manifest.json").read_text())
    results = []
    for filename, expected in manifest["framework"]["files"].items():
        file = path / "framework_sources" / filename
        require(hashlib.sha256(file.read_bytes()).hexdigest() == expected, f"runtime source mismatch: {filename}")
    for case_id in manifest["case_ids"]:
        result = json.loads((path / f"{case_id}.json").read_text())
        case = result["case"]
        inputs = json.loads((path / "inputs" / f"{case_id}.json").read_text())["case"]
        require(case == inputs, f"saved input metadata mismatch: {case_id}")
        if result["status"] == "failed":
            require(bool(result.get("failure_reason")), f"unexplained failure: {case_id}")
            results.append(result)
            continue
        runs = result["runs"]
        for side in ("original", "modified"):
            require(len(runs[side]) == manifest["trials_per_side"] >= 3, f"incomplete trials: {case_id}/{side}")
            for run in runs[side]:
                require(len(run["judge_calls"]) == 1, f"unexpected judgment count: {case_id}")
                call = run["judge_calls"][0]
                require(call["spec"]["state"] == case[f"{side}_context"], f"source/spec mismatch: {case_id}/{side}")
                options = {o["id"] for o in call["spec"]["options"]}
                require(call["result"]["decision"] in options, f"invalid decision: {case_id}")
                require("intervention" not in call["result"], f"fixed decision in live run: {case_id}")
        actual_diff = assess_runs(runs)
        require(actual_diff == result["diff"], f"differential summary mismatch: {case_id}")
        cf = result["counterfactual"]
        cells = cf["cells"]
        allowed = "allow" if case["repo"] == "llm-guard" else "proceed"
        require(set(cells) == {f"{s}|{d}" for s in ("original", "modified") for d in ("block", allowed)},
                f"incomplete factorial intervention: {case_id}")
        signatures = {k: behavior_signature(v) for k, v in cells.items()}
        source_effect = any(signatures[f"original|{d}"] != signatures[f"modified|{d}"] for d in ("block", allowed))
        decision_effect = all(signatures[f"{s}|block"] != signatures[f"{s}|{allowed}"] for s in ("original", "modified"))
        matches = all(behavior_signature(r) == signatures[f"{side}|{r['judge_calls'][0]['result']['decision']}"]
                      for side, values in runs.items() for r in values)
        require((source_effect, decision_effect, matches) == (cf["source_effect_under_fixed_decision"],
                  cf["decision_controls_behavior"], cf["matches_live"]), f"counterfactual summary mismatch: {case_id}")
        require(cf["causal_confirmation"] == bool(actual_diff["flip"] and actual_diff["behavioral_divergence"] and
                  decision_effect and matches and not source_effect), f"causality summary mismatch: {case_id}")
        results.append(result)
    require(build_tables(results) == json.loads((path / "tables.json").read_text()), "table aggregate mismatch")
    checksums = path / "checksums.json"
    if checksums.exists():
        for name, digest in json.loads(checksums.read_text()).items():
            candidate = (path / name).resolve()
            require(candidate.is_relative_to(path.resolve()), "checksum path escapes experiment")
            require(hashlib.sha256(candidate.read_bytes()).hexdigest() == digest, f"artifact mismatch: {name}")
    return {"run_id": manifest["run_id"], "cases_checked": len(results), "status": "verified",
            "scope": "recorded data, runtime sources, inputs, summaries, interventions, and tables; no new inference"}


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("experiment", type=Path)
    print(json.dumps(verify(p.parse_args().experiment), ensure_ascii=False, indent=2))
