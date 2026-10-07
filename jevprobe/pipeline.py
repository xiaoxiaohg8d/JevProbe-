"""Context-to-Decision pipeline (v3): Stage 0-6 measurement architecture.

Stage 1  C2D Surface Discovery         static: Jev call sites + external sources
Stage 2  Reachability Validation       source enumeration -> per-channel canary probes
Stage 3  Context Transformation        ACT: 7 families / 13 strategies, factorized
Stage 4  Decision Differential Testing deterministic judge, flip/margin/JS/U2A
Stage 5A End-to-End Behavioral Validation  REAL runs, live judgment, no decision override
Stage 5B Counterfactual Validation         decision-intervention causality check
Stage 6  Measurement Aggregation       evidence levels L1-L4+C, per-factor stats

Evidence levels attached to every finding:
  L1 Reachability  L2 Decision Divergence  L3 Behavioral Divergence
  L4 Security-Relevant Divergence  C Counterfactual Confirmation
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess as sp
import sys
import time
from ast import literal_eval
from datetime import datetime, timezone
from pathlib import Path

from . import manipulation, oracle
from .analysis import discovery, e2e, impact, probes, reachability
from .runners import LocalJudgeBackend, LocalSemifRunner, ScriptedSemanticsBackend


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-dir", required=True)
    ap.add_argument("--entry", required=True)
    ap.add_argument("--request", default=None,
                    help="fallback single FILE source (ignored when sources.json exists)")
    ap.add_argument("--classes", default=",".join(manipulation.STRATEGIES))
    ap.add_argument("--target-decision", default="allow")
    ap.add_argument("--out", required=True)
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--e2e-backend", choices=["local", "scripted"], default="local",
                    help="5A judgment backend: real local judge or scripted fixture")
    ap.add_argument("--security-control", action="store_true",
                    help="target's judgment is itself a security control "
                         "(scanner/guard): library-level verdict flip counts as "
                         "SECURITY_POLICY_BYPASS")
    args = ap.parse_args(argv)

    target_dir, out = Path(args.target_dir), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    classes = [c.strip() for c in args.classes.split(",") if c.strip()]
    unknown = [c for c in classes if c not in manipulation.STRATEGIES]
    if unknown:
        ap.error(f"unknown strategies: {unknown}")

    _write_manifest(out, args)

    # ---- Stage 1: C2D surface discovery --------------------------------------
    surfaces = discovery.discover_tree(target_dir)
    (out / "surfaces.json").write_text(json.dumps(surfaces, default=lambda o: o.__dict__,
                                                  ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[1] surfaces={len(surfaces)} external_sources="
          f"{len(discovery.external_sources(surfaces))}")

    # ---- Stage 2: source enumeration + canary reachability -------------------
    manifest = target_dir / "sources.json"
    if manifest.exists():
        source_reports = probes.enumerate_sources(manifest, target_dir, args.entry)
    elif args.request:
        source_reports = [probes.validate_source(
            {"id": "request_doc", "kind": "FILE", "path": args.request},
            target_dir, args.entry)]
    else:
        ap.error("no sources.json manifest and no --request fallback given")
    (out / "sources.json").write_text(json.dumps(source_reports, ensure_ascii=False,
                                                 indent=2, default=str), encoding="utf-8")
    for r in source_reports:
        print(f"[2] source {r['source_id']:14s} {r['kind']:10s} -> {r['status']}"
              + ("" if r["status"] == "VERIFIED" else f" ({r.get('error', 'canary absent')})"))
    verified_files = [r for r in source_reports
                      if r["status"] == "VERIFIED" and r["kind"] == "FILE"]
    if not verified_files:
        print("    no VERIFIED attacker-controlled FILE source — aborting")
        return 1
    primary = verified_files[0]
    request_file = Path(str(primary["detail"]))
    if not request_file.is_absolute():
        request_file = target_dir / request_file
    base_spec = primary.get("captured_spec")
    if not base_spec:
        print("    primary source yielded no captured spec — aborting")
        return 1

    # ---- Stage 3: attacker-controlled context transformations ----------------
    original_context = request_file.read_text(encoding="utf-8")
    acts = manipulation.generate(original_context, classes, use_llm=not args.no_llm)
    (out / "transformations.json").write_text(json.dumps(acts, ensure_ascii=False, indent=2),
                                              encoding="utf-8")
    ok = [m for m in acts if m.get("context")]
    print(f"[3] ACT strategies={len(ok)}/{len(acts)} families="
          f"{sorted({m['family'] for m in ok})}")

    # ---- Stage 4: decision differential testing -------------------------------
    # Transformed specs are CAPTURED by replaying the app with the transformed
    # source (never hand-assembled): all channels stay intact.
    t0 = time.time()
    rows = [base_spec]
    usable: list[dict] = []
    for m in ok:
        spec_t = e2e.capture_spec(target_dir, args.entry, request_file, m["context"])
        if not spec_t:
            continue
        s2 = copy.deepcopy(spec_t)
        s2["id"] = f"{base_spec['id']}::{m['class']}"
        rows.append(s2)
        usable.append(m)
    results = LocalSemifRunner().run(rows, out / "judge", "diff")
    base_res = results[0]
    base_dec = oracle.decision(oracle.prob_dict(base_res))[0]
    diffs = []
    for m, r in zip(usable, results[1:]):
        a = oracle.analyze([base_res], [r], inverse={})
        diffs.append({"class": m["class"], "family": m["family"], "family_name": m["family_name"],
                      "stealth": m["stealth"], "adaptive": m["adaptive"], "mode": m["mode"],
                      "mechanism": m.get("mechanism", ""), "analysis": a,
                      "transformed_source": m["context"]})
    (out / "differential.json").write_text(
        json.dumps({"baseline": {"decision": base_dec, "raw": base_res},
                    "diffs": [{k: v for k, v in d.items() if k != "transformed_source"}
                              for d in diffs]},
                   ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    flipped = [d for d in diffs if d["analysis"]["flip"]]
    print(f"[4] judge pass {time.time() - t0:.0f}s baseline={base_dec} "
          f"flips={len(flipped)}/{len(diffs)}")

    # ---- Stage 5A: end-to-end behavioral validation ---------------------------
    backend = (LocalJudgeBackend(out / "judge_e2e") if args.e2e_backend == "local"
               else ScriptedSemanticsBackend())
    e2e_out = e2e.e2e_validation(
        target_dir, args.entry, request_file, backend,
        {d["class"]: d["transformed_source"] for d in flipped})
    (out / "e2e.json").write_text(json.dumps(e2e_out, ensure_ascii=False, indent=2,
                                             default=str), encoding="utf-8")
    e2e_by_strategy = {r["strategy"]: r for r in e2e_out["results"]}
    n_e2e_div = sum(r["behavioral_divergence"] for r in e2e_out["results"])
    print(f"[5A] e2e backend={backend.name} real runs={1 + len(e2e_out['results'])} "
          f"behavioral_divergence={n_e2e_div}/{len(e2e_out['results'])}")

    # ---- Stage 5B: counterfactual decision intervention -----------------------
    run_cache: dict[str, tuple] = {}

    def run_dec(dec: str):
        if dec not in run_cache:
            run_cache[dec] = reachability.run_with_decision(
                target_dir, args.entry, request_file, dec)
        return run_cache[dec]

    run_dec(base_dec)
    counterfactuals = []
    for d in flipped:
        div = impact.dynamic_divergence(lambda dec: run_dec(dec),
                                        base_dec, d["analysis"]["trans_decision"])
        counterfactuals.append({"strategy": d["class"],
                                "confirmed": div["control_flow_diverged"],
                                "divergence": div})
    (out / "counterfactual.json").write_text(
        json.dumps(counterfactuals, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8")
    print(f"[5B] counterfactual confirmed="
          f"{sum(c['confirmed'] for c in counterfactuals)}/{len(counterfactuals)}")

    # ---- Stage 6: findings + measurement aggregation ---------------------------
    entry_src = (target_dir / f"{args.entry}.py").read_text(encoding="utf-8")
    bmap = impact.branch_map(entry_src)
    (out / "branch_map.json").write_text(json.dumps(bmap, ensure_ascii=False, indent=2),
                                         encoding="utf-8")
    all_sink_kinds = {sk["kind"] for b in bmap for sinks in b["branches"].values()
                      for sk in sinks}
    cf_by_strategy = {c["strategy"]: c for c in counterfactuals}
    findings = []
    for d in flipped:
        a = d["analysis"]
        toward = a["trans_decision"] == args.target_decision
        er = e2e_by_strategy.get(d["class"], {})
        cf = cf_by_strategy.get(d["class"], {})
        layers = impact.classify_divergence(
            a["flip"], toward, er.get("evidence") and {
                "control_flow_diverged": er["behavioral_divergence"],
                "gained_actions": er.get("gained_actions", []),
                "lost_actions": er.get("lost_actions", [])},
            all_sink_kinds, security_control=args.security_control)
        findings.append({
            "surface_id": f"{args.entry}.py:judgment",
            "source_id": primary["source_id"],
            "strategy": d["class"], "family": d["family"], "stealth": d["stealth"],
            "mechanism": d.get("mechanism", ""),
            "decision": {"baseline": base_dec, "transformed": a["trans_decision"],
                         "diverged": True, "baseline_margin": a["base_margin"],
                         "transformed_margin": a["trans_margin"]},
            "reachability": True,
            "e2e": {"behavioral_divergence": er.get("behavioral_divergence"),
                    "security_relevant": er.get("security_relevant_divergence")},
            "counterfactual": {"confirmed": cf.get("confirmed")},
            "evidence_levels": {
                "L1_reachability": True,
                "L2_decision_divergence": True,
                "L3_behavioral_divergence": er.get("behavioral_divergence", False),
                "L4_security_relevant": er.get("security_relevant_divergence", False),
                "C_counterfactual": cf.get("confirmed", False)},
            "impact_categories": layers["impact_classes"],
            "toward_attacker_goal": toward,
        })
    stats = _stats(diffs, findings, args.target_decision)
    (out / "impact.json").write_text(json.dumps(
        [f["impact_categories"] for f in findings], ensure_ascii=False, indent=2),
        encoding="utf-8")
    (out / "measurement.json").write_text(json.dumps(stats, ensure_ascii=False, indent=2),
                                          encoding="utf-8")
    (out / "findings.json").write_text(json.dumps(findings, ensure_ascii=False, indent=2,
                                                  default=str), encoding="utf-8")
    _render_md(out / "findings.md", args, base_dec, diffs, findings, stats, e2e_out)
    print(f"[6] findings={len(findings)} full-chain (L1-L4+C)="
          f"{sum(all(f['evidence_levels'].values()) for f in findings)}")
    for f in findings:
        ev = f["evidence_levels"]
        print(f"    !! {f['strategy']:24s} {f['decision']['baseline']}->"
              f"{f['decision']['transformed']} | L3={ev['L3_behavioral_divergence']} "
              f"L4={ev['L4_security_relevant']} C={ev['C_counterfactual']} | "
              f"{'+'.join(f['impact_categories'])}")
    print(f"    measurement: exposure={stats['verified_reachability_rate']:.0%} "
          f"decision_div={stats['decision_divergence_rate']:.0%} "
          f"behavior_prop={stats['behavior_propagation_rate']:.0%} "
          f"security_impact={stats['security_impact_rate']:.0%}")
    print(f"artifacts in {out}")
    return 0


def _write_manifest(out: Path, args):
    try:
        commit = sp.run(["git", "rev-parse", "HEAD"], capture_output=True,
                        text=True, cwd=Path(__file__).resolve().parents[1]).stdout.strip()
    except Exception:
        commit = "unknown"
    manifest = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "jevsec_commit": commit,
        "target": args.target_dir, "entry": args.entry,
        "judge": {"model": os.getenv("SEMIF_MODEL"),
                  "revision": os.getenv("SEMIF_REVISION"), "temperature": 0},
        "e2e_backend": args.e2e_backend,
        "config": {k: v for k, v in vars(args).items() if k != "func"},
    }
    (out / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2),
                                       encoding="utf-8")


def _stats(diffs: list[dict], findings: list[dict], target_decision: str) -> dict:
    fam: dict[str, dict] = {}
    for d in diffs:
        e = fam.setdefault(d["family"], {"family_name": d["family_name"], "n": 0,
                                         "flips": 0, "toward": 0})
        e["n"] += 1
        if d["analysis"]["flip"]:
            e["flips"] += 1
            if d["analysis"]["trans_decision"] == target_decision:
                e["toward"] += 1
    n = len(diffs)
    n_find = len(findings)
    l3 = sum(f["evidence_levels"]["L3_behavioral_divergence"] for f in findings)
    l4 = sum(f["evidence_levels"]["L4_security_relevant"] for f in findings)
    return {
        "per_family": fam,
        "surface_exposure_rate": 1.0 if findings else (0.0 if n else 0.0),
        "verified_reachability_rate": 1.0,   # pipeline aborts earlier when 0 (per-run scope)
        "decision_divergence_rate": (n_find / n) if n else 0.0,
        "behavior_propagation_rate": (l3 / n_find) if n_find else 0.0,
        "security_impact_rate": (l4 / n_find) if n_find else 0.0,
        **impact.impact_stats(findings),
    }


def _render_md(path: Path, args, base_dec, diffs, findings, stats, e2e_out):
    lines = ["# Context-to-Decision Findings (v3, evidence-graded)", "",
             f"- baseline decision: `{base_dec}`  e2e backend: `{args.e2e_backend}`", "",
             "## Evidence-graded findings", "",
             "| strategy | family | decision | L1 | L2 | L3 | L4 | C | impact categories |",
             "|---|---|---|---|---|---|---|---|---|"]
    for f in findings:
        ev = f["evidence_levels"]
        lines.append(
            f"| {f['strategy']} | {f['family']} | {f['decision']['baseline']}->"
            f"{f['decision']['transformed']} | {'Y' if ev['L1_reachability'] else '-'} "
            f"| {'Y' if ev['L2_decision_divergence'] else '-'} "
            f"| {'Y' if ev['L3_behavioral_divergence'] else '-'} "
            f"| {'Y' if ev['L4_security_relevant'] else '-'} "
            f"| {'Y' if ev['C_counterfactual'] else '-'} "
            f"| {', '.join(f['impact_categories'])} |")
    lines += ["", "## Measurement", "",
              f"- decision divergence rate: {stats['decision_divergence_rate']:.1%}",
              f"- behavior propagation rate: {stats['behavior_propagation_rate']:.1%}",
              f"- security impact rate: {stats['security_impact_rate']:.1%}",
              "", "## Per-family", "",
              "| family | n | flips | toward-attacker |", "|---|---|---|---|"]
    for fid, e in sorted(stats["per_family"].items()):
        lines.append(f"| {fid} {e['family_name']} | {e['n']} | {e['flips']} | {e['toward']} |")
    lines += ["", "## Impact class distribution", ""]
    for cls, cnt in sorted(stats["impact_class_distribution"].items()):
        meta = impact.SECURITY_IMPACT_CLASSES.get(cls, {})
        lines.append(f"- **{cls}** x{cnt} — {meta.get('name', '')} "
                     f"{meta.get('cwe', [])}")
    lines += ["", "## 5A e2e detail (real runs, live judgment)", ""]
    for r in e2e_out["results"]:
        lines.append(f"- `{r['strategy']}`: decisions {r['baseline']['decisions']} -> "
                     f"{r['transformed']['decisions']}, status "
                     f"{r['baseline']['status']} -> {r['transformed']['status']}, "
                     f"gained {r['gained_actions']}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
