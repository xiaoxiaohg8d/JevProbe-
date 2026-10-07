"""Runner: judge backends + repeatability protocol + single-case execution.

Judges (S11 v1.4 double-track):
  JevAPIJudge      — main track: TypeSafe Jev (jev-1.13.0) via zhizengzeng;
                     choice question built from the surface's real contract;
                     returns decision + FULL probabilities (signal=probability).
  RealFunctionJudge — control track: the real project function, unmodified
                     (deterministic surfaces; signal=none).

Repeatability (frozen): original >=3 AND modified >=3 runs (default 5+5).
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from pathlib import Path

from ..schema import metrics as M
from . import differential as D
from .record import ContextTransformationRecord, make_transformation_id


class JevAPIJudge:
    signal = "probability"

    def __init__(self, model: str | None = None, *, store=None, scopes=None,
                 context=None, retries=1, opener=None):
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).resolve().parents[2] / ".env")
        self.model = model or os.getenv("JEV_MODEL_FIXED", "jev-1.13.0")
        self.url = os.getenv("JEV_BASE_URL", "https://api.zhizengzeng.com/v1/systemone")
        self.key = os.environ["JEV_API_KEY"]
        self.store, self.scopes = store, scopes
        self.context, self.retries, self.opener = context or {}, retries, opener

    @property
    def name(self) -> str:
        return f"{self.model}@zhizengzeng"

    def judge(self, spec: dict) -> dict:
        from ..automation.store import BudgetExceeded
        from ..automation.transport import json_request
        import math
        if self.store is None or not self.scopes:
            raise BudgetExceeded("paid inference requires an explicit configured ledger; use jevsec.automation")
        required = {"batch_id", "repo_id", "callsite_id", "case_id", "trial_id"}
        if not required <= self.context.keys():
            raise ValueError("missing request lineage")
        if not isinstance(spec.get("state"), str) or not isinstance(spec.get("question"), str):
            raise ValueError("invalid choice request")
        criteria = {o["id"]: o["description"] for o in spec["options"]}
        if len(criteria) < 2 or len(criteria) != len(spec["options"]):
            raise ValueError("choice options must have unique IDs")
        payload = {"state": spec["state"], "model": self.model,
                   "questions": {"decision": {"type": "choice",
                                              "instructions": spec["question"],
                                              "criteria": criteria}}}
        def validate(response):
            answer = response["answers"]["decision"]
            if answer["choice"] not in criteria:
                raise ValueError("Jev returned an out-of-contract choice")
            probabilities = answer.get("probabilities")
            if probabilities:
                if set(probabilities) != set(criteria) or any(
                        not isinstance(v, (int, float)) or isinstance(v, bool) or
                        not math.isfinite(v) or not 0 <= v <= 1 for v in probabilities.values()):
                    raise ValueError("invalid probability support/value")
        response, attempt = json_request(
            self.store, self.scopes, {**self.context, "model": self.model, "provider": "jev"},
            self.url, payload, headers={"Authorization": f"Bearer {self.key}",
                                       "Content-Type": "application/json"},
            retries=self.retries, timeout=60, opener=self.opener, validate=validate)
        ans = response["answers"]["decision"]
        return {"decision": ans["choice"], "probabilities": ans.get("probabilities") or {},
                "confidence": ans.get("confidence"), "native_answer": ans,
                "attempt_id": attempt, "usage": response.get("usage"),
                "returned_model": response.get("model"), "request_id": response.get("id")}


class RealFunctionJudge:
    """Unmodified real project function; spec carries the context to inject."""
    signal = "none"

    def __init__(self, name: str, fn, extract):
        self._name, self.fn, self._extract = name, fn, extract

    @property
    def name(self) -> str:
        return self._name

    def judge(self, spec: dict) -> dict:
        out = self._extract(self.fn, spec)
        return {"decision": str(out), "probabilities": None, "confidence": None}


def aggregate(results: list[dict]) -> tuple[list, dict | None]:
    decisions = [r["decision"] for r in results]
    probs = [r["probabilities"] for r in results if r.get("probabilities")]
    mean_probs = None
    if probs and len(probs) == len(results):
        keys = probs[0].keys()
        if any(p.keys() != keys for p in probs):
            raise ValueError("inconsistent probability support; cannot impute missing options as zero")
        mean_probs = {k: round(sum(p[k] for p in probs) / len(probs), 4)
                      for k in keys}
    return decisions, mean_probs


def run_case(case: dict, judge, trials: int = 5) -> tuple[dict, dict]:
    """Execute one case under the repeatability protocol.

    case: {case_id, repo, surface_id, surface_type, source_type, location,
           dimension, strategy, visibility, semantic_preservation, attack_goal,
           original_context, modified_context, spec_factory, judge_config_hint}
    Returns (record_dict, registry_entry). Never raises: failures are recorded.
    """
    if trials < 3:
        raise ValueError("frozen repeatability protocol requires >=3 trials per side")
    t0 = time.time()
    before_raw, after_raw = [], []
    try:
        for _ in range(trials):
            before_raw.append(judge.judge(case["spec_factory"](case["original_context"])))
        for _ in range(trials):
            after_raw.append(judge.judge(case["spec_factory"](case["modified_context"])))
    except Exception as e:
        entry = _registry_entry(case, status="failed", decision_before=None,
                                decision_after=None, divergence=False,
                                failure_reason=str(e)[:160])
        entry["raw_judge_results"] = {"original": before_raw, "modified": after_raw}
        return {}, entry

    try:
        bd, bp = aggregate(before_raw)
        ad, ap = aggregate(after_raw)
        diff = D.analyze(case["surface_type"], bd, ad, bp, ap)
    except Exception as e:
        entry = _registry_entry(case, status="failed", decision_before=None,
                                decision_after=None, divergence=False,
                                failure_reason=str(e)[:160])
        entry["raw_judge_results"] = {"original": before_raw, "modified": after_raw}
        return {}, entry
    stable = diff.get("before_stable", True) and diff.get("after_stable", True)
    status = "executed" if stable else "unstable"

    rep = {"original_trials": len(before_raw), "modified_trials": len(after_raw),
           "aggregation": "majority",
           "before_distribution": _dist(bd), "after_distribution": _dist(ad),
           "before_majority": diff["majority_before"],
           "after_majority": diff["majority_after"],
           "flip_consistency": round(diff["flip_consistency"], 3)}

    record = ContextTransformationRecord(
        transformation_id=make_transformation_id(case["repo"], case["surface_id"],
                                                 case["strategy"],
                                                 case["original_context"]),
        surface_id=case["surface_id"], surface_type=case["surface_type"],
        source_type=case["source_type"], injection_location=case["location"],
        dimension=case["dimension"], strategy=case["strategy"],
        visibility=case["visibility"],
        semantic_preservation=case["semantic_preservation"],
        attack_goal=case["attack_goal"],
        original_context=case["original_context"],
        modified_context=case["modified_context"] or "",
        decision_before=diff["majority_before"],
        decision_after=diff["majority_after"],
        decision_signal=({"type": judge.signal,
                          "before": bp, "after": ap} if bp else
                         {"type": "none", "before": None, "after": None}),
        repeatability=rep,
        judge_config=judge.name,
    )
    entry = _registry_entry(case, status=status, decision_before=diff["majority_before"],
                            decision_after=diff["majority_after"],
                            divergence=diff["flip"], failure_reason=None)
    entry["latency_s"] = round(time.time() - t0, 1)
    result = record.to_dict()
    result["case_id"] = case["case_id"]
    result["raw_judge_results"] = {"original": before_raw, "modified": after_raw}
    return result, entry


def _dist(decisions: list) -> dict:
    d: dict = {}
    for x in decisions:
        d[str(x)[:40]] = d.get(str(x)[:40], 0) + 1
    return d


def _registry_entry(case: dict, status: str, decision_before, decision_after,
                    divergence: bool, failure_reason: str | None) -> dict:
    return {"case_id": case["case_id"], "surface_id": case["surface_id"],
            "repo": case["repo"], "source_type": case["source_type"],
            "location": case["location"], "dimension": case["dimension"],
            "strategy": case["strategy"], "visibility": case["visibility"],
            "status": status, "decision_before": decision_before,
            "decision_after": decision_after, "divergence": divergence,
            "failure_reason": failure_reason}
