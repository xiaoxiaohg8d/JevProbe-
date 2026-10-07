"""Stage 5A — End-to-End Behavioral Validation.

Two REAL executions of the target: original external source vs transformed
source. The judgment path must run live — the decision is computed by a real
backend wired through the target's judgment entry point. Overriding the final
decision is FORBIDDEN here (that is Stage 5B's counterfactual intervention).
Only the dangerous sink itself (audit-mode) and external dependencies may be
mocked/stubbed.
"""
from __future__ import annotations

import copy
import importlib
import sys
from pathlib import Path

from .impact import _action_names


def e2e_run(target_dir: Path, entry_module: str, request_file: Path,
            judge_backend, source_text: str | None = None) -> dict:
    """One real target execution with the live judge backend wired in.

    source_text: if given, the request file is temporarily replaced by it
    (this is the attacker-controlled channel, not a decision override).
    """
    sys.path.insert(0, str(target_dir))
    judge_client = importlib.import_module("judge_client")
    recorder: list[str] = []
    real = judge_client.judge

    def observing_judge(spec):
        decision = judge_backend(spec)  # real computation from the spec
        recorder.append(decision)
        return decision

    backup = None
    try:
        if source_text is not None:
            backup = request_file.read_text(encoding="utf-8")
            request_file.write_text(source_text, encoding="utf-8")
        judge_client.judge = observing_judge
        from .probes import HarnessEnv
        from .reachability import load_target
        with HarnessEnv(target_dir):
            target = load_target(target_dir, entry_module)
            audit: list = []
            status = target.run(str(request_file), audit)
    finally:
        judge_client.judge = real
        if backup is not None:
            request_file.write_text(backup, encoding="utf-8")
        sys.path.remove(str(target_dir))
    return {"status": status, "audit": audit, "decisions": recorder}


def capture_spec(target_dir: Path, entry_module: str, request_file: Path,
                 source_text: str | None = None) -> dict | None:
    """Re-run the app (capture-only judgment) and return the REAL spec it builds.

    Stage 4 must score specs captured this way: replacing fields of a captured
    spec by hand silently drops channels (the v2->v3 regression that 5A caught).
    """
    sys.path.insert(0, str(target_dir))
    judge_client = importlib.import_module("judge_client")
    captured: list[dict] = []
    real = judge_client.judge
    backup = None
    try:
        if source_text is not None:
            backup = request_file.read_text(encoding="utf-8")
            request_file.write_text(source_text, encoding="utf-8")
        judge_client.judge = lambda spec: (captured.append(copy.deepcopy(spec)) or "deny")
        from .probes import HarnessEnv
        from .reachability import load_target
        with HarnessEnv(target_dir):
            target = load_target(target_dir, entry_module)
            target.run(str(request_file), [])
    finally:
        judge_client.judge = real
        if backup is not None:
            request_file.write_text(backup, encoding="utf-8")
        sys.path.remove(str(target_dir))
    return captured[0] if captured else None


def _norm(audit: list[dict]) -> list[str]:
    return sorted(f"{a.get('action')}|{a.get('cmd', '')}" for a in audit)


def e2e_validation(target_dir: Path, entry_module: str, request_file: Path,
                   judge_backend, transformed: dict[str, str]) -> dict:
    """Baseline vs per-strategy transformed sources, full real execution.

    Returns {"baseline": ..., "results": [per-strategy divergence records]}.
    """
    base = e2e_run(target_dir, entry_module, request_file, judge_backend)
    base_actions = _norm(base["audit"])
    results = []
    for name, text in transformed.items():
        t = e2e_run(target_dir, entry_module, request_file, judge_backend,
                    source_text=text)
        t_actions = _norm(t["audit"])
        gained = sorted(set(t_actions) - set(base_actions))
        lost = sorted(set(base_actions) - set(t_actions))
        decision_div = t["decisions"] != base["decisions"]
        behavior_div = bool(gained or lost or t["status"] != base["status"])
        gained_names = {g.split("|", 1)[0] for g in gained}
        security_relevant = bool(gained_names & {"EXECUTE", "WRITE", "SEND", "DELETE", "DEPLOY"})
        results.append({
            "strategy": name,
            "baseline": {"status": base["status"], "decisions": base["decisions"],
                         "actions": base_actions},
            "transformed": {"status": t["status"], "decisions": t["decisions"],
                            "actions": t_actions},
            "decision_divergence": decision_div,
            "behavioral_divergence": behavior_div,
            "security_relevant_divergence": security_relevant,
            "gained_actions": gained,
            "lost_actions": lost,
            "evidence": {"audit_baseline": base["audit"], "audit_transformed": t["audit"]},
        })
    return {"baseline": base, "results": results}
