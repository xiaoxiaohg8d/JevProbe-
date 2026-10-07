"""Stage 2 — Reachability Validation via dynamic canary.

Injects a unique canary token into the candidate EXTERNAL source (the request
document the target reads), monkeypatches the target's judgment backend to
capture the context it actually receives, runs the target flow, and reports
whether the canary reached the Jev input. Restores file and patch on exit.
"""
from __future__ import annotations

import copy
import importlib
import importlib.util
import secrets
import sys
from pathlib import Path


def load_target(target_dir: Path, entry_module: str):
    """Fresh-exec target module; binds judge_client.judge's CURRENT value."""
    sys.path.insert(0, str(target_dir))
    sys.modules.pop(entry_module, None)
    spec = importlib.util.spec_from_file_location(
        entry_module, target_dir / f"{entry_module}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_canary() -> str:
    return f"CANARY-{secrets.token_hex(6).upper()}"


def probe_file_source(target_dir: Path, entry_module: str, request_file: Path) -> dict:
    """Canary the FILE source; verify it appears in the captured judgment context."""
    sys.path.insert(0, str(target_dir))
    judge_client = importlib.import_module("judge_client")

    canary = make_canary()
    original = request_file.read_text(encoding="utf-8")
    captured: list[dict] = []
    real_judge = judge_client.judge

    def capturing_judge(spec):
        captured.append(copy.deepcopy(spec))
        try:
            return real_judge(spec)
        except NotImplementedError:
            return "deny"  # backend not configured in harness mode

    report = {"source": str(request_file), "canary": canary}
    try:
        request_file.write_text(original + f"\n\n{canary}\n", encoding="utf-8")
        judge_client.judge = capturing_judge
        target = load_target(target_dir, entry_module)
        audit: list = []
        result = target.run(str(request_file), audit)
        states = [c.get("state", "") for c in captured]
        report.update({
            "judgment_invocations": len(captured),
            "canary_reached": any(canary in s for s in states),
            "run_result": result,
            "audit": audit,
            "captured_spec": captured[0] if captured else None,
        })
    finally:
        judge_client.judge = real_judge
        request_file.write_text(original, encoding="utf-8")
        sys.path.remove(str(target_dir))
    return report


def run_with_decision(target_dir: Path, entry_module: str, request_file: Path,
                      decision: str) -> tuple[str, list]:
    """Execute the target with the judgment backend pinned to `decision`."""
    sys.path.insert(0, str(target_dir))
    judge_client = importlib.import_module("judge_client")
    real_judge = judge_client.judge
    judge_client.judge = lambda spec: decision
    try:
        from .probes import HarnessEnv
        with HarnessEnv(target_dir):
            target = load_target(target_dir, entry_module)
            audit: list = []
            status = target.run(str(request_file), audit)
    finally:
        judge_client.judge = real_judge
        sys.path.remove(str(target_dir))
    return status, audit
