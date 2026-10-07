"""Native consumer validation with an explicitly configured Jev backend.

These drivers measure a Jev-substituted integration, not project-default
vulnerability.  Only the judgment provider and external dependency/sink are
adapted; target consumer branches and self-check parsing execute unchanged.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import sys
import types


def fingerprint(repo_dir: Path, files: list[str]) -> dict:
    return {
        "commit": subprocess.check_output(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"], text=True).strip(),
        "files": {name: hashlib.sha256((repo_dir / name).read_bytes()).hexdigest()
                  for name in files},
        "dirty": bool(subprocess.check_output(
            ["git", "-C", str(repo_dir), "status", "--porcelain"], text=True).strip()),
    }


@contextmanager
def _guard_packages(repo_dir: Path):
    """Bypass unused scanner imports; load selected ORIGINAL modules normally.

    Restore sys.modules, including an existing llm_guard installation, on exit.
    This avoids downloading unrelated classifier weights for a consumer test.
    """
    prefix = "llm_guard"
    previous = {k: v for k, v in sys.modules.items()
                if k == prefix or k.startswith(prefix + ".")}
    for k in previous:
        del sys.modules[k]
    try:
        for suffix in ("", ".input_scanners", ".output_scanners"):
            module = types.ModuleType(prefix + suffix)
            module.__path__ = [str(repo_dir / (prefix + suffix).replace(".", "/"))]
            sys.modules[module.__name__] = module
        yield importlib.import_module("llm_guard.evaluate")
    finally:
        for k in list(sys.modules):
            if k == prefix or k.startswith(prefix + "."):
                del sys.modules[k]
        sys.modules.update(previous)


class LLMGuardDriver:
    execution_scope = "native_consumer_with_jev_substitute"

    def __init__(self, repo_dir: Path, surface: dict):
        self.repo_dir, self.surface = repo_dir, surface

    def run(self, context: str, judge) -> dict:
        from ..act.surfaces import spec_factory
        audit, calls = [], []
        surface = self.surface

        class JevScanner:
            def scan(self, prompt):
                spec = spec_factory(surface, prompt)
                result = judge.judge(spec)
                calls.append({"spec": spec, "result": result})
                decision = result["decision"]
                if decision not in {"allow", "block"}:
                    raise ValueError("scanner judge returned an out-of-contract decision")
                # This field is unavailable in decision-only counterfactuals.
                # Native scan_prompt merely stores it; never invent a score.
                risk = (result.get("probabilities") or {}).get("block")
                return prompt, decision == "allow", risk

        class AuditNextScanner:
            def scan(self, prompt):
                audit.append({"action": "NEXT_SCANNER", "cmd": None})
                return prompt, True, 0.0

        with _guard_packages(self.repo_dir) as target:
            sanitized, valid, scores = target.scan_prompt(
                [JevScanner(), AuditNextScanner()], context, fail_fast=True)
        return {"status": "passed" if all(valid.values()) else "blocked",
                "audit": audit, "judge_calls": calls,
                "native_result": {"valid": valid, "scores": scores,
                                  "sanitized_sha256": hashlib.sha256(sanitized.encode()).hexdigest()}}


class NemoDriver:
    execution_scope = "native_consumer_with_jev_substitute"

    def __init__(self, repo_dir: Path, surface: dict):
        self.repo_dir, self.surface = repo_dir, surface

    def run(self, context: str, judge) -> dict:
        return asyncio.run(self._run(context, judge))

    async def _run(self, context: str, judge) -> dict:
        from nemoguardrails import Guardrails, RailsConfig
        from nemoguardrails.guardrails import iorails as target_module
        from nemoguardrails.testing.fake_model import FakeLLMModel
        from nemoguardrails.types import LLMResponse, LLMResponseChunk
        from ..act.surfaces import spec_factory

        if not Path(target_module.__file__).resolve().is_relative_to(self.repo_dir.resolve()):
            raise RuntimeError("Nemo installation does not match the pinned target checkout")
        audit, calls = [], []
        surface = self.surface

        class JevModel:
            model_name = "jev-1.13.0"
            provider_name = "jevsec-configured-adapter"
            provider_url = None

            async def generate_async(self, prompt, *, stop=None, **kwargs):
                # Use the ACTUAL prompt built by the target task manager.
                if not isinstance(prompt, str):
                    raise TypeError("expected the configured text self-check prompt")
                spec = spec_factory(surface, prompt)
                result = await asyncio.to_thread(judge.judge, spec)
                calls.append({"spec": spec, "result": result})
                if result["decision"] not in {"block", "proceed"}:
                    raise ValueError("rail judge returned an out-of-contract decision")
                # Native self_check_input parses yes=unsafe, no=safe.
                return LLMResponse(content="yes" if result["decision"] == "block" else "no")

            async def stream_async(self, prompt, *, stop=None, **kwargs):
                response = await self.generate_async(prompt, stop=stop, **kwargs)
                yield LLMResponseChunk(delta_content=response.content)

        config = RailsConfig.from_content(yaml_content="""
models:
  - type: main
    engine: openai
    model: fixture-main
    parameters:
      api_key: fixture-only
      base_url: http://127.0.0.1:1/v1
  - type: self_check_input
    engine: openai
    model: fixture-self-check
    parameters:
      api_key: fixture-only
      base_url: http://127.0.0.1:1/v1
rails:
  input:
    flows: [self check input]
prompts:
  - task: self_check_input
    content: "{{ user_input }}"
""")
        app = Guardrails(config, require_iorails=True)
        engine = app.rails_engine
        # Replace the provider, BEFORE the real self-check action computes its
        # verdict.  Stage 5A never overrides a final target decision.
        engine.engine_registry._llms["self_check_input"] = JevModel()
        main = FakeLLMModel(responses=["FIXTURE_MAIN_COMPLETED"])

        async def audit_main(model_type, messages, **kwargs):
            if model_type != "main":
                raise RuntimeError("unexpected external model route")
            audit.append({"action": "MAIN_LLM_CALL", "cmd": None})
            return await main.generate_async(messages, **kwargs)

        # The external main LLM is an inert audit sink, not the judgment.
        engine.engine_registry.model_call = audit_main
        try:
            result = await app.generate_async(messages=[{"role": "user", "content": context}])
        finally:
            await engine.stop()
        if len(calls) != 1:
            raise RuntimeError(f"expected one live self-check call, got {len(calls)}")
        return {"status": "generated" if audit else "blocked", "audit": audit,
                "judge_calls": calls, "native_result": result}


def behavior_signature(run: dict) -> str:
    """Exclude changed source bytes: they are not evidence of branch divergence."""
    return json.dumps({"status": run["status"], "audit": run["audit"]}, sort_keys=True)


class FixedDecisionJudge:
    """Stage 5B ONLY: explicit counterfactual intervention."""
    def __init__(self, decision: str):
        self.decision = decision

    def judge(self, spec):
        return {"decision": self.decision, "probabilities": None, "confidence": None,
                "intervention": "fixed_decision_counterfactual"}
