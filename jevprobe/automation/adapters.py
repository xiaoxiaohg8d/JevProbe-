"""Reusable native scanner sequence adapter, tested on a held-out output path."""
from __future__ import annotations

from ..analysis.native_e2e import _guard_packages


class ScannerSequenceDriver:
    def __init__(self, repo_dir, contract, channel="output", trusted_prompt="Fixture task; review the returned content."):
        if channel not in {"input", "output"}:
            raise ValueError("unsupported scanner channel")
        self.repo_dir, self.contract = repo_dir, contract
        self.channel, self.trusted_prompt = channel, trusted_prompt

    def run(self, context, judge):
        calls, audit = [], []
        contract, channel = self.contract, self.channel

        class JudgmentScanner:
            def scan(self, *args):
                source = args[-1]
                spec = {"state": source, **contract}
                result = judge.judge(spec)
                if result["decision"] not in {"allow", "block"}:
                    raise ValueError("native scanner contract mismatch")
                calls.append({"spec": spec, "result": result})
                return source, result["decision"] == "allow", (result.get("probabilities") or {}).get("block")

        class NextScanner:
            def scan(self, *args):
                audit.append({"action": "NEXT_SCANNER", "cmd": None})
                return args[-1], True, 0.0

        with _guard_packages(self.repo_dir) as target:
            if channel == "output":
                sanitized, valid, scores = target.scan_output(
                    [JudgmentScanner(), NextScanner()], self.trusted_prompt, context, fail_fast=True)
            else:
                sanitized, valid, scores = target.scan_prompt([JudgmentScanner(), NextScanner()], context, fail_fast=True)
        return {"status": "passed" if all(valid.values()) else "blocked", "audit": audit, "judge_calls": calls,
                "native_result": {"valid": valid, "scores": scores},
                "scope": "configured_jev_substitute; external_source_reinjection; unchanged_native_consumer"}
