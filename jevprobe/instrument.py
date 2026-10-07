"""Sprint 3 Phase E/F — Instrumentation V0: monitor_call + canary reachability.

V0 scope (frozen): direct call + wrapper-resolved call observation by
monkeypatching the discovered callable at its defining module — no AST
rewrite, no runtime weaving. The monitor records the judgment boundary
(input hash + decision output); canary checks reuse the same records.

Driver protocol (per project): a small script under targets/_instr/<repo>/
sets OPENAI_BASE_URL to the local vLLM, patches surfaces found by Discovery
V0, invokes the judgment path with a fixture, dumps records JSON.
"""
from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path


class Monitor:
    def __init__(self):
        self.records: list[dict] = []
        self._saved: dict[int, object] = {}
        self._patches: list = []

    # ---- core wrapper --------------------------------------------------
    def wrap(self, surface: dict, fn):
        def monitored(*args, **kwargs):
            rec = self._record(surface, args, kwargs, pending=True)
            try:
                out = fn(*args, **kwargs)
            except Exception as e:  # observe failures too — never silent
                rec["decision_output"] = f"<raised {type(e).__name__}: {str(e)[:80]}>"
                self.records.append(rec)
                raise
            rec["decision_output"] = repr(out)[:200]
            self.records.append(rec)
            return out

        async def monitored_async(*args, **kwargs):
            rec = self._record(surface, args, kwargs, pending=True)
            try:
                out = await fn(*args, **kwargs)
            except Exception as e:
                rec["decision_output"] = f"<raised {type(e).__name__}: {str(e)[:80]}>"
                self.records.append(rec)
                raise
            rec["decision_output"] = repr(out)[:200]
            self.records.append(rec)
            return out

        import inspect
        return monitored_async if inspect.iscoroutinefunction(fn) else monitored

    def _record(self, surface: dict, args, kwargs, pending: bool = False) -> dict:
        payload = repr(args)[:400] + repr(kwargs)[:200]
        return {
            "surface_id": f"{surface.get('file')}:{surface.get('line')}",
            "repo": surface.get("repo", ""),
            "file": surface.get("file"), "line": surface.get("line"),
            "resolved_callable": surface.get("resolved_callable") or surface.get("callee"),
            "call_chain_depth": surface.get("call_chain_depth", 1),
            "wrapper_candidates": surface.get("wrapper_candidates", []),
            "input_sources": surface.get("input_sources", []),
            "consumer_type": surface.get("consumer_type", ""),
            "input_hash": hashlib.sha256(payload.encode()).hexdigest()[:16],
            "input_preview": payload[:240],
            "decision_output": None,
            "reachable": True,  # the call actually fired in this run
        }

    # ---- patching -------------------------------------------------------
    def patch(self, module_name: str, attr: str, surface: dict) -> bool:
        """Wrap module.attr in place; returns False if target missing."""
        try:
            mod = importlib.import_module(module_name)
        except Exception:
            return False
        fn = getattr(mod, attr, None)
        if fn is None or not callable(fn):
            return False
        self._saved[id(fn)] = fn
        self._patches.append((module_name, attr))
        setattr(mod, attr, self.wrap(surface, fn))
        return True

    def patch_from_surfaces(self, surfaces: list[dict]) -> tuple[int, int]:
        """Patch (module, attr) pairs inferred from surface file paths."""
        ok = fail = 0
        for s in surfaces:
            module = _module_from_path(s.get("file", ""))
            attr = (s.get("callee") or "").split(".")[-1]
            if not module or not attr:
                fail += 1
                continue
            if self.patch(module, attr, s):
                ok += 1
                self._patches.append((module, attr))
            else:
                fail += 1
        return ok, fail

    # ---- canary (Phase F) -------------------------------------------------
    def canary_report(self, canary: str, source: str, location: str) -> dict:
        hits = [r for r in self.records if canary in r["input_preview"]]
        return {
            "canary": canary, "source": source, "location": location,
            "judgment_invocations": len(self.records),
            "reachable": bool(hits),
            "propagation_depth": (hits[0]["call_chain_depth"] if hits
                                  else (self.records[0]["call_chain_depth"] if self.records else None)),
            "reached_surface": hits[0]["surface_id"] if hits else None,
        }

    def dump(self, path: Path):
        path.write_text(json.dumps(self.records, ensure_ascii=False, indent=1),
                        encoding="utf-8")


def _module_from_path(py_path: str) -> str | None:
    """repo-relative 'pkg/sub/mod.py' -> importable 'pkg.sub.mod' (best effort)."""
    if not py_path or not py_path.endswith(".py") or py_path.startswith("/"):
        return None
    parts = py_path[:-3].replace("\\", "/").split("/")
    if not parts or any(not p or p in {".", ".."} for p in parts):
        return None
    return ".".join(parts)
