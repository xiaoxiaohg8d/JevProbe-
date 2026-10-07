"""Judgment Surface record schema (V0 output format, S11 v1.4).

V0 must emit call-chain information: many real projects hide the Jev boundary
behind application wrappers (agent.decide -> policy.evaluate -> jev), so
"found a judge call" != "found the decision boundary".
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .taxonomy import SurfaceType, SourceType


@dataclass
class SourceRef:
    kind: SourceType
    detail: str            # e.g. "requests.get(url).text"
    where: str = ""        # param-trace if interprocedurally resolved

    def to_dict(self) -> dict:
        return {"kind": self.kind.to_json(), "detail": self.detail, "where": self.where}


@dataclass
class Surface:
    """One discovered Jev judgment call site + its V0 call-chain context."""
    file: str
    line: int
    symbol: str                       # enclosing function
    callee: str                       # syntactic callee name
    resolved_callable: str = ""       # best-effort resolved target ("" if unknown)
    call_chain_depth: int = 1         # 1 = direct jev(...) call
    wrapper_candidates: list[str] = field(default_factory=list)
    sources: list[SourceRef] = field(default_factory=list)
    surface_type: SurfaceType | None = None   # typed by downstream consumer analysis
    sink_types: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "file": self.file, "line": self.line, "symbol": self.symbol,
            "callee": self.callee, "resolved_callable": self.resolved_callable,
            "call_chain_depth": self.call_chain_depth,
            "wrapper_candidates": self.wrapper_candidates,
            "sources": [s.to_dict() for s in self.sources],
            "surface_type": self.surface_type.to_json() if self.surface_type else None,
            "sink_types": self.sink_types,
        }
