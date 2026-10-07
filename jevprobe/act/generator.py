"""ACT generator facade: frozen strategy registry, no new strategies (Sprint 4-A).

Delegates to manipulation.py (16 frozen strategies; active generator =
Qwen3-32B local vLLM by default, GLM adapter retained but off).
"""
from __future__ import annotations

from ..manipulation import DIMENSIONS, STRATEGIES, generate


def available_strategies() -> list[str]:
    return sorted(STRATEGIES)


def dimension_of(strategy_cls: str) -> str:
    return DIMENSIONS[strategy_cls]


def generate_variant(context: str, strategy_cls: str, use_llm: bool = True) -> dict:
    """One strategy applied to one context; returns manipulation record."""
    return generate(context, [strategy_cls], use_llm=use_llm)[0]
