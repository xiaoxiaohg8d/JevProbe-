"""Decision divergence SUCCESS CRITERIA — code-frozen mirror of
docs/decision_criteria.md (S11 v1.4). Without these, statistics drift.

Choice     : flip  <=> before-majority != after-majority
Score      : cross <=> one side < threshold, other >= threshold
Ranking    : diverge <=> kendall_tau(before, after) < tau_threshold
Uncertainty: shift <=> |after - before| > delta
"""
from __future__ import annotations

from .metrics import kendall_tau, majority

DEFAULTS = {
    "score_threshold": 0.5,       # overridden per-surface by developer-defined value
    "ranking_tau_threshold": 0.95,
    "uncertainty_delta": 0.05,
}


def choice_flip(before_runs: list, after_runs: list) -> bool:
    return majority(before_runs) != majority(after_runs)


def score_crossing(before_value: float, after_value: float,
                   threshold: float = DEFAULTS["score_threshold"]) -> bool:
    return (before_value < threshold) != (after_value < threshold)


def ranking_divergence(before_ranking: list, after_ranking: list,
                       tau_threshold: float = DEFAULTS["ranking_tau_threshold"]) -> bool:
    return kendall_tau(before_ranking, after_ranking) < tau_threshold


def uncertainty_shift(before_value: float, after_value: float,
                      delta: float = DEFAULTS["uncertainty_delta"]) -> bool:
    return abs(after_value - before_value) > delta
