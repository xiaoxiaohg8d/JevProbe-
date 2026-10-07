"""Differential analysis: before/after per frozen surface-type metric.

Choice -> DFR (per-case flip + majority + consistency)
Score  -> TCR (threshold crossing on means)
Ranking -> RDR = (1 - tau)/2
Uncertainty -> USS (per-option Δp; never renamed confidence)
"""
from __future__ import annotations

from ..schema import criteria as C
from ..schema import metrics as M


def choice_diff(before_decisions: list, after_decisions: list) -> dict:
    mb, ma = M.majority(before_decisions), M.majority(after_decisions)
    return {
        "flip": C.choice_flip(before_decisions, after_decisions),
        "majority_before": mb, "majority_after": ma,
        "before_stable": len(set(before_decisions)) == 1,
        "after_stable": len(set(after_decisions)) == 1,
        "flip_consistency": (sum(1 for d in after_decisions if d == ma) / len(after_decisions))
        if after_decisions else 0.0,
    }


def score_diff(before_vals: list[float], after_vals: list[float], threshold: float) -> dict:
    mb = sum(before_vals) / len(before_vals) if before_vals else 0.0
    ma = sum(after_vals) / len(after_vals) if after_vals else 0.0
    return {
        "crossed": C.score_crossing(mb, ma, threshold),
        "mean_before": round(mb, 4), "mean_after": round(ma, 4),
        "std_before": round(_std(before_vals), 4),
        "std_after": round(_std(after_vals), 4),
    }


def ranking_diff(before_rank: list, after_rank: list) -> dict:
    tau = M.kendall_tau(before_rank, after_rank)
    return {"tau": round(tau, 4), "rdr": round(M.rdr(before_rank, after_rank), 4),
            "diverged": C.ranking_divergence(before_rank, after_rank)}


def uncertainty_diff(before_probs: dict | None, after_probs: dict | None) -> dict:
    """USS as Δp per option (probability signal); None-safe."""
    if not before_probs or not after_probs:
        return {"type": "none"}
    if set(before_probs) != set(after_probs):
        raise ValueError("probability support changed between sides; cannot impute missing values")
    keys = set(before_probs) | set(after_probs)
    deltas = {k: round(after_probs.get(k, 0.0) - before_probs.get(k, 0.0), 4) for k in keys}
    return {"type": "probability", "deltas": deltas,
            "max_abs_delta": round(max(abs(v) for v in deltas.values()), 4)}


def analyze(surface_type: str, before_decisions: list, after_decisions: list,
            before_probs: dict | None = None, after_probs: dict | None = None,
            threshold: float | None = None) -> dict:
    """Per-case divergence record for a choice surface (current pilot scope)."""
    if surface_type != "choice":
        raise ValueError(f"pilot v0.1 scope: choice surfaces only, got {surface_type}")
    out = choice_diff(before_decisions, after_decisions)
    uss = uncertainty_diff(before_probs, after_probs)
    out["uss"] = uss
    return out


def _std(vals: list[float]) -> float:
    if not vals:
        return 0.0
    mu = sum(vals) / len(vals)
    return (sum((v - mu) ** 2 for v in vals) / len(vals)) ** 0.5
