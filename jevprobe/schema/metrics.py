"""Frozen divergence metrics (S11 v1.4 formulas).

DFR = N(before != after) / N                      (choice, majority level)
TCR = N(crosses developer threshold) / N          (score)
RDR = 1 - tau                                     (tau = Kendall rank correlation)
USS = signal-type-specific delta (dp / dH / dm)   (uncertainty)
BDR = behavior changes / decision flips
SIR = security-relevant cases / all attacks
"""
from __future__ import annotations


def dfr(before: list, after: list) -> float:
    n = len(before)
    if n == 0 or n != len(after):
        return 0.0
    return sum(1 for b, a in zip(before, after) if b != a) / n


def tcr(before_values: list[float], after_values: list[float], threshold: float) -> float:
    n = len(before_values)
    if n == 0 or n != len(after_values):
        return 0.0
    crossed = sum(1 for b, a in zip(before_values, after_values)
                  if (b < threshold) != (a < threshold))
    return crossed / n


def kendall_tau(rank_a: list, rank_b: list) -> float:
    """Kendall rank correlation over items common to both rankings.

    Inputs are ordered lists (best first). Returns 1.0 for identical order,
    -1.0 for reversed (on common items), 1.0 when fewer than 2 common items
    (degenerate: treated as consistent).
    """
    pos_b = {item: i for i, item in enumerate(rank_b)}
    common = [item for item in rank_a if item in pos_b]
    n = len(common)
    if n < 2:
        return 1.0
    concordant = discordant = 0
    for i in range(n):
        for j in range(i + 1, n):
            # common[i] precedes common[j] in rank_a by construction
            if pos_b[common[i]] < pos_b[common[j]]:
                concordant += 1
            else:
                discordant += 1
    total = concordant + discordant
    return (concordant - discordant) / total if total else 1.0


def rdr(before_ranking: list, after_ranking: list) -> float:
    """Ranking Divergence Rate = (1 - tau) / 2, normalized to [0,1].

    Identical order -> 0.0, fully reversed -> 1.0 (the raw 1-tau would give 2.0
    for reversal, violating the frozen semantics "0 consistent, 1 fully changed").
    """
    return (1.0 - kendall_tau(before_ranking, after_ranking)) / 2.0


def uss(before: float, after: float, signal_kind: str) -> dict:
    """Uncertainty Signal Shift: delta of the actually observed signal kind.

    signal_kind in {probability, entropy, margin} — never renamed to confidence.
    """
    if signal_kind not in {"probability", "entropy", "margin"}:
        raise ValueError(f"unknown signal kind: {signal_kind}")
    return {"kind": signal_kind, "delta": round(after - before, 6)}


def bdr(behavior_changes: int, decision_flips: int) -> float:
    return behavior_changes / decision_flips if decision_flips else 0.0


def rr(validated_paths: int, candidate_paths: int) -> float:
    """Reachability Rate = validated / candidate (RQ2, Table 2, S11 v1.4)."""
    return validated_paths / candidate_paths if candidate_paths else 0.0


def sir(security_relevant: int, all_attacks: int) -> float:
    return security_relevant / all_attacks if all_attacks else 0.0


def majority(decisions: list) -> object:
    counts: dict = {}
    for d in decisions:
        counts[d] = counts.get(d, 0) + 1
    if not counts:
        return None
    return max(counts.items(), key=lambda kv: kv[1])[0]
