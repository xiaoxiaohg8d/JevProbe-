"""Differential oracle for SJI: canonical-space comparison of judgment results.

Core idea: a transform is only verdict-worthy if, after mapping its labels back
through the transform's inverse bijection, the consumed decision (argmax) or
its margin changes. All comparisons happen on canonical probability dicts.
"""
from __future__ import annotations

import math

EPS = 1e-12


def prob_dict(result: dict) -> dict[str, float]:
    return dict(zip(result["option_ids"], result["probabilities"]))


def canonical(p: dict[str, float], inverse: dict[str, str]) -> dict[str, float]:
    """Relabel probabilities back to base option ids; sums on collision."""
    out: dict[str, float] = {}
    for k, v in p.items():
        base = inverse.get(k, k)
        out[base] = out.get(base, 0.0) + v
    return out


def decision(p: dict[str, float]) -> tuple[str | None, float]:
    items = sorted(p.items(), key=lambda kv: (-kv[1], kv[0]))
    if not items:
        return None, 0.0
    top_id, top_p = items[0]
    second = items[1][1] if len(items) > 1 else 0.0
    return top_id, top_p - second


def js_divergence(p: dict[str, float], q: dict[str, float]) -> float:
    keys = set(p) | set(q)
    pv = _norm([p.get(k, 0.0) for k in keys])
    qv = _norm([q.get(k, 0.0) for k in keys])
    m = [(a + b) / 2 for a, b in zip(pv, qv)]
    return _kl(pv, m) / 2 + _kl(qv, m) / 2


def normalized_entropy(p: dict[str, float]) -> float:
    if len(p) < 2:
        return 0.0
    vals = _norm(list(p.values()))
    h = -sum(v * math.log2(v + EPS) for v in vals if v > 0)
    return h / math.log2(len(vals))


def analyze(base_results: list[dict], trans_results: list[dict],
            inverse: dict[str, str] | None = None, margin_eps: float = 0.05) -> dict:
    """Compare baseline vs transformed judgment results (lists = repeats).

    A result dict carries ``option_ids`` + ``probabilities``; sampling-based
    runners may additionally carry ``picks`` (raw per-repeat label choices),
    which is what sign consistency is computed over.
    """
    inverse = inverse or {}
    bp = [canonical(prob_dict(r), inverse) for r in base_results]
    tp = [canonical(prob_dict(r), inverse) for r in trans_results]
    if not bp or not tp:
        return {"error": "empty results"}

    base_dec, base_margin = decision(bp[0])
    trans_decs = [decision(p)[0] for p in tp]
    trans_margins = [decision(p)[1] for p in tp]
    trans_dec = _majority(trans_decs)
    flip = trans_dec != base_dec and trans_dec is not None

    repeat_decs = [inverse.get(pick, pick)
                   for r in trans_results for pick in r.get("picks", [])]
    if len(repeat_decs) >= 2:
        systematic = flip and all(d == trans_dec for d in repeat_decs)
    else:
        systematic = flip  # deterministic readout: a flip is by definition systematic

    base_p = bp[0]
    trans_p = tp[0]
    deltas = {k: round(trans_p.get(k, 0.0) - base_p.get(k, 0.0), 6) for k in set(base_p) | set(trans_p)}

    return {
        "base_decision": base_dec,
        "base_margin": round(base_margin, 6),
        "trans_decision": trans_dec,
        "trans_margin": round(sum(trans_margins) / len(trans_margins), 6),
        "flip": flip,
        "systematic_flip": systematic,
        "margin_crossing": (base_margin >= margin_eps) and (sum(trans_margins) / len(trans_margins) < margin_eps),
        "delta_top_p": round(_top_delta(base_p, trans_p), 6),
        "per_option_delta": deltas,
        "js_divergence": round(js_divergence(base_p, trans_p), 6),
        "u2a": {
            "base_entropy": round(normalized_entropy(base_p), 6),
            "trans_entropy": round(normalized_entropy(trans_p), 6),
            "base_uncertain": base_margin < margin_eps,
            "trans_uncertain": (sum(trans_margins) / len(trans_margins)) < margin_eps,
        },
    }


def summarize(analyses: list[dict]) -> dict:
    n = len(analyses)
    if n == 0:
        return {"n": 0}
    return {
        "n": n,
        "flip_rate": sum(a["flip"] for a in analyses) / n,
        "systematic_flip_rate": sum(a["systematic_flip"] for a in analyses) / n,
        "margin_crossing_rate": sum(a["margin_crossing"] for a in analyses) / n,
        "mean_js": sum(a["js_divergence"] for a in analyses) / n,
        "mean_abs_delta_top": sum(abs(a["delta_top_p"]) for a in analyses) / n,
    }


def _norm(vals: list[float]) -> list[float]:
    s = sum(vals)
    return [v / s for v in vals] if s > 0 else [0.0] * len(vals)


def _kl(a: list[float], b: list[float]) -> float:
    return sum(x * math.log2((x + EPS) / (y + EPS)) for x, y in zip(a, b) if x > 0)


def _majority(decs: list[str | None]) -> str | None:
    counts: dict[str, int] = {}
    for d in decs:
        if d is not None:
            counts[d] = counts.get(d, 0) + 1
    return max(counts.items(), key=lambda kv: kv[1])[0] if counts else None


def _top_delta(base_p: dict, trans_p: dict) -> float:
    bd = decision(base_p)[0]
    return trans_p.get(bd, 0.0) - base_p.get(bd, 0.0)
