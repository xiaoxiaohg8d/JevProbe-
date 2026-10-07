"""Budgeted resumable GitHub pagination with explicit search coverage limits."""
from __future__ import annotations

import urllib.parse

from .manifest import select_candidates
from .store import BudgetExceeded, digest, now
from .transport import json_request
from ..collect import _categorize


def collect(store, queries, token, scopes, max_pages=2, per_page=100, opener=None):
    if not 1 <= max_pages <= 10 or not 1 <= per_page <= 100:
        raise ValueError("GitHub search pagination is bounded to 1000 results/query")
    repos, coverage = {}, []
    for query, category in queries:
        row = {"query": query, "category_hint": category, "pages": [], "status": "complete", "total_count": None}
        for page in range(1, max_pages + 1):
            params = {"q": query, "sort": "stars", "order": "desc", "per_page": per_page, "page": page}
            cache_key = "github-search:s13.1:" + digest(params)
            cached = store.input(cache_key)
            try:
                if cached is None:
                    answer, attempt = json_request(store, scopes,
                        {"provider": "github", "batch_id": "collection", "query_hash": digest(query), "page": page},
                        "https://api.github.com/search/repositories?" + urllib.parse.urlencode(params), None,
                        headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                                 "User-Agent": "jevprobe-s13"}, opener=opener, retries=0, timeout=30)
                    cached = {"answer": answer, "attempt_id": attempt, "snapshot_at": now()}
                    store.put_input(cache_key, cached)
                answer = cached["answer"]
                row["total_count"] = answer["total_count"]
                row["incomplete_results"] = answer.get("incomplete_results", False)
                items = answer["items"]
                row["pages"].append({"page": page, "items": len(items), "snapshot_at": cached["snapshot_at"],
                                     "attempt_id": cached["attempt_id"], "cache_key": cache_key})
                for item in items:
                    name = item["full_name"]
                    existing = repos.get(item["id"])
                    if existing:
                        existing["discovery_reason"].append(query)
                        continue
                    repos[item["id"]] = {"repo": name, "github_id": item["id"], "stars": item["stargazers_count"],
                        "stars_snapshot_at": cached["snapshot_at"], "source_url": item["html_url"],
                        "category": _categorize(item["name"], item.get("description"), item.get("topics"), category),
                        "category_status": "heuristic_pending_review", "fork": item.get("fork"),
                        "archived": item.get("archived"), "license": item.get("license"), "discovery_reason": [query]}
                if len(items) < per_page or page * per_page >= answer["total_count"]:
                    break
            except BudgetExceeded:
                row["status"] = "budget_interrupted"
                break
            except Exception as error:
                row.update({"status": "collection_failed", "error_type": type(error).__name__})
                break
        fetched = sum(p["items"] for p in row["pages"])
        if row["total_count"] is not None and fetched < row["total_count"] and row["status"] == "complete":
            row["status"] = "coverage_capped"
        row["suggested_split"] = "partition nonoverlapping stars ranges, then creation dates for equal-star overflow" if (row["total_count"] or 0) > 1000 else None
        coverage.append(row)
        # Search rate-limit response is in the authoritative attempt ledger.
        attempts = store.export()["attempts"]
        latest = attempts[-1] if attempts else None
        headers = (latest.get("result") or {}).get("headers", {}) if latest else {}
        if headers.get("x-ratelimit-remaining") == "0":
            coverage.append({"status": "rate_limit_checkpoint", "reset": headers.get("x-ratelimit-reset")})
            break
    return {"version": "s13.1", "provenance": "github_live_or_exact_metadata_cache", "coverage": coverage,
            "repos": select_candidates(list(repos.values())), "complete_population_claim": False}


def star_partitions(query):
    """Deterministic nonoverlapping first partition; overflow must split again."""
    ranges = ["0..9", "10..99", "100..999", "1000..9999", ">=10000"]
    return [query + " stars:" + interval for interval in ranges]
