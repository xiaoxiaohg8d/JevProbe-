"""Sprint 3 Phase C — GitHub candidate collection for the ecosystem census.

Repo-level search across keyword groups (Jev-ish decision verbs x agent
indicators), deduplicated and categorized. Output: candidate_repos.json.
Rate-limit aware (search: 30 req/min authenticated).
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import urllib.request
import urllib.parse

CENSUS_DIR = Path(__file__).resolve().parent / "census"
CENSUS_DIR.mkdir(exist_ok=True)

QUERIES = [
    ("llm agent", "Agent framework"),
    ("agent framework llm", "Agent framework"),
    ("autonomous agent llm", "Agent framework"),
    ("coding agent", "Coding agent"),
    ("ai coding assistant agent", "Coding agent"),
    ("swe agent llm", "Coding agent"),
    ("mcp server", "MCP/tool agent"),
    ("tool calling agent", "MCP/tool agent"),
    ("function calling llm agent", "MCP/tool agent"),
    ("llm guardrail", "Security agent"),
    ("prompt injection detection", "Security agent"),
    ("llm safety filter", "Security agent"),
    ("llm judge evaluation", "Other"),
    ("agent workflow llm", "Other"),
    ("llm decision making", "Other"),
]

CATEGORY_HINTS = {
    "Coding agent": ["coding", "swe", "dev ", "developer", "code assistant", "ide",
                     "autocode", "refactor", "copilot", "cline", "aider", "continue"],
    "Security agent": ["security", "guard", "scan", "inject", "pentest", "vuln",
                       "safety", "moderation", "firewall", "protect"],
    "MCP/tool agent": ["mcp", "tool", "function call", "server", "plugin"],
    "Agent framework": ["agent", "autogen", "crew", "langgraph", "langchain",
                        "orchestrat", "workflow", "planner", "swarm"],
}


def _categorize(name: str, desc: str, topics, query_cat: str) -> str:
    text = (name + " " + (desc or "") + " " + " ".join(topics or [])).lower()
    for cat, hints in CATEGORY_HINTS.items():
        if any(h in text for h in hints):
            return cat
    return query_cat if query_cat != "Other" else "Other"


def _search(token: str, q: str, per_page: int = 30) -> list[dict]:
    url = ("https://api.github.com/search/repositories?q="
           + urllib.parse.quote(f"{q} language:python") + f"&sort=stars&per_page={per_page}")
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "jevsec-census"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r).get("items", [])


def main() -> int:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    token = os.getenv("GH_TOKEN")
    if not token:
        raise SystemExit("GH_TOKEN missing in .env")

    repos: dict[str, dict] = {}
    failures = []
    for q, cat in QUERIES:
        try:
            items = _search(token, q)
        except Exception as e:
            failures.append({"query": q, "error": str(e)[:120]})
            time.sleep(3)
            continue
        for it in items:
            full = it["full_name"]
            if full in repos:
                repos[full]["discovery_reason"].append(q)
                continue
            repos[full] = {
                "repo": full,
                "category": _categorize(it["name"], it.get("description") or "",
                                        it.get("topics"), cat),
                "stars": it["stargazers_count"],
                "language": it.get("language"),
                "size_kb": it.get("size"),
                "source_url": it["html_url"],
                "description": (it.get("description") or "")[:140],
                "discovery_reason": [q],
            }
        print(f"query '{q}': {len(items)} items (total unique {len(repos)})", flush=True)
        time.sleep(2.5)  # stay under search rate limit

    out = sorted(repos.values(), key=lambda r: -r["stars"])
    (CENSUS_DIR / "candidate_repos.json").write_text(
        json.dumps({"meta": {"queries": len(QUERIES), "failures": failures,
                             "collected_at": time.strftime("%Y-%m-%dT%H:%M:%S")},
                    "repos": out}, ensure_ascii=False, indent=1), encoding="utf-8")
    by_cat = {}
    for r in out:
        by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
    print("candidates:", len(out), "by category:", by_cat)
    if failures:
        print("query failures:", failures)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
