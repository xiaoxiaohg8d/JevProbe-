"""Static scan cache keyed by source, relative path and detector implementation."""
from __future__ import annotations

import ast
from pathlib import Path

from .store import digest
from ..discovery_v0 import DiscoveryV0


def discover(store, candidates, names=None):
    detector_source = Path(__file__).resolve().parents[1] / "discovery_v0.py"
    dependency = detector_source.parent / "analysis/discovery.py"
    detector_hash = digest([detector_source.read_text(), dependency.read_text(), sorted(names or [])])
    detector = DiscoveryV0(judgment_names=names, path_filter=True) if names else DiscoveryV0(path_filter=True)
    results = []
    for candidate in candidates:
        row = {"repo_id": candidate["repo"], "provenance": candidate.get("provenance", "candidate"),
               "detector_hash": detector_hash, "status": "static_scanned", "files": [], "errors": [], "cached_files": 0}
        root = Path(candidate["checkout"]) if candidate.get("checkout") else None
        if root is None or not root.is_dir():
            row["status"] = "untested_checkout_missing"
            results.append(row)
            continue
        for path in sorted(root.rglob("*.py")):
            if any(p in {".git", ".venv", "node_modules", "__pycache__"} for p in path.relative_to(root).parts):
                continue
            relative = str(path.relative_to(root))
            try:
                source = path.read_text(encoding="utf-8")
                ast.parse(source)  # Record parse failure rather than silently empty discovery.
                key = "static:s13.1:" + digest({"source": source, "relative": relative, "root_name": root.name,
                                                "detector": detector_hash})
                cached = store.input(key)
                if cached is None:
                    surfaces, excluded = detector.scan_file(path, root)
                    cached = {"relative_path": relative, "source_hash": digest(source),
                              "surfaces": surfaces, "excluded": excluded, "confirmation": "heuristic_only"}
                    store.put_input(key, cached)
                else:
                    row["cached_files"] += 1
                row["files"].append(cached)
            except (SyntaxError, UnicodeError, OSError) as error:
                row["errors"].append({"file": relative, "diagnostic_status": "discovery_error", "error_type": type(error).__name__})
        if row["errors"]:
            row["status"] = "static_partial_failure"
        results.append(row)
    return results
