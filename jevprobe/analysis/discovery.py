"""Stage 1 — Judgment Surface Discovery.

Static analysis that locates Jev/judgment call sites in Python code and runs a
backward slice (intraprocedural + one hop into module-local functions) to
classify which EXTERNAL inputs flow into the judgment context.

Known limits (documented on purpose): no interprocedural aliasing beyond one
hop, no framework-specific taint config, dynamic calls are missed. MVP scope.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_JUDGMENT_NAMES = {
    "jev", "judge", "evaluate", "decide", "classify", "score", "verify", "assess",
}
CONTEXT_KEYWORDS = {
    "context", "prompt", "state", "question", "input", "text", "doc",
    "document", "evidence", "content", "request",
}

FILE_LEAVES = {"read", "read_text", "readlines", "readline"}
HTTP_ROOTS = {"requests", "httpx", "urllib", "aiohttp", "http"}
SUBPROC_ROOTS = {"subprocess"}
SUBPROC_LEAVES = {"check_output", "check_call", "run", "Popen", "popen"}


@dataclass
class SourceRef:
    kind: str          # FILE_READ / HTTP / USER_INPUT / ENV / SUBPROCESS / PARAM / CONSTANT / UNKNOWN
    detail: str
    where: str = ""


@dataclass
class Surface:
    file: str
    line: int
    call: str
    context_expr: str
    sources: list[SourceRef] = field(default_factory=list)


BLACKLIST_LEAVES = {"model_validate", "validate_assignment"}  # pydantic noise


def is_judgment_leaf(dotted: str, names: set[str] | None = None) -> bool:
    """Match 'jev', 'judge', 'judge_safety', 'evaluate_request', 'classify_doc', ...

    Precision guards from census round 1: pydantic model_validate and private
    underscore methods are excluded (they dominated false positives).
    """
    names = names or DEFAULT_JUDGMENT_NAMES
    leaf = dotted.split(".")[-1]
    if leaf in BLACKLIST_LEAVES or "model_validate" in dotted:
        return False
    if leaf.startswith("_"):
        return False
    return any(leaf == n or leaf.startswith(n + "_") or leaf.endswith("_" + n) for n in names)


def dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _free_names(expr: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(expr) if isinstance(n, ast.Name)}


def _leaf_root(dotted: str) -> tuple[str, str]:
    parts = dotted.split(".")
    return (parts[-1], parts[0]) if parts else ("", "")


def _classify(expr: ast.AST, funcs: dict, env: dict, depth: int = 0) -> SourceRef | None:
    if depth > 4:
        return SourceRef("UNKNOWN", "recursion-limit")
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return SourceRef("CONSTANT", repr(expr.value[:40]))
    if isinstance(expr, ast.JoinedStr):
        return SourceRef("TEMPLATE", "f-string")
    if isinstance(expr, ast.BinOp):
        return _classify(expr.left, funcs, env, depth + 1) or _classify(expr.right, funcs, env, depth + 1)
    if isinstance(expr, ast.Attribute):
        if expr.attr in {"text", "content", "json", "body", "stdout"}:
            return _classify(expr.value, funcs, env, depth + 1)
        return _classify(expr.value, funcs, env, depth + 1) if isinstance(expr.value, ast.Call) else None
    if isinstance(expr, ast.Call):
        dotted = dotted_name(expr.func)
        if not dotted:
            return SourceRef("UNKNOWN", "dynamic-call")
        leaf, root = _leaf_root(dotted)
        if "read_text" in dotted or (leaf in FILE_LEAVES and root in {"open", "Path", "path"}):
            return SourceRef("FILE_READ", dotted)
        if root in HTTP_ROOTS:
            return SourceRef("HTTP", dotted)
        if root in SUBPROC_ROOTS and leaf in SUBPROC_LEAVES:
            return SourceRef("SUBPROCESS", dotted)
        if dotted == "input" or "argv" in dotted:
            return SourceRef("USER_INPUT", dotted)
        if root == "os" or leaf == "getenv" or dotted.startswith("os.environ"):
            return SourceRef("ENV", dotted)
        if dotted in funcs:  # one hop into module-local function
            ret = _return_expr(funcs[dotted])
            inner = _classify(ret, funcs, env, depth + 1) if ret is not None else None
            return SourceRef(inner.kind if inner else "UNKNOWN",
                             f"{dotted}() -> {inner.detail if inner else '?'}")
        return SourceRef("UNKNOWN", dotted)
    if isinstance(expr, ast.Name):
        return env.get(expr.id) or SourceRef("PARAM", expr.id)
    return None


def _return_expr(fn: ast.FunctionDef) -> ast.AST | None:
    rets = [n.value for n in ast.walk(fn) if isinstance(n, ast.Return) and n.value is not None]
    return rets[-1] if rets else None


def _pick_context_expr(call: ast.Call) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg in CONTEXT_KEYWORDS:
            return kw.value
    return call.args[0] if call.args else None


def _env_for(fn, funcs) -> dict[str, SourceRef]:
    env: dict[str, SourceRef] = {}
    for stmt in ast.walk(fn):
        if isinstance(stmt, ast.Assign):
            cls = _classify(stmt.value, funcs, env)
            if cls:
                for t in stmt.targets:
                    if isinstance(t, ast.Name):
                        env[t.id] = cls
    return env


def _call_sites(funcs: dict) -> dict[str, list]:
    """callee name -> [(caller_name, call_node)] for module-local calls."""
    sites: dict[str, list] = {}
    for caller_name, fn in funcs.items():
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                leaf = dotted_name(node.func).split(".")[-1]
                if leaf in funcs and leaf != caller_name:
                    sites.setdefault(leaf, []).append((caller_name, node))
    return sites


def _resolve_param(fn_name: str, param_name: str, funcs: dict, callsites: dict,
                   depth: int = 0, seen: set | None = None):
    """Limited-depth interprocedural resolution: caller argument -> callee
    parameter -> judgment context. Returns (SourceRef, trace) or None; when
    unresolved we keep PARAM — never guess."""
    if depth > 3:
        return None
    seen = (seen or set()) | {fn_name}
    fn = funcs.get(fn_name)
    if fn is None:
        return None
    params = [a.arg for a in fn.args.args]
    if param_name not in params:
        return None
    idx = params.index(param_name)
    for caller_name, call in callsites.get(fn_name, []):
        if caller_name in seen:
            continue
        arg = call.args[idx] if idx < len(call.args) else next(
            (kw.value for kw in call.keywords if kw.arg == param_name), None)
        if arg is None:
            continue
        cls = _classify(arg, funcs, _env_for(funcs[caller_name], funcs), depth + 1)
        if cls and cls.kind != "PARAM":
            return cls, f"{caller_name}(): {ast.unparse(arg)[:40]}"
        if cls and cls.kind == "PARAM":
            sub = _resolve_param(caller_name, cls.detail, funcs, callsites,
                                 depth + 1, seen)
            if sub:
                return sub[0], f"{caller_name}:{param_name} <- {sub[1]}"
    return None


def discover_file(path: Path, judgment_names: set[str] | None = None) -> list[Surface]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    funcs = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    surfaces = []
    callsites = _call_sites(funcs)
    for fn in funcs.values():
        env = _env_for(fn, funcs)
        fn_params = {a.arg for a in fn.args.args}
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            dotted = dotted_name(node.func)
            if not is_judgment_leaf(dotted, judgment_names):
                continue
            ctx_expr = _pick_context_expr(node)
            if ctx_expr is None:
                continue
            sources = []
            for n in sorted(_free_names(ctx_expr)):
                src = env.get(n) or SourceRef("PARAM", n)
                if src.kind == "PARAM" and n in fn_params:
                    hit = _resolve_param(fn.name, n, funcs, callsites)
                    if hit:
                        src = SourceRef(hit[0].kind, hit[0].detail,
                                        f"param-trace: {fn.name}:{n} <- {hit[1]}")
                sources.append(src)
            surfaces.append(Surface(str(path), node.lineno, dotted,
                                    ast.unparse(ctx_expr)[:80], sources))
    return surfaces


def external_sources(surfaces: list[Surface]) -> list[SourceRef]:
    """Attacker-relevant sources: anything not a pure constant/template."""
    out, seen = [], set()
    for s in surfaces:
        for src in s.sources:
            if src.kind in {"CONSTANT", "TEMPLATE"}:
                continue
            key = (src.kind, src.detail)
            if key not in seen:
                seen.add(key)
                out.append(src)
    return out


def discover_tree(root: Path, judgment_names: set[str] | None = None) -> list[Surface]:
    out = []
    for p in sorted(root.rglob("*.py")):
        if any(seg in {".venv", "node_modules", "__pycache__"} for seg in p.parts):
            continue
        try:
            out.extend(discover_file(p, judgment_names))
        except SyntaxError:
            continue
    return out
