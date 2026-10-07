"""Generic stdio bridge adapters: one bridge per project, shared transport loop.

BridgeRunner spawns a transport-only bridge (subprocess) and mediates the
systemone request/response over stdio; SdkTextAdapter is a complete adapter
for applications whose Jev judgment consumes a text channel via the shared
typesafe SDK (including .mjs bridges via bun).

All content read from the target application is untrusted data.
"""
import json
import os
import selectors
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from dotenv import dotenv_values

NATIVE_MJS_BRIDGES = {}  # optional: project -> native .mjs bridge name



class BridgeRunner:
    def __init__(self, root, repo_id, runtime=os.environ.get("JEVPROBE_RUNTIME", "work/runtime"), timeout_s=180, extra_args=()):
        self.root = Path(root).resolve()
        self.repo_id = repo_id
        if repo_id not in BRIDGES:
            raise ValueError(f"no JevProbe bridge for {repo_id}")
        self.checkout = self.root / "targets/_census" / repo_id.replace("/", "__")
        pin = json.loads((self.checkout / ".jevsec_pin.json").read_text())
        self.commit = pin["commit"]
        self.bun = (self.root / runtime).resolve() / "bun-npm/package/bin/bun"
        self.runtime = (self.root / runtime).resolve()
        self.bridge = Path(__file__).with_name(BRIDGES[repo_id])
        self.timeout_s = timeout_s
        self.extra_args = tuple(extra_args)
        self.deps_root = None  # optional override: where project node_modules live

    def run(self, initial, judge):
        # Same hygiene as NativeOutput: the child never sees credentials.
        env = {k: v for k, v in os.environ.items()
               if not any(x in k.upper() for x in ("API_KEY", "TOKEN", "SECRET", "PASSWORD"))}
        with tempfile.TemporaryDirectory(prefix="jevsec--") as directory:
            with tempfile.TemporaryFile(mode="w+t") as errors:
                process = subprocess.Popen(
                    [str(self.bun), "--no-install", str(self.bridge), str(self.checkout),
                     str(self.deps_root or self.runtime)]
                    + [str(a) for a in self.extra_args],
                    cwd=directory, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=errors, text=True, bufsize=1)
                requests, ordinal = [], 0
                try:
                    process.stdin.write(json.dumps(initial) + "\n")
                    process.stdin.flush()
                    deadline = time.monotonic() + self.timeout_s
                    selector = selectors.DefaultSelector()
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not selector.select(remaining):
                            raise TimeoutError("bridge deadline")
                        line = process.stdout.readline()
                        if not line:
                            errors.seek(0)
                            raise RuntimeError("bridge exited: " + errors.read(1600))
                        message = json.loads(line)
                        if message["kind"] == "result":
                            process.wait(timeout=5)
                            return {"requests": requests, "result": message,
                                    "source_hash": digest(initial),
                                    "repo_id": self.repo_id, "commit": self.commit}
                        if message["kind"] != "request":
                            raise ValueError("unexpected bridge message")
                        request = message["request"]
                        response = judge(request, ordinal)
                        if isinstance(response, tuple):  # (answer, attempt) json_request convention
                            response = response[0]
                        validate_response(request, response)
                        requests.append({"ordinal": ordinal, "url": message.get("url"), "request": request})
                        process.stdin.write(json.dumps({"kind": "response", "response": response}) + "\n")
                        process.stdin.flush()
                        ordinal += 1
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)


class SdkTextAdapter:
    """Generic adapter for Python SDK projects that evaluate text via
    TypeSafeClient.system_one with standard questions. The bridge runs the
    project's own client construction and question building."""

    def __init__(self, root, repo_id, bridge_name, runtime=os.environ.get("JEVPROBE_RUNTIME", "work/runtime")):
        self.root = Path(root).resolve()
        self.repo_id = repo_id
        checkout_name = repo_id.replace("/", "__")
        self.checkout = self.root / "targets/_census" / checkout_name
        pin = json.loads((self.checkout / ".jevsec_pin.json").read_text())
        self.commit = pin.get("commit")
        self.python = Path(os.environ.get("JEVPROBE_PYTHON", sys.executable))
        self.bridge = Path(__file__).with_name(bridge_name)

    def run(self, text, judge):
        env = {k: v for k, v in os.environ.items()
               if not k.lower().endswith("_proxy") and k.lower() not in ("all_proxy", "no_proxy")}
        bun = self.root / "work/runtime/bun-npm/package/bin/bun"
        if self.bridge.suffix == ".mjs" and bun.exists():
            # .mjs bridges: symlink deps into checkout, then run with bun
            nm = self.checkout / "node_modules"
            deps = self.root / "work/_runtime/jev-mcp-deps/node_modules"
            if deps.exists() and not nm.exists():
                os.symlink(deps, nm, target_is_directory=True)
            # For .mjs bridges, pass runtime dir so bridge can find SDK deps
            self._runtime_dir = str(self.root / "work/_runtime")
            cmd = [str(bun), "--no-install", str(self.bridge), str(self.checkout),
                   str(self.root / "work/_runtime")]
        else:
            cmd = [str(self.python), str(self.bridge), str(self.checkout)]
        with tempfile.TemporaryDirectory(prefix="jevsec-sdk-") as directory:
            with tempfile.TemporaryFile(mode="w+t") as errors:
                process = subprocess.Popen(
                    cmd,
                    cwd=directory, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=errors, text=True, bufsize=1)
                requests, ordinal = [], 0
                try:
                    process.stdin.write(json.dumps({"text": text}) + "\n")
                    process.stdin.flush()
                    deadline = time.monotonic() + 120
                    selector = selectors.DefaultSelector()
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not selector.select(remaining):
                            raise TimeoutError("sdk bridge deadline")
                        line = process.stdout.readline()
                        if not line:
                            errors.seek(0)
                            raise RuntimeError("sdk bridge exited: " + errors.read(1600))
                        message = json.loads(line)
                        if message["kind"] == "result":
                            process.wait(timeout=5)
                            return {"requests": requests, "result": message,
                                    "repo_id": self.repo_id, "commit": self.commit}
                        if message["kind"] != "request":
                            raise ValueError("unexpected sdk bridge message")
                        response = judge(message["request"], ordinal)
                        if isinstance(response, tuple):
                            response = response[0]
                        validate_response(message["request"], response)
                        requests.append({"ordinal": ordinal, "request": message["request"]})
                        process.stdin.write(json.dumps({"kind": "response", "response": response}) + "\n")
                        process.stdin.flush()
                        ordinal += 1
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)

    @staticmethod
    def decisions(result):
        payload = result["result"]
        answers = payload.get("answers") or {}
        return {"answers": answers,
                "behavior": {k: (v.get("choice") or v.get("noul") or v.get("score"))
                             for k, v in answers.items() if isinstance(v, dict)},
                "decision_values": {}, "requests": result["requests"]}

    def decision_rows(self, result):
        rows = []
        for name, answer in (result["result"].get("answers") or {}).items():
            if not isinstance(answer, dict):
                continue
            if answer.get("type") == "choice" and answer.get("choice"):
                options = sorted((answer.get("probabilities") or {answer["choice"]: 1}).keys())
                rows.append({"decision_id": f"ans:{name}", "value": answer["choice"],
                             "native_answer": answer, "signal_type": "choice",
                             "surface_type": "choice",
                             "contract": {"type": "choice", "options": options}})
            elif answer.get("type") == "noul" and isinstance(answer.get("noul"), (int, float)):
                rows.append({"decision_id": f"ans:{name}", "value": answer["noul"],
                             "native_answer": answer, "signal_type": "probability",
                             "surface_type": "score",
                             "contract": {"type": "score", "range": [0, 1],
                                          "boundaries": [{"operator": ">=", "threshold": 0.5}]}})
        return rows
