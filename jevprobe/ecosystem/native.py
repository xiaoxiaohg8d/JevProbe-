"""Isolated JSON-line transport for real target request construction/consumption."""
from __future__ import annotations

import json
import os
from pathlib import Path
import selectors
import subprocess
import tempfile
import time

from ..automation.store import digest
from .core import number


def validate_response(request, response):
    answers = response.get("answers")
    if not isinstance(answers, dict) or set(answers) != set(request["questions"]):
        raise ValueError("missing/extra native answers")
    for key, question in request["questions"].items():
        answer = answers[key]
        kind = question["type"]
        if answer.get("type") != kind:
            raise ValueError("answer type mismatch")
        if kind == "noul":
            if not 0 <= number(answer.get("noul")) <= 1:
                raise ValueError("noul outside range")
        elif kind == "choice":
            if answer.get("choice") not in question["criteria"]:
                raise ValueError("choice outside criteria")
            for value in (answer.get("probabilities") or {}).values():
                if not 0 <= number(value) <= 1:
                    raise ValueError("invalid probability")
        elif kind == "score":
            value = number(answer.get("score"))
            if isinstance(question.get("criteria"), list) and not 0 <= value <= len(question["criteria"]) - 1:
                raise ValueError("score outside actual rubric")
        else:
            raise ValueError("native answer type not yet supported by bridge")


class NativeOutput:
    def __init__(self, root, target, runtime=os.environ.get("JEVPROBE_RUNTIME", "work/runtime")):
        self.root = Path(root).resolve()
        self.target = (self.root / target).resolve()
        self.runtime = (self.root / runtime).resolve()
        self.bun = self.runtime / "bun-npm/package/bin/bun"
        self.bridge = Path(__file__).with_name("native_bridge.ts")

    def initial(self, case, source):
        return {"tool": case["tool"], "task": case["task"], "source": source}

    def decision(self, case, ordinal, name, question, answer):
        if question["type"] != "noul":
            raise ValueError("output adapter expected native noul contract")
        return {"decision_id": f"output:{ordinal}:{name}", "value": answer["noul"], "native_answer": answer,
                "signal_type": "probability", "surface_type": "score",
                "contract": {"type": "score", "range": [0, 1],
                             "boundaries": [{"operator": ">=", "threshold": case.get("config", {}).get("security_threshold", .7)}]}}

    execution_scope = "native output guard and notice consumer; Pi host/agent not executed"

    def run(self, case, source, judge):
        # Child has no API credentials, PI state or model-service access configured.
        env = {k: v for k, v in os.environ.items() if not k.startswith("PI_") and
               not any(x in k.upper() for x in ("API_KEY", "TOKEN", "SECRET", "PASSWORD"))}
        env["BUN_CONFIG_NO_CLEAR_TERMINAL"] = "1"
        with tempfile.TemporaryDirectory(prefix="jevprobe-native-") as directory:
            env["PI_CODING_AGENT_DIR"] = directory
            with tempfile.TemporaryFile(mode="w+t") as errors:
                process = subprocess.Popen([str(self.bun), "--no-install", str(self.bridge), str(self.target), str(self.runtime)],
                    cwd=directory, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=errors, text=True, bufsize=1)
                requests, decisions = [], []
                try:
                    process.stdin.write(json.dumps(self.initial(case, source)) + "\n")
                    process.stdin.flush()
                    deadline = time.monotonic() + 180
                    selector = selectors.DefaultSelector()
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not selector.select(remaining):
                            raise TimeoutError("native bridge deadline")
                        line = process.stdout.readline()
                        if not line:
                            errors.seek(0)
                            detail = errors.read(1600)
                            raise RuntimeError("native bridge exited: " + detail)
                        message = json.loads(line)
                        if message["kind"] == "result":
                            process.wait(timeout=5)
                            return {"requests": requests, "decisions": decisions,
                                    "behavior": message["behavior"], "native_verdict": message["verdict"],
                                    "native_config": message["config"], "source_hash": digest(source),
                                    "execution_scope": self.execution_scope}
                        if message["kind"] != "request":
                            raise ValueError("unexpected native bridge message")
                        request = message["request"]
                        response, attempt = judge(request, message["ordinal"])
                        validate_response(request, response)
                        requests.append({"ordinal": message["ordinal"], "request": request,
                                         "request_hash": digest(request), "attempt_id": attempt,
                                         "response": response})
                        for name, question in request["questions"].items():
                            answer = response["answers"][name]
                            decisions.append(self.decision(case, message["ordinal"], name, question, answer))
                        process.stdin.write(json.dumps({"kind": "response", "response": response}) + "\n")
                        process.stdin.flush()
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)
                    process.stdin.close()
                    process.stdout.close()


class NativeFilter(NativeOutput):
    """Official optional context filter; exact native chunking and selection."""
    execution_scope = ("native filterOutput and selectChunks; optional feature off by default; "
                       "transport serialized; extension recall/footer and downstream agent not executed")

    def __init__(self, root, target, runtime=os.environ.get("JEVPROBE_RUNTIME", "work/runtime")):
        super().__init__(root, target, runtime)
        self.bridge = Path(__file__).with_name("native_filter_bridge.ts")

    def initial(self, case, source):
        return {**super().initial(case, source),
                "command": case.get("command"), "plan": case.get("plan")}

    def decision(self, case, ordinal, name, question, answer):
        if question["type"] != "score" or len(question["criteria"]) != 4:
            raise ValueError("filter adapter expected native four-level score rubric")
        return {"decision_id": f"filter:chunk:{name}", "value": answer["score"], "native_answer": answer,
                "signal_type": "score", "surface_type": "score",
                "source_location": {"request_ordinal": ordinal, "field": "state." + name},
                "contract": {"type": "score", "range": [0, 3],
                             "boundaries": [{"operator": ">=", "threshold": 1.5}]},
                "consumer_notes": "Eligibility boundary only; ranking, 6000-character budget and always-kept tail additionally control native text selection"}


def offline_response(request, ordinal):
    """Transport capture/control only; never a natural measurement."""
    return {"answers": {name: {"type": question["type"], "noul": 0}
                        for name, question in request["questions"].items()},
            "model": "offline_capture_only", "usage": {}, "elapsedMs": 0}, None
