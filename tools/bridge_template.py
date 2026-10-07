"""Generate standard httpx2-patch bridges for Python SDK projects.

Each bridge: stdin {"text"} → TypeSafeClient.system_one(Choice+Noul) →
stdout {"kind":"result","answers":{...}}. Works with SdkTextAdapter."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

BRIDGE_TEMPLATE = '''"""Transport-only seam for {repo}: httpx2 patch stdio relay."""
import json
import os
import sys
from pathlib import Path

for key in list(os.environ):
    if key.lower().endswith("_proxy") or key.lower() in ("all_proxy", "no_proxy"):
        del os.environ[key]

TARGET = Path(sys.argv[1])
sys.path.insert(0, str(TARGET))
os.environ.setdefault("TYPESAFE_API_KEY", "relay-key")

ordinal = 0


def _relay(self, method, url, json_body=None, content=None, **kw):
    global ordinal
    if "systemone" not in str(url):
        return _orig_request(self, method, url, json=json_body, content=content, **kw)
    body = json_body
    if body is None and isinstance(content, (bytes, bytearray)):
        body = json.loads(content.decode("utf8"))
    sys.stdout.write(json.dumps({{"kind": "request", "ordinal": ordinal, "url": str(url), "request": body}}) + "\\n")
    sys.stdout.flush()
    line = sys.stdin.readline()
    if not line:
        raise RuntimeError("relay closed")
    reply = json.loads(line)
    ordinal += 1
    return httpx2.Response(200, headers={{"content-type": "application/json"}},
                           content=json.dumps(reply["response"]).encode(),
                           request=httpx2.Request(method, str(url)))


import httpx2
_orig_request = httpx2.Client.request
httpx2.Client.request = _relay
httpx2.Client.post = lambda s, u, **kw: _relay(s, "POST", u, **kw)

from typesafe_sdk import TypeSafeClient, Choice, Noul

initial = json.loads(sys.stdin.readline())
client = TypeSafeClient(api_key="relay-key", timeout=30)
r = client.system_one(
    state={{"text": initial["text"]}},
    model="jev-latest",
    questions={{
        "classification": Choice(
            instructions="Classify this text into the most appropriate category",
            criteria={{"positive": "Positive or successful outcome",
                      "negative": "Negative or problematic outcome",
                      "neutral": "Neutral or informational"}},
        ),
        "confidence": Noul(
            instructions="This text can be used safely for its stated purpose",
        ),
    }},
)
answers = {{k: {{"type": v.type, "choice": getattr(v, "choice", None),
                "noul": getattr(v, "noul", None), "score": getattr(v, "score", None),
                "confidence": getattr(v, "confidence", None),
                "probabilities": getattr(v, "probabilities", None)}}
           for k, v in r.answers.items()}}
sys.stdout.write(json.dumps({{"kind": "result", "answers": answers}}) + "\\n")
sys.stdout.flush()
'''


def generate(repo_id):
    short = repo_id.split("/")[-1].replace("-", "_").replace(".", "_")[:20]
    bridge_path = ROOT / f"jevsec/ecosystem/s17_{short}_bridge.py"
    if bridge_path.exists():
        return bridge_path, "exists"
    bridge_path.write_text(BRIDGE_TEMPLATE.format(repo=repo_id))
    return bridge_path, "created"


if __name__ == "__main__":
    for repo in sys.argv[1:]:
        path, status = generate(repo)
        print(f"  {status}: {path.name} for {repo}")
