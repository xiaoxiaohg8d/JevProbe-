"""Bounded transport with durable preflight reservations and no hidden retries."""
from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request

from .store import canonical


class RecordedHTTPError(RuntimeError):
    def __init__(self, status, attempt_id):
        self.status, self.attempt_id = status, attempt_id
        super().__init__(f"HTTP {status}; ledger attempt {attempt_id}")


def json_request(store, scopes, context, url, payload, headers=None, retries=0,
                 timeout=60, opener=None, validate=None, cost_units=None):
    """Only 429/502/503/504 retry; ambiguous timeouts and invalid outputs stop.

    Headers, raw provider error bodies, URL queries and exception messages are
    deliberately excluded from the ledger to avoid credential disclosure.
    """
    opener = opener or urllib.request.urlopen
    if retries not in range(3):
        raise ValueError("retries must be 0..2")
    body = canonical(payload).encode() if payload is not None else None
    # UTF-8 bytes are a conservative input-token reservation, not measured usage.
    estimated_tokens = len(body or url.encode()) + (payload or {}).get("max_tokens", 0)
    for number in range(retries + 1):
        attempt = store.reserve(scopes, {**context, "attempt_number": number + 1},
                                {"url": url.split("?")[0], "body": payload,
                                 "request_query_hash": __import__("hashlib").sha256(url.encode()).hexdigest()},
                                tokens=estimated_tokens, cost_units=cost_units)
        request = urllib.request.Request(url, data=body, headers=headers or {})
        try:
            with opener(request, timeout=timeout) as response:
                answer = json.load(response)
                response_meta = {k.lower(): v for k, v in response.headers.items()
                                 if k.lower().startswith("x-ratelimit-") or k.lower() in {"retry-after", "date", "etag", "x-request-id"}}
            if validate:
                validate(answer)
        except urllib.error.HTTPError as error:
            store.settle(attempt, "http_error", {"http_status": error.code})
            if error.code in {429, 502, 503, 504} and number < retries:
                time.sleep(min(2 ** number, 4))
                continue
            raise RecordedHTTPError(error.code, attempt) from None
        except (TimeoutError, socket.timeout, urllib.error.URLError, OSError) as error:
            store.settle(attempt, "unknown", {"error_type": type(error).__name__, "may_have_been_processed": True})
            raise RuntimeError(f"ambiguous transport error; attempt {attempt}; no automatic retry") from None
        except Exception as error:
            store.settle(attempt, "contract_error", {"error_type": type(error).__name__})
            raise RuntimeError(f"response contract error; attempt {attempt}; no automatic retry") from None
        store.settle(attempt, "success", {"response": answer, "headers": response_meta}, answer.get("usage"))
        return answer, attempt
    raise AssertionError("unreachable")
