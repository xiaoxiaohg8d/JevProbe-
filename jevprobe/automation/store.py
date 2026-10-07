"""Durable inputs, trials, diagnostics, and atomic multi-scope HTTP budgets.

Reservations are committed BEFORE transport. Ambiguous/crashed attempts remain
charged and cannot silently become successful trials on restart. SQLite is the
authoritative checkpoint; JSON exports are derived, never inference caches.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import time
import uuid


def now():
    return datetime.now(timezone.utc).isoformat()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class BudgetExceeded(RuntimeError):
    pass


class RecoveryRequired(RuntimeError):
    pass


class Store:
    def __init__(self, path, namespace=""):
        self.path = Path(path)
        self.namespace = namespace + ":" if namespace else ""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS budgets(scope TEXT PRIMARY KEY, config TEXT NOT NULL, started REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS inputs(id TEXT PRIMARY KEY, hash TEXT NOT NULL, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS attempts(
                id TEXT PRIMARY KEY, context TEXT NOT NULL, input_hash TEXT NOT NULL,
                started TEXT NOT NULL, ended TEXT, status TEXT NOT NULL,
                tokens INTEGER NOT NULL, cost INTEGER NOT NULL, usage TEXT, result TEXT);
            CREATE TABLE IF NOT EXISTS charges(attempt TEXT NOT NULL, scope TEXT NOT NULL,
                PRIMARY KEY(attempt,scope), FOREIGN KEY(attempt) REFERENCES attempts(id));
            CREATE TABLE IF NOT EXISTS trials(id TEXT PRIMARY KEY, status TEXT NOT NULL, data TEXT);
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, time TEXT NOT NULL, data TEXT NOT NULL);
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            yield db
        finally:
            db.close()

    @contextmanager
    def transaction(self):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def configure(self, scope, config):
        if not isinstance(config.get("max_attempts"), int) or isinstance(config["max_attempts"], bool) or config["max_attempts"] < 0:
            raise ValueError("an explicit nonnegative max_attempts is required")
        for name in ("max_tokens", "max_cost_units", "max_inflight", "max_runtime_s"):
            if config.get(name) is not None and (not isinstance(config[name], int) or isinstance(config[name], bool) or config[name] <= 0):
                raise ValueError(f"{name} must be a positive integer or null")
        if config.get("max_cost_units") is not None and not config.get("currency"):
            raise ValueError("monetary budget requires currency and integer cost units")
        encoded = canonical(config)
        with self.transaction() as db:
            old = db.execute("SELECT config FROM budgets WHERE scope=?", (scope,)).fetchone()
            if old and old["config"] != encoded:
                raise ValueError("budget configuration is immutable; create a new versioned scope")
            db.execute("INSERT OR IGNORE INTO budgets VALUES(?,?,?)", (scope, encoded, time.time()))

    def put_input(self, identifier, data):
        identifier = self.namespace + identifier
        encoded, hashed = canonical(data), digest(data)
        with self.transaction() as db:
            old = db.execute("SELECT hash FROM inputs WHERE id=?", (identifier,)).fetchone()
            if old and old["hash"] != hashed:
                raise ValueError(f"saved input/config changed: {identifier}")
            db.execute("INSERT OR IGNORE INTO inputs VALUES(?,?,?)", (identifier, hashed, encoded))
        return hashed

    def input(self, identifier):
        identifier = self.namespace + identifier
        with self.connect() as db:
            row = db.execute("SELECT data FROM inputs WHERE id=?", (identifier,)).fetchone()
        return json.loads(row["data"]) if row else None

    def reserve(self, scopes, context, payload, tokens=0, cost_units=None):
        if not isinstance(tokens, int) or isinstance(tokens, bool) or tokens < 0 or (cost_units is not None and
                (not isinstance(cost_units, int) or isinstance(cost_units, bool) or cost_units < 0)) or not scopes or len(scopes) != len(set(scopes)):
            raise ValueError("invalid reservation")
        identifier = str(uuid.uuid4())
        request_hash = self.put_input("request:" + digest(payload), payload)
        with self.transaction() as db:
            currencies = set()
            for scope in scopes:
                row = db.execute("SELECT * FROM budgets WHERE scope=?", (scope,)).fetchone()
                if not row:
                    raise BudgetExceeded(f"budget not configured: {scope}")
                limits = json.loads(row["config"])
                used = db.execute("""SELECT count(*) n, coalesce(sum(tokens),0) tokens,
                    coalesce(sum(cost),0) cost, coalesce(sum(status='reserved'),0) active
                    FROM attempts JOIN charges ON attempts.id=charges.attempt WHERE scope=?""", (scope,)).fetchone()
                if used["n"] >= limits["max_attempts"]:
                    raise BudgetExceeded(f"HTTP attempt limit: {scope}")
                if limits.get("max_tokens") is not None and (tokens <= 0 or used["tokens"] + tokens > limits["max_tokens"]):
                    raise BudgetExceeded(f"token limit or missing conservative estimate: {scope}")
                if limits.get("max_cost_units") is not None:
                    currencies.add(limits["currency"])
                    if cost_units is None or used["cost"] + cost_units > limits["max_cost_units"]:
                        raise BudgetExceeded(f"cost limit or unknown price: {scope}")
                if limits.get("max_inflight") is not None and used["active"] >= limits["max_inflight"]:
                    raise BudgetExceeded(f"concurrency limit: {scope}")
                if limits.get("max_runtime_s") is not None and time.time() - row["started"] >= limits["max_runtime_s"]:
                    raise BudgetExceeded(f"runtime limit: {scope}")
            if len(currencies) > 1:
                raise ValueError("cannot mix budget currencies")
            db.execute("INSERT INTO attempts(id,context,input_hash,started,status,tokens,cost) VALUES(?,?,?,?,?,?,?)",
                       (identifier, canonical(context), request_hash, now(), "reserved", tokens, cost_units or 0))
            db.executemany("INSERT INTO charges VALUES(?,?)", [(identifier, scope) for scope in scopes])
        return identifier

    def settle(self, identifier, status, result, usage=None):
        if status not in {"success", "http_error", "contract_error", "unknown"}:
            raise ValueError("invalid attempt status")
        with self.transaction() as db:
            row = db.execute("SELECT status FROM attempts WHERE id=?", (identifier,)).fetchone()
            if not row or row["status"] != "reserved":
                raise RecoveryRequired("attempt missing or already settled")
            # Keep conservative reservations; actual usage is separately recorded.
            db.execute("UPDATE attempts SET status=?,ended=?,result=?,usage=? WHERE id=?",
                       (status, now(), canonical(result), canonical(usage), identifier))

    def claim_trial(self, identifier):
        with self.transaction() as db:
            row = db.execute("SELECT * FROM trials WHERE id=?", (identifier,)).fetchone()
            if row:
                if row["status"] == "completed":
                    return json.loads(row["data"])
                raise RecoveryRequired(f"unresolved trial {identifier}: {row['status']}; explicit recovery required")
            db.execute("INSERT INTO trials VALUES(?,?,?)", (identifier, "running", None))
        return None

    def finish_trial(self, identifier, data, status="completed"):
        if status not in {"completed", "failed", "unknown"}:
            raise ValueError("invalid trial status")
        with self.transaction() as db:
            changed = db.execute("UPDATE trials SET status=?,data=? WHERE id=? AND status='running'",
                                 (status, canonical(data), identifier)).rowcount
            if changed != 1:
                raise RecoveryRequired("cannot overwrite a completed/unclaimed trial")

    def event(self, **data):
        data = {"batch_namespace": self.namespace, **data}
        with self.connect() as db:
            db.execute("INSERT INTO events(time,data) VALUES(?,?)", (now(), canonical(data)))

    def export(self):
        with self.connect() as db:
            output = {table: [dict(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY rowid")]
                      for table in ("budgets", "inputs", "attempts", "charges", "trials", "events")}
        for table, fields in {"budgets": ["config"], "inputs": ["data"], "attempts": ["context", "usage", "result"],
                              "trials": ["data"], "events": ["data"]}.items():
            for row in output[table]:
                for field in fields:
                    if row[field] is not None:
                        row[field] = json.loads(row[field])
        return output
