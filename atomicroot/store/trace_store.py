"""SQLite policy state, version vector, event provenance, and atomic Commit."""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator


@dataclass
class CommitResult:
    status: str
    version_before: dict[str, int] = field(default_factory=dict)
    version_after: dict[str, int] = field(default_factory=dict)
    result_ref: str | None = None
    stale_keys: list[str] = field(default_factory=list)
    expected: dict[str, int] = field(default_factory=dict)
    actual: dict[str, int] = field(default_factory=dict)


class Snapshot:
    """A single SQLite read transaction. Missing keys have version zero."""

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    def read(self, key: str, default: Any = None) -> tuple[int, Any]:
        row = self._conn.execute(
            "SELECT version, value FROM conflict_keys WHERE key = ?", (key,)
        ).fetchone()
        return (row[0], json.loads(row[1])) if row else (0, default)

    def version(self, key: str) -> int:
        return self.read(key)[0]

    def events(self, task_id: str, tool: str | None = None) -> list[dict[str, Any]]:
        if tool is None:
            rows = self._conn.execute(
                "SELECT seq,event_id,task_id,agent_id,tool,args_hash,ticket_id,write_set,timestamp,args "
                "FROM trace_events WHERE task_id=? ORDER BY seq", (task_id,)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT seq,event_id,task_id,agent_id,tool,args_hash,ticket_id,write_set,timestamp,args "
                "FROM trace_events WHERE task_id=? AND tool=? ORDER BY seq", (task_id, tool)
            ).fetchall()
        names = ("seq", "event_id", "task_id", "agent_id", "tool", "args_hash",
                 "ticket_id", "write_set", "timestamp", "args")
        return [dict(zip(names, row)) for row in rows]


class TraceStore:
    """Each instance has its own connection; SQLite serializes writers across instances."""

    def __init__(self, db_path: str = ":memory:", *, clock=None):
        self._conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._lock = threading.RLock()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._create_tables()

    def _create_tables(self):
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS conflict_keys (
                    key TEXT PRIMARY KEY, version INTEGER NOT NULL DEFAULT 0,
                    value TEXT NOT NULL DEFAULT 'null');
                CREATE TABLE IF NOT EXISTS trace_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    task_id TEXT NOT NULL, agent_id TEXT NOT NULL, tool TEXT NOT NULL,
                    args_hash TEXT NOT NULL, ticket_id TEXT NOT NULL UNIQUE,
                    nonce TEXT UNIQUE, write_set TEXT NOT NULL, timestamp TEXT NOT NULL,
                    args TEXT NOT NULL DEFAULT '{}');
            """)

    @contextmanager
    def snapshot(self) -> Iterator[Snapshot]:
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                snap = Snapshot(self._conn)
                self._conn.execute("SELECT COUNT(*) FROM conflict_keys").fetchone()
                yield snap
            finally:
                self._conn.execute("ROLLBACK")

    def get_version(self, key: str) -> int:
        with self.snapshot() as snap:
            return snap.version(key)

    def get_versions(self, keys: list[str]) -> dict[str, int]:
        with self.snapshot() as snap:
            return {key: snap.version(key) for key in keys}

    def get_state(self, key: str, default: Any = None) -> Any:
        with self.snapshot() as snap:
            return snap.read(key, default)[1]

    def ensure_key(self, key: str, initial_version: int = 0) -> None:
        with self._lock:
            self._conn.execute("INSERT OR IGNORE INTO conflict_keys(key,version) VALUES (?,?)",
                               (key, initial_version))

    def set_version(self, key: str, version: int) -> None:
        """Test setup only. Production state changes use set_state/commit."""
        if type(version) is not int or version < 0:
            raise ValueError("invalid version")
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute("SELECT version FROM conflict_keys WHERE key=?", (key,)).fetchone()
                if row and version < row[0]:
                    raise ValueError("conflict key versions cannot decrease")
                self._conn.execute("INSERT INTO conflict_keys(key,version) VALUES (?,?) "
                                   "ON CONFLICT(key) DO UPDATE SET version=excluded.version",
                                   (key, version))
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def set_state(self, key: str, value: Any) -> None:
        """Trusted configuration mutation; every change bumps the conflict key."""
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute("SELECT value FROM conflict_keys WHERE key=?", (key,)).fetchone()
                if row is None:
                    self._conn.execute("INSERT INTO conflict_keys(key,version,value) VALUES (?,1,?)",
                                       (key, encoded))
                elif row[0] != encoded:
                    self._conn.execute("UPDATE conflict_keys SET version=version+1,value=? WHERE key=?",
                                       (encoded, key))
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def initialize_state(self, key: str, value: Any) -> None:
        """Trusted initial definition at version zero, never overwrite existing state."""
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        with self._lock:
            self._conn.execute("INSERT OR IGNORE INTO conflict_keys(key,version,value) VALUES (?,0,?)",
                               (key, encoded))

    def register_task_state(self, task_id: str, budget_cap: int) -> None:
        """Publish contract and official initial taint/spend in one transaction."""
        contract_key = f"contract:{task_id}"
        encoded = json.dumps({"budget_cap": budget_cap}, sort_keys=True, separators=(",", ":"))
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                contract = self._conn.execute("SELECT value FROM conflict_keys WHERE key=?",
                                              (contract_key,)).fetchone()
                for key, initial in [(f"taint:{task_id}", "[]"), (f"budget:{task_id}", "0")]:
                    row = self._conn.execute("SELECT value FROM conflict_keys WHERE key=?", (key,)).fetchone()
                    if row is None:
                        if contract is not None:
                            raise ValueError(f"missing existing task state: {key}; explicit migration required")
                        self._conn.execute("INSERT INTO conflict_keys(key,version,value) VALUES (?,0,?)",
                                           (key, initial))
                if contract is None:
                    self._conn.execute("INSERT INTO conflict_keys(key,version,value) VALUES (?,1,?)",
                                       (contract_key, encoded))
                elif contract[0] != encoded:
                    self._conn.execute("UPDATE conflict_keys SET version=version+1,value=? WHERE key=?",
                                       (encoded, contract_key))
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def commit(self, footprint: dict[str, int], write_set: list[str],
               event_data: dict[str, Any], *, skip_freshness_check: bool = False) -> CommitResult:
        """Fresh, consume ticket_id/nonce, append, update state, bump versions atomically."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if self._conn.execute("SELECT 1 FROM conflict_keys WHERE key=?",
                                      (f"contract3:{event_data['task_id']}",)).fetchone():
                    raise ValueError("Phase 3 task requires IntentGateway and transactional outbox")
                keys = set(footprint) | set(write_set)
                before = {}
                for key in keys:
                    row = self._conn.execute("SELECT version FROM conflict_keys WHERE key=?", (key,)).fetchone()
                    before[key] = row[0] if row else 0
                stale = [key for key, ver in footprint.items() if before[key] != ver]
                if stale and not skip_freshness_check:
                    self._conn.execute("ROLLBACK")
                    return CommitResult("STALE_TICKET", before, stale_keys=stale,
                                        expected={k: footprint[k] for k in stale},
                                        actual={k: before[k] for k in stale})
                if "not_before" in event_data and "not_after" in event_data:
                    start = datetime.fromisoformat(event_data["not_before"].replace("Z", "+00:00"))
                    end = datetime.fromisoformat(event_data["not_after"].replace("Z", "+00:00"))
                    now = self._clock()
                    if start.tzinfo is None or end.tzinfo is None or not (start <= now <= end):
                        self._conn.execute("ROLLBACK")
                        return CommitResult("EXPIRED")
                args = event_data.get("args", {})
                task_id = event_data["task_id"]
                tool = event_data["tool"]
                membership_key = f"policies:{tool}"
                membership = self._conn.execute("SELECT version FROM conflict_keys WHERE key=?",
                                                (membership_key,)).fetchone()
                if membership is not None and membership_key not in footprint:
                    raise ValueError("missing policy membership dependency; reauthorize ticket")
                if tool in {"transfer_funds", "make_payment", "purchase"}:
                    amount = args.get("amount")
                    if type(amount) is not int or amount < 0 or f"budget:{task_id}" not in write_set:
                        raise ValueError("invalid or untracked spend")
                if tool == "read_document":
                    doc_id = args.get("doc_id")
                    row = self._conn.execute("SELECT value FROM conflict_keys WHERE key=?",
                                             (f"class:{doc_id}",)).fetchone()
                    if row:
                        data_class = json.loads(row[0])
                        if args.get("data_class", data_class) != data_class:
                            raise ValueError("document classification mismatch")
                        if data_class in {"finance", "sensitive"} and f"taint:{task_id}" not in write_set:
                            raise ValueError("missing taint write")
                    else:
                        data_class = None
                else:
                    data_class = None
                recorded_args = dict(args)
                if data_class is not None:
                    recorded_args["_resolved_data_class"] = data_class
                self._conn.execute(
                    "INSERT INTO trace_events(event_id,task_id,agent_id,tool,args_hash,ticket_id,nonce,write_set,timestamp,args) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (event_data.get("event_id", f"ev-{uuid.uuid4().hex}"), task_id,
                     event_data["agent_id"], tool, event_data["args_hash"],
                     event_data["ticket_id"], event_data.get("nonce"),
                     json.dumps(write_set), event_data.get("timestamp", ""), json.dumps(recorded_args, sort_keys=True)))
                if data_class in {"finance", "sensitive"}:
                    key = f"taint:{task_id}"
                    row = self._conn.execute("SELECT value FROM conflict_keys WHERE key=?", (key,)).fetchone()
                    classes = set(json.loads(row[0])) if row and row[0] != "null" else set()
                    classes.add(data_class)
                    self._put_value(key, sorted(classes))
                if tool in {"transfer_funds", "make_payment", "purchase"}:
                    key = f"budget:{task_id}"
                    row = self._conn.execute("SELECT value FROM conflict_keys WHERE key=?", (key,)).fetchone()
                    spend = json.loads(row[0]) if row and row[0] != "null" else 0
                    self._put_value(key, spend + amount)
                after = dict(before)
                for key in dict.fromkeys(write_set):
                    self._conn.execute("INSERT INTO conflict_keys(key,version) VALUES (?,1) "
                                       "ON CONFLICT(key) DO UPDATE SET version=version+1", (key,))
                    after[key] = before[key] + 1
                self._conn.execute("COMMIT")
                return CommitResult("COMMITTED", before, after, f"res-{uuid.uuid4().hex[:8]}")
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                if "ticket_id" in str(exc) or "nonce" in str(exc):
                    return CommitResult("REPLAY")
                raise
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def _put_value(self, key: str, value: Any) -> None:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
        self._conn.execute("INSERT INTO conflict_keys(key,value) VALUES (?,?) "
                           "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, encoded))

    def get_trace(self, task_id: str | None = None) -> list[dict[str, Any]]:
        with self.snapshot() as snap:
            if task_id is not None:
                return snap.events(task_id)
            rows = snap._conn.execute("SELECT DISTINCT task_id FROM trace_events").fetchall()
            return sorted((event for (tid,) in rows for event in snap.events(tid)),
                          key=lambda event: event["seq"])

    def close(self):
        self._conn.close()
