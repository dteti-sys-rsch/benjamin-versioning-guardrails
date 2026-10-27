"""Phase 3 tables share the existing Trace Store SQLite database and lock."""
from contextlib import contextmanager
import uuid
from threading import local

from atomicroot.store.trace_store import TraceStore, Snapshot
from atomicroot.authority.ticket import canonical_json_bytes
from atomicroot.authority.policy_engine import MAX_STATE_BYTES
from atomicroot.framework.contention import coordinator_for


def dumps(value):
    return canonical_json_bytes(value).decode("utf-8")


def uid(prefix):
    return prefix + "-" + uuid.uuid4().hex


class FrameworkStore(TraceStore):
    def __init__(self, db_path=":memory:", *, id_factory=None, harness=None, **kwargs):
        self.coordinator = coordinator_for(db_path)
        self.new_id = id_factory or uid
        self.harness = harness
        self._instrumentation = local()
        super().__init__(db_path, **kwargs)
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS proposals (
                id TEXT PRIMARY KEY, task TEXT NOT NULL, digest TEXT NOT NULL,
                base INTEGER NOT NULL, status TEXT NOT NULL, data TEXT NOT NULL,
                review TEXT NOT NULL, activated_version INTEGER);
            CREATE TABLE IF NOT EXISTS reviews (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, task TEXT NOT NULL,
                status TEXT NOT NULL, expires REAL NOT NULL, data TEXT NOT NULL,
                approver TEXT);
            CREATE TABLE IF NOT EXISTS operations (
                task TEXT NOT NULL, operation TEXT NOT NULL, agent TEXT NOT NULL,
                digest TEXT NOT NULL, request TEXT NOT NULL,
                PRIMARY KEY(task,operation));
            CREATE TABLE IF NOT EXISTS authorizations (
                ticket TEXT PRIMARY KEY, task TEXT NOT NULL, operation TEXT NOT NULL,
                data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS outbox (
                task TEXT NOT NULL, operation TEXT NOT NULL, ticket TEXT NOT NULL UNIQUE,
                agent TEXT NOT NULL, digest TEXT NOT NULL, payload TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('PENDING','RELEASING','RELEASED','UNKNOWN','FAILED')),
                attempts INTEGER NOT NULL DEFAULT 0, lease TEXT, lease_until REAL,
                receipt TEXT, error TEXT, amount INTEGER NOT NULL,
                PRIMARY KEY(task,operation));
            CREATE TABLE IF NOT EXISTS service_events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL,
                actor TEXT NOT NULL, data TEXT NOT NULL, timestamp REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS receiver_receipts (
                task TEXT NOT NULL, operation TEXT NOT NULL, digest TEXT NOT NULL,
                receipt TEXT NOT NULL, PRIMARY KEY(task,operation));
            CREATE TABLE IF NOT EXISTS receiver_state (
                key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS classification_proposals (
                id TEXT PRIMARY KEY, resource TEXT NOT NULL,
                status TEXT NOT NULL, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS resolved_tasks (
                id TEXT PRIMARY KEY, task TEXT NOT NULL, digest TEXT NOT NULL,
                data TEXT NOT NULL);
        """)

    @contextmanager
    def transaction(self):
        # Admission always precedes the connection lock; fallback never upgrades
        # from a transaction. Every framework writer uses this same boundary.
        with self.coordinator.acquire(), self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            self._instrumentation.events = []
            try:
                yield self._conn
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                self._instrumentation.events = []
                raise
            finally:
                events = self._instrumentation.events
                self._instrumentation.events = None
        for stage, action, task in events: self.observe(stage, action, task=task)

    def observe(self, stage, action=None, *, task=None):
        if self.harness is None: return
        events = getattr(self._instrumentation, "events", None)
        if events is not None:
            events.append((stage, action, task))
        elif self.coordinator.held_exclusively():
            pending = getattr(self._instrumentation, "deferred", None)
            if pending is None: self._instrumentation.deferred = pending = []
            pending.append((stage, action, task))
        else:
            callback = getattr(self.harness, "context_checkpoint", None)
            if callback: callback(stage, action, task=task)
            else: self.harness.checkpoint(stage, action)

    def flush_observations(self):
        pending = getattr(self._instrumentation, "deferred", [])
        self._instrumentation.deferred = []
        for stage, action, task in pending:
            if callback := getattr(self.harness, "context_checkpoint", None):
                callback(stage, action, task=task, deferred=True)
                continue
            callback = getattr(self.harness, "deferred_checkpoint", None)
            if callback: callback(stage, action)
            else: self.observe(stage, action)

    def set_state(self, key, value):
        with self.transaction() as conn:
            row = conn.execute("SELECT value FROM conflict_keys WHERE key=?", (key,)).fetchone()
            if row is None or row[0] != dumps(value): self.put(conn, key, value)

    def initialize_state(self, key, value):
        with self.transaction() as conn: self.put(conn, key, value, initial=True)

    def set_version(self, key, version):
        with self.coordinator.acquire(): super().set_version(key, version)

    def ensure_key(self, key, initial_version=0):
        with self.coordinator.acquire(): super().ensure_key(key, initial_version)

    def register_task_state(self, task_id, budget_cap):
        with self.coordinator.acquire(): super().register_task_state(task_id, budget_cap)

    def commit(self, *args, **kwargs):
        with self.coordinator.acquire(): return super().commit(*args, **kwargs)

    def now(self):
        return self._clock().timestamp()

    @staticmethod
    def value(conn, key):
        return Snapshot(conn).read(key)

    def put(self, conn, key, value, *, initial=False):
        encoded = dumps(value)
        if len(encoded.encode("utf-8")) > MAX_STATE_BYTES:
            raise ValueError("fact exceeds state size limit")
        if initial:
            inserted = conn.execute("INSERT OR IGNORE INTO conflict_keys(key,version,value) VALUES (?,0,?)", (key, encoded))
            if inserted.rowcount == 0: return
        else:
            conn.execute("INSERT INTO conflict_keys(key,version,value) VALUES (?,1,?) "
                         "ON CONFLICT(key) DO UPDATE SET version=version+1,value=excluded.value", (key, encoded))
        self.observe("mutation:" + key.split(":", 1)[0], key)

    @staticmethod
    def stale(conn, footprint):
        return [k for k, v in footprint.items() if Snapshot(conn).version(k) != v]

    def audit(self, conn, kind, actor, data):
        conn.execute("INSERT INTO service_events(kind,actor,data,timestamp) VALUES (?,?,?,?)",
                     (kind, actor, dumps(data), self.now()))
        self.observe("service:" + kind, actor)

    @staticmethod
    def row(conn, sql, args=()):
        cursor = conn.execute(sql, args)
        row = cursor.fetchone()
        return dict(zip((c[0] for c in cursor.description), row)) if row else None

    def inspect_outbox(self):
        with self._lock:
            return [self.row(self._conn, "SELECT * FROM outbox WHERE task=? AND operation=?", row)
                    for row in self._conn.execute("SELECT task,operation FROM outbox").fetchall()]
