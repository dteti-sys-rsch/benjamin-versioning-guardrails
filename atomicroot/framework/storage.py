"""Phase 3 tables share the existing Trace Store SQLite database and lock."""
from contextlib import contextmanager
import uuid

from atomicroot.store.trace_store import TraceStore, Snapshot
from atomicroot.authority.ticket import canonical_json_bytes
from atomicroot.authority.policy_engine import MAX_STATE_BYTES


def dumps(value):
    return canonical_json_bytes(value).decode("utf-8")


def uid(prefix):
    return prefix + "-" + uuid.uuid4().hex


class FrameworkStore(TraceStore):
    def __init__(self, db_path=":memory:", **kwargs):
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
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

    def now(self):
        return self._clock().timestamp()

    @staticmethod
    def value(conn, key):
        return Snapshot(conn).read(key)

    @staticmethod
    def put(conn, key, value, *, initial=False):
        encoded = dumps(value)
        if len(encoded.encode("utf-8")) > MAX_STATE_BYTES:
            raise ValueError("fact exceeds state size limit")
        if initial:
            conn.execute("INSERT OR IGNORE INTO conflict_keys(key,version,value) VALUES (?,0,?)", (key, encoded))
        else:
            conn.execute("INSERT INTO conflict_keys(key,version,value) VALUES (?,1,?) "
                         "ON CONFLICT(key) DO UPDATE SET version=version+1,value=excluded.value", (key, encoded))

    @staticmethod
    def stale(conn, footprint):
        return [k for k, v in footprint.items() if Snapshot(conn).version(k) != v]

    def audit(self, conn, kind, actor, data):
        conn.execute("INSERT INTO service_events(kind,actor,data,timestamp) VALUES (?,?,?,?)",
                     (kind, actor, dumps(data), self.now()))

    @staticmethod
    def row(conn, sql, args=()):
        cursor = conn.execute(sql, args)
        row = cursor.fetchone()
        return dict(zip((c[0] for c in cursor.description), row)) if row else None

    def inspect_outbox(self):
        with self._lock:
            return [self.row(self._conn, "SELECT * FROM outbox WHERE task=? AND operation=?", row)
                    for row in self._conn.execute("SELECT task,operation FROM outbox").fetchall()]
