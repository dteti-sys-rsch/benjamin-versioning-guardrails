"""One-use durable reviews, with distinct contract and operation bindings."""
import json
from atomicroot.framework.storage import dumps, uid


class ApprovalBroker:
    def __init__(self, store): self.store = store

    def create(self, conn, kind, task, data, *, ttl=300):
        if kind not in {"contract", "operation"} or not 0 < ttl <= 3600:
            raise ValueError("invalid review kind/expiry")
        review_id = uid("review")
        data = {**data, "required_role": "approver", "task_id": task}
        conn.execute("INSERT INTO reviews(id,kind,task,status,expires,data) VALUES (?,?,?,'PENDING',?,?)",
                     (review_id, kind, task, self.store.now() + ttl, dumps(data)))
        return review_id

    def _get(self, conn, review_id):
        row = self.store.row(conn, "SELECT * FROM reviews WHERE id=?", (review_id,))
        if row is None: raise ValueError("unknown review")
        row["data"] = json.loads(row["data"])
        return row

    def status(self, review_id, principal):
        with self.store.snapshot() as snapshot:
            row = self._get(snapshot._conn, review_id)
            stale = self.store.stale(snapshot._conn, row["data"]["footprint"])
            row["effective_status"] = row["status"]
            if row["status"] in {"PENDING", "APPROVED"}:
                if self.store.now() >= row["expires"]: row["effective_status"] = "EXPIRED"
                elif stale: row["effective_status"] = "STALE"
            row["stale_keys"] = stale
        if row["task"] not in principal.tasks: raise PermissionError("task outside authenticated scope")
        if "approver" not in principal.roles and principal.subject != row["data"].get("agent_id"):
            raise PermissionError("review not owned by caller")
        return row

    def decide(self, review_id, approve, principal):
        if type(approve) is not bool: raise ValueError("approve must be boolean")
        with self.store.transaction() as conn:
            row = self._get(conn, review_id)
            principal.require("approver", task=row["task"])
            if row["status"] != "PENDING": raise ValueError("review already decided or consumed")
            if self.store.now() >= row["expires"]: raise ValueError("review expired")
            stale = self.store.stale(conn, row["data"]["footprint"])
            if stale: raise ValueError("review stale; new preview required: " + ",".join(stale))
            status = "APPROVED" if approve else "REJECTED"
            conn.execute("UPDATE reviews SET status=?,approver=? WHERE id=?", (status, principal.subject, review_id))
            if row["kind"] == "operation" and approve:
                data = row["data"]
                key = f"consent:{row['task']}:{data['operation_id']}"
                # Infrastructure transition only: business Footprint stays pinned.
                self.store.put(conn, key, {"status": status, "review_id": review_id})
            self.store.audit(conn, "REVIEW_" + status, principal.subject, {"review_id": review_id, "kind": row["kind"]})
        return {"review_id": review_id, "status": status}

    def validate_grant(self, conn, review_id, kind, task, digest, *, agent=None, operation=None, tool=None):
        row = self._get(conn, review_id)
        data = row["data"]
        if row["kind"] != kind or row["task"] != task or data["digest"] != digest:
            raise ValueError("grant binding mismatch")
        if row["status"] != "APPROVED" or not row["approver"] or self.store.now() >= row["expires"]:
            raise ValueError("grant unavailable, replayed or expired")
        if self.store.stale(conn, data["footprint"]): raise ValueError("grant stale; new review required")
        if kind == "operation":
            if (data["agent_id"], data["operation_id"], data["tool"]) != (agent, operation, tool):
                raise ValueError("grant operation/identity mismatch")
            _, consent = self.store.value(conn, f"consent:{task}:{operation}")
            if consent != {"status": "APPROVED", "review_id": review_id}:
                raise ValueError("grant superseded or consumed")
        return row

    def consume(self, conn, review_id):
        updated = conn.execute("UPDATE reviews SET status='CONSUMED' WHERE id=? AND status='APPROVED'", (review_id,))
        if updated.rowcount != 1: raise ValueError("grant not consumable")
