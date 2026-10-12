"""Leased at-least-once dispatch and a durable, deduplicating dummy receiver."""
import json

from atomicroot.authority.ticket import args_hash, freeze_json
from atomicroot.authority.policy_engine import money_integer
from atomicroot.framework.storage import dumps, uid
from atomicroot.framework.registry import TOOLS


class SimulatedReceiver:
    """Dedupe, simulated state mutation and receipt are ONE durable transaction."""
    def __init__(self, store, *, definite_failures=frozenset()):
        self.store = store
        self.definite_failures = frozenset(definite_failures)  # trusted fault fixture

    def deliver(self, task, operation, payload):
        payload = freeze_json(payload)
        digest = args_hash(payload)
        with self.store.transaction() as conn:
            row = self.store.row(conn, "SELECT * FROM receiver_receipts WHERE task=? AND operation=?", (task, operation))
            if row:
                if row["digest"] != digest: raise ValueError("receiver operation payload mismatch")
                return json.loads(row["receipt"])
            if (task, operation) in self.definite_failures:
                receipt = {"outcome": "FAILED", "absence_proven": True, "receipt_id": uid("receipt")}
            else:
                tool, args = payload["tool"], payload["args"]
                simulator = TOOLS[tool].effect_class
                if simulator == "send":
                    key = f"email:{task}:{operation}"
                    result = {"to": args["to"], "body": args["body"]}
                elif simulator == "transfer":
                    key = f"account:{args['to']}"
                    previous = conn.execute("SELECT value FROM receiver_state WHERE key=?", (key,)).fetchone()
                    balance = json.loads(previous[0])["balance"] if previous else 0
                    result = {"balance": balance + args["amount"], "last_operation": operation}
                elif simulator == "deploy":
                    key = f"deployment:{args['to']}"
                    result = {"resource": args["resource"], "digest": args["digest"], "operation": operation}
                elif simulator == "read":
                    key = f"read:{task}:{operation}"
                    result = {"content": payload["resource_snapshot"]["content"], "digest": args["digest"],
                              "instruction_trust": "UNTRUSTED", "factual_accuracy": "UNVERIFIED"}
                elif simulator == "classification":
                    key = f"inference:{task}:{operation}"
                    result = {"provider": args["to"], "resource": args["resource"], "digest": args["digest"],
                              "outcome": "OFFLINE_SIMULATION", "candidate_label": "UNKNOWN"}
                else:
                    raise ValueError("receiver has no registered simulator")
                conn.execute("INSERT INTO receiver_state(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                             (key, dumps(result)))
                receipt = {"outcome": "DELIVERED", "receipt_id": uid("receipt"), "result": result}
            conn.execute("INSERT INTO receiver_receipts(task,operation,digest,receipt) VALUES (?,?,?,?)",
                         (task, operation, digest, dumps(receipt)))
        return receipt


class Dispatcher:
    def __init__(self, store, receiver, *, lease_seconds=30):
        if not 0 < lease_seconds <= 300: raise ValueError("invalid lease")
        self.store, self.receiver, self.lease_seconds = store, receiver, lease_seconds

    def claim(self, *, task=None, operation=None):
        if (task is None) != (operation is None): raise ValueError("task and operation required together")
        with self.store.transaction() as conn:
            now = self.store.now()
            # Expiry does not prove absence of an effect. Keep reservation bound.
            conn.execute("UPDATE outbox SET status='UNKNOWN',lease=NULL,lease_until=NULL,error='lease expired; reconcile by idempotent retry' "
                         "WHERE status='RELEASING' AND lease_until<=?", (now,))
            where, params = ("", ()) if task is None else (" AND task=? AND operation=?", (task, operation))
            row = self.store.row(conn, "SELECT * FROM outbox WHERE status IN ('PENDING','UNKNOWN')" + where + " ORDER BY rowid LIMIT 1", params)
            if row is None: return None
            lease = uid("lease")
            conn.execute("UPDATE outbox SET status='RELEASING',lease=?,lease_until=?,attempts=attempts+1 WHERE task=? AND operation=?",
                         (lease, now + self.lease_seconds, row["task"], row["operation"]))
            return {**row, "lease": lease, "status": "RELEASING", "attempts": row["attempts"] + 1}

    def finish(self, claim, receipt=None, *, error=None):
        with self.store.transaction() as conn:
            row = self.store.row(conn, "SELECT * FROM outbox WHERE task=? AND operation=?", (claim["task"], claim["operation"]))
            if row is None or row["status"] != "RELEASING" or row["lease"] != claim["lease"]:
                return {"status": "IGNORED", "reason": "lease superseded"}
            delivered = receipt is not None and receipt.get("outcome") == "DELIVERED"
            absent = receipt is not None and receipt.get("outcome") == "FAILED" and receipt.get("absence_proven") is True
            if not delivered and not absent:
                conn.execute("UPDATE outbox SET status='UNKNOWN',lease=NULL,lease_until=NULL,error=? WHERE task=? AND operation=?",
                             (error or "ambiguous receiver outcome", row["task"], row["operation"]))
                return {"status": "UNKNOWN"}
            # Only receipts committed by the registered receiver can settle the ledger.
            proof = conn.execute("SELECT receipt FROM receiver_receipts WHERE task=? AND operation=?", (row["task"], row["operation"])).fetchone()
            if proof is None or json.loads(proof[0]) != receipt:
                raise ValueError("unverified receiver settlement receipt")
            amount = row["amount"]
            if amount:
                reserved_key, used_key = f"reserved:{row['task']}", f"budget:{row['task']}"
                reserved = money_integer(self.store.value(conn, reserved_key)[1])
                if reserved < amount: raise ValueError("reservation invariant violated")
                self.store.put(conn, reserved_key, reserved - amount)
                if delivered:
                    used = money_integer(self.store.value(conn, used_key)[1])
                    self.store.put(conn, used_key, money_integer(used + amount))
            status = "RELEASED" if delivered else "FAILED"
            conn.execute("UPDATE outbox SET status=?,receipt=?,error=NULL,lease=NULL,lease_until=NULL WHERE task=? AND operation=?",
                         (status, dumps(receipt), row["task"], row["operation"]))
            self.store.audit(conn, "SETTLEMENT", "Dispatcher", {"task": row["task"], "operation": row["operation"],
                                                                  "amount": amount, "status": status, "receipt": receipt["receipt_id"]})
            return {"status": status, "receipt": receipt}

    def dispatch_once(self, *, lose_ack=False):
        claim = self.claim()
        if claim is None: return {"status": "IDLE"}
        try:
            # Deliberately outside the claim/settlement transactions.
            receipt = self.receiver.deliver(claim["task"], claim["operation"], json.loads(claim["payload"]))
            if lose_ack: raise TimeoutError("simulated lost acknowledgement")
        except Exception as exc:
            return self.finish(claim, error=str(exc))
        return self.finish(claim, receipt)
