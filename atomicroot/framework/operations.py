"""Trusted read provenance and concrete intent observations, never worker facts."""
import json


def read_basis(store, conn, request):
    task, agent, args = request["task_id"], request["agent_id"], request["args"]
    row = store.row(conn, "SELECT o.operation,o.payload,o.receipt,r.receipt AS proof FROM outbox o JOIN receiver_receipts r "
        "ON o.task=r.task AND o.operation=r.operation WHERE o.task=? AND o.agent=? AND o.status='RELEASED' "
        "AND json_extract(r.receipt,'$.receipt_id')=?", (task, agent, args["read_receipt"]))
    if not row: raise ValueError("missing or forged delivered read receipt")
    payload, proof = json.loads(row["payload"]), json.loads(row["proof"])
    if payload["tool"] != "read_document" or json.loads(row["receipt"]) != proof:
        raise ValueError("receipt is not a verified read")
    document = payload["resource_snapshot"]
    binding = {"task": task, "agent": agent, "operation": row["operation"], "resource": document["resource"],
               "version": document["version"], "digest": document["digest"]}
    if proof.get("read_binding") != binding or document["resource"] != args["resource"]:
        raise ValueError("read receipt task/agent/resource/version binding mismatch")
    return {**binding, "receipt_id": args["read_receipt"]}


def intent_facts(store, conn, request):
    """Record actual state at acceptance, independently of the authorization plan."""
    task, agent, args = request["task_id"], request["agent_id"], request["args"]
    get = lambda key: store.value(conn, key)[1]
    mode = get(f"taskmode:{task}")
    document = get("document:" + args["resource"]) if "resource" in args else None
    binding = get(f"taskresolved:{task}")
    resolved = conn.execute("SELECT data FROM resolved_tasks WHERE id=?", (binding["id"],)).fetchone() if binding else None
    spec = json.loads(resolved[0])["spec"] if resolved else None
    return {"schema_version": 1, "contract": get(f"contract3:{task}"),
            "contract_version": store.value(conn, f"contract3:{task}")[0],
            "used": get(f"budget:{task}"), "reserved": get(f"reserved:{task}"), "exposure": get(f"exposure:{task}"),
            "agent_members": get(f"agents:{task}"), "delegation": get(f"delegation:{task}:{agent}"),
            "entitlement": get(f"entitlement:{task}:{mode['owner']}") if mode else None,
            "task_scope": spec["scope"] if spec else None,
            "configured_agent_count": len(spec["agents"]) if spec else None,
            "execution_limits": {**spec["limits"]["inference"], **{k: spec["limits"][k] for k in ("max_steps", "max_in_flight")}} if spec else None,
            "document": {k: v for k, v in document.items() if k != "content"} if document else None,
            "label": get("label:" + args["resource"]) if "resource" in args else None,
            "read_basis": get(f"readbasis:{task}:{request['operation_id']}") if request["tool"] == "update_document" else None,
            "operation_consent": get(f"consent:{task}:{request['operation_id']}"),
            "purpose": request["purpose"]}
