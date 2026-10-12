"""Explicit configuration foundation. No workflow execution or live inference."""
import argparse
import json
from pathlib import Path

from nacl.signing import SigningKey
from atomicroot.authority.ticket import freeze_json
from atomicroot.framework.app import FrameworkRuntime
from atomicroot.framework.identity import Principal
from atomicroot.framework.task_spec import exact, task_schema, sequence


def load(path):
    raw = Path(path).read_bytes()
    if len(raw) > 32768: raise ValueError("input file exceeds 32768 bytes")
    def pairs(items):
        data = {}
        for key, value in items:
            if key in data: raise ValueError("duplicate JSON key")
            data[key] = value
        return data
    return freeze_json(json.loads(raw, object_pairs_hook=pairs))


def init_fixture(runtime, data):
    """Explicit local admin action; never called from TaskSpec or worker endpoints."""
    exact(data, {"resources", "destinations", "entitlements"})
    admin = Principal("local-admin", frozenset({"admin"}))
    for resource in sequence(data["resources"]):
        exact(resource, {"resource", "content", "label", "purposes"})
        owner = Principal("local-owner", frozenset({"owner"}), resources=frozenset({resource["resource"]}))
        with runtime.store.snapshot() as snap: previous = snap.read("document:" + resource["resource"])[1]
        if previous is not None: raise ValueError("fixture resource exists; use official owner API for changes")
        ref = runtime.storage.ingest(resource["resource"], resource["content"], owner)
        runtime.labels.set_label(ref["resource"], ref["digest"], ref["version"], resource["label"], resource["purposes"], owner)
    for destination in sequence(data["destinations"]): runtime.catalog.set_destination(destination, admin)
    for entitlement in sequence(data["entitlements"]):
        exact(entitlement, {"task", "subject", "rights"})
        runtime.catalog.set_entitlement(entitlement["task"], entitlement["subject"], entitlement["rights"], admin)
    return {"status": "FIXTURE_INSTALLED", "identity_mode": "TRUSTED_LOCAL_FIXTURE"}


def local_identities(runtime):
    # Authentication fixture is host-owned. TaskSpec cannot nominate its parent.
    with runtime.store.snapshot() as snap:
        tasks = frozenset(key.split(":")[1] for (key,) in snap._conn.execute(
            "SELECT key FROM conflict_keys WHERE key LIKE 'entitlement:%:local-user'"))
    return (Principal("local-user", frozenset({"user"}), tasks),
            Principal("local-human", frozenset({"approver"}), tasks))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", default=".runs/phase36")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("schema")
    for name in ("init-fixture", "validate", "preview"):
        sub.add_parser(name).add_argument("file")
    decision = sub.add_parser("decide")
    decision.add_argument("review_id"); decision.add_argument("decision", choices=("approve", "reject", "pause"))
    activate = sub.add_parser("activate")
    activate.add_argument("proposal_id"); activate.add_argument("review_id")
    sub.add_parser("status").add_argument("task_id")
    args = parser.parse_args()
    if args.command == "schema": print(json.dumps(task_schema(), indent=2)); return 0
    directory = Path(args.directory)
    directory.mkdir(parents=True, exist_ok=True)
    key_path = directory / "signing.key"
    if not key_path.exists():
        key_path.write_bytes(bytes(SigningKey.generate()))
        key_path.chmod(0o600)
    runtime = FrameworkRuntime(str(directory / "ledger.sqlite"), signing_key=SigningKey(key_path.read_bytes()))
    try:
        user, approver = local_identities(runtime)
        if args.command == "init-fixture": result = init_fixture(runtime, load(args.file))
        elif args.command == "validate": result = runtime.tasks.validate(load(args.file), user)
        elif args.command == "preview": result = runtime.tasks.propose(load(args.file), user)
        elif args.command == "decide":
            if args.decision == "pause":
                result = {"status": "PAUSED", "review": runtime.broker.status(args.review_id, approver)["effective_status"]}
            else: result = runtime.broker.decide(args.review_id, args.decision == "approve", approver)
        elif args.command == "activate": result = runtime.contracts.activate(args.proposal_id, args.review_id, approver)
        else: result = runtime.tasks.status(args.task_id, user)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 1 if result.get("valid") is False else 0
    except (ValueError, PermissionError) as exc:
        print(json.dumps({"status": "REJECTED", "error": str(exc)})); return 1
    finally: runtime.store.close()


if __name__ == "__main__": raise SystemExit(main())
