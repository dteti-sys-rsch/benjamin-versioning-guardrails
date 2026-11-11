"""Universal zero-config environment synthesizer and canonical tool/argument alias normalizer.

Preserves all 23 frozen evaluation files in `examples/phase55/eval/freeze.json` untouched
while allowing arbitrary daily and enterprise goals to run without per-task JSON setup.
All Z3 policy evaluation, Ed25519 single-use tickets, SQLite CAS freshness checks,
taint tracking (PUBLIC/SENSITIVE/UNKNOWN), and atomic outbox invariants remain authoritative.
"""
from copy import deepcopy
import inspect
import json
from pathlib import Path
import re

from nacl.signing import SigningKey

from atomicroot.authority.policy_engine import valid_identity
from atomicroot.authority.ticket import args_hash, freeze_json
from atomicroot.framework.app import FrameworkRuntime
from atomicroot.framework.identity import Principal
from atomicroot.framework.registry import TOOLS
from atomicroot.framework.storage import dumps
from atomicroot.integration import dynamic_proposal as v12
from atomicroot.integration.config_workflow import ConfigWorkflow, ScriptedWorker
from atomicroot.integration.environment import (
    activate_intake,
    initialize_environment,
    local_identities,
    prepare_environment,
)
from atomicroot.integration.goals import GoalService
from atomicroot.integration.guarded import WORKER_TOOLS
from atomicroot.integration.inference import ModelBridge
from atomicroot.integration.progress import Progress
from atomicroot.integration.providers import (
    DEFAULT_OLLAMA_MODEL,
    DisabledClassifier,
    Limits,
    OLLAMA_ENDPOINT,
    live_model,
)
from atomicroot.integration.workspace import task_environment
from atomicroot.observability import point

DEFAULT_UNIVERSAL_MODEL = "qwen3.8:27b-q8_0"
DEFAULT_PURPOSE = "universal-assistance"
DEFAULT_NOTE_ID = "workspace-context"

# Canonical tool alias mapping for planner and worker boundaries.
TOOL_ALIASES = {
    # read_document
    "read_document": "read_document",
    "read": "read_document",
    "read_file": "read_document",
    "read_doc": "read_document",
    "get_document": "read_document",
    "get_file": "read_document",
    "open_document": "read_document",
    "open_file": "read_document",
    "view_document": "read_document",
    "view_file": "read_document",
    "load_document": "read_document",
    "load_file": "read_document",
    "fetch_document": "read_document",
    "inspect_document": "read_document",
    "cat_file": "read_document",
    "baca_dokumen": "read_document",
    "baca_file": "read_document",
    # update_document
    "update_document": "update_document",
    "update": "update_document",
    "write_document": "update_document",
    "write_file": "update_document",
    "write_doc": "update_document",
    "edit_document": "update_document",
    "edit_file": "update_document",
    "edit_doc": "update_document",
    "modify_document": "update_document",
    "modify_file": "update_document",
    "save_document": "update_document",
    "save_file": "update_document",
    "patch_document": "update_document",
    "update_file": "update_document",
    "update_doc": "update_document",
    "create_document": "update_document",
    "record_note": "update_document",
    "append_document": "update_document",
    "ubah_dokumen": "update_document",
    "simpan_dokumen": "update_document",
    "tulis_dokumen": "update_document",
    # send_email
    "send_email": "send_email",
    "email": "send_email",
    "send_mail": "send_email",
    "mail": "send_email",
    "send_message": "send_email",
    "send_notification": "send_email",
    "notify_email": "send_email",
    "notify": "send_email",
    "compose_email": "send_email",
    "dispatch_email": "send_email",
    "email_user": "send_email",
    "send_confirmation": "send_email",
    "send_receipt": "send_email",
    "kirim_email": "send_email",
    "kirim_pesan": "send_email",
    # transfer_funds
    "transfer_funds": "transfer_funds",
    "pay": "transfer_funds",
    "payment": "transfer_funds",
    "make_payment": "transfer_funds",
    "send_money": "transfer_funds",
    "wire_transfer": "transfer_funds",
    "pay_invoice": "transfer_funds",
    "transfer_money": "transfer_funds",
    "transfer": "transfer_funds",
    "purchase": "transfer_funds",
    "buy": "transfer_funds",
    "buy_ticket": "transfer_funds",
    "book_ticket": "transfer_funds",
    "pay_ticket": "transfer_funds",
    "order_item": "transfer_funds",
    "buy_online": "transfer_funds",
    "checkout": "transfer_funds",
    "checkout_payment": "transfer_funds",
    "pay_bill": "transfer_funds",
    "pay_order": "transfer_funds",
    "pay_reservation": "transfer_funds",
    "book_and_pay": "transfer_funds",
    "bayar": "transfer_funds",
    "transfer_dana": "transfer_funds",
    "beli_tiket": "transfer_funds",
    "beli_barang": "transfer_funds",
    "pesan_tiket": "transfer_funds",
    # deploy
    "deploy": "deploy",
    "deploy_service": "deploy",
    "release": "deploy",
    "publish_release": "deploy",
    "rollout": "deploy",
    "deploy_app": "deploy",
    "trigger_deploy": "deploy",
    "confirm_reservation": "deploy",
    "activate_booking": "deploy",
    "reserve_slot": "deploy",
    "book_reservation": "deploy",
    "publish": "deploy",
    "rilis": "deploy",
    # model_inference
    "model_inference": "model_inference",
    "inference": "model_inference",
    "llm_inference": "model_inference",
    "call_llm": "model_inference",
    "generate_text": "model_inference",
    "summarize": "model_inference",
}

# Keywords that genuinely represent capabilities outside the 6 canonical tools.
TRUE_UNSUPPORTED_KEYWORDS = (
    "whatsapp",
    "sms",
    "telegram",
    "slack",
    "microsoft teams",
    "teams channel",
    "discord",
    "wechat",
    "shell",
    "bash",
    "powershell",
    "terminal",
    "command_line",
    "sql",
    "database",
    "postgres",
    "mysql",
    "sqlite",
    "delete_file",
    "delete_document",
    "remove_file",
    "drop_table",
    " hapus ",
    "print_document",
    "printer",
    "fax",
    "phone_call",
    "voice_call",
    "telepon",
    "video_call",
    "zoom_call",
    "camera",
    "microphone",
    "bluetooth",
)

# Per-tool argument alias table for worker action staging.
ARG_ALIASES = {
    "read_document": {
        "file": "resource",
        "doc": "resource",
        "document": "resource",
        "path": "resource",
        "name": "resource",
        "source": "resource",
        "id": "resource",
        "hash": "digest",
        "sha256": "digest",
        "expected_digest": "digest",
    },
    "update_document": {
        "file": "resource",
        "doc": "resource",
        "document": "resource",
        "path": "resource",
        "name": "resource",
        "target": "resource",
        "hash": "digest",
        "sha256": "digest",
        "base_digest": "digest",
        "expected_digest": "digest",
        "text": "content",
        "body": "content",
        "data": "content",
        "value": "content",
        "new_content": "content",
        "receipt": "read_receipt",
        "read_op": "read_receipt",
        "operation_id": "read_receipt",
    },
    "send_email": {
        "recipient": "to",
        "email": "to",
        "address": "to",
        "destination": "to",
        "target": "to",
        "receiver": "to",
        "message": "body",
        "text": "body",
        "content": "body",
    },
    "transfer_funds": {
        "recipient": "to",
        "payee": "to",
        "vendor": "to",
        "merchant": "to",
        "destination": "to",
        "account": "to",
        "target": "to",
        "receiver": "to",
        "value": "amount",
        "price": "amount",
        "total": "amount",
        "cost": "amount",
        "nominal": "amount",
        "sum": "amount",
    },
    "deploy": {
        "file": "resource",
        "doc": "resource",
        "document": "resource",
        "artifact": "resource",
        "package": "resource",
        "service": "resource",
        "hash": "digest",
        "sha256": "digest",
        "destination": "to",
        "target": "to",
        "env": "to",
        "environment": "to",
        "recipient": "to",
    },
}

SPENDING_HINTS = (
    "pay",
    "payment",
    "bayar",
    "pembayaran",
    "transfer",
    "beli",
    "buy",
    "purchase",
    "tiket",
    "ticket",
    "booking",
    "pesanan",
    "order",
    "invoice",
    "tagihan",
    "bill",
    "checkout",
    "harga",
    "price",
    "amount",
    "sejumlah",
    "senilai",
    "seharga",
    "rupiah",
    "usd",
    "dana",
    "uang",
    "money",
    "fund",
    "deposit",
    "fee",
)


def normalize_tool_name(name):
    """Map an unambiguous tool synonym to its canonical registered tool name."""
    if type(name) is not str:
        return name
    cleaned = name.strip().lower().replace("-", "_").replace(" ", "_")
    if cleaned in TOOL_ALIASES:
        return TOOL_ALIASES[cleaned]
    # Heuristic token match for compound names like 'cinema_ticket_payment' or 'email_confirmation'
    if any(u in cleaned for u in ("whatsapp", "sms", "telegram", "slack", "teams", "shell", "sql", "delete", "print", "fax", "phone")):
        return name
    if any(k in cleaned for k in ("pay", "transfer", "ticket", "tiket", "buy", "purchase", "beli", "bayar", "checkout", "invoice", "order_item")):
        return "transfer_funds"
    if any(k in cleaned for k in ("email", "mail", "message", "notify", "pesan", "confirmation")):
        return "send_email"
    if any(k in cleaned for k in ("update", "write", "edit", "modify", "save", "patch", "ubah", "simpan", "tulis")):
        return "update_document"
    if any(k in cleaned for k in ("read", "view", "open", "fetch", "load", "baca")):
        return "read_document"
    if any(k in cleaned for k in ("deploy", "release", "rollout", "publish", "rilis", "activate_booking", "confirm_reservation")):
        return "deploy"
    return name


def has_true_unsupported_intent(text_value):
    """Return True if text explicitly asks for an external protocol outside the 6 canonical tools."""
    if type(text_value) is not str:
        return False
    lowered = " " + text_value.lower() + " "
    return any(keyword in lowered for keyword in TRUE_UNSUPPORTED_KEYWORDS)


def infer_goal_budget(goal, *, explicit_budget=None):
    """Derive workspace budget ceiling strictly from the trusted user goal string (never untrusted docs)."""
    if explicit_budget is not None:
        return int(explicit_budget)
    if type(goal) is not str:
        return 0
    lowered = goal.lower()
    if not any(hint in lowered for hint in SPENDING_HINTS):
        return 0
    numbers = [int(m) for m in re.findall(r"\b\d+\b", goal) if int(m) > 0]
    if not numbers:
        return 100000
    return sum(numbers)


def normalize_planner_proposal(raw, *, messages=None, goal=None, catalog=None):
    """Normalize tool aliases and missing recipient permission requests in an untrusted planner envelope."""
    if type(raw) is not dict:
        return raw
    data = deepcopy(raw)
    if messages is not None and (goal is None or catalog is None):
        try:
            ctx = json.loads(messages[1]["content"])
            goal = goal if goal is not None else ctx.get("goal", "")
            catalog = catalog if catalog is not None else ctx.get("allowed_catalog")
        except Exception:
            pass
    goal_text = goal or ""
    catalog = catalog or {}
    clarifications = catalog.get("clarifications", []) if type(catalog.get("clarifications")) is list else []
    grounding = (goal_text + " " + " ".join(str(c) for c in clarifications)).lower()
    known_resources = {r["resource"] for r in catalog.get("resources", []) if type(r) is dict and "resource" in r}
    known_destinations = {d["destination"] for d in catalog.get("destinations", []) if type(d) is dict and "destination" in d}
    known_scope = catalog.get("scope", []) if type(catalog.get("scope")) is list else []
    purposes = sorted({r.get("purpose") for r in known_scope if type(r) is dict and r.get("purpose")})
    default_purpose = purposes[0] if purposes else DEFAULT_PURPOSE

    # 1. Normalize requirements
    req = data.get("requirements")
    if type(req) is dict:
        reads = list(req.get("required_reads") or []) if type(req.get("required_reads")) is list else []
        receipts = []
        for item in (req.get("required_receipts") or []) if type(req.get("required_receipts")) is list else []:
            if type(item) is not dict:
                receipts.append(item)
                continue
            item = dict(item)
            canonical = normalize_tool_name(item.get("tool"))
            item["tool"] = canonical
            if canonical == "read_document":
                dest = item.get("destination")
                if type(dest) is str and dest not in reads:
                    reads.append(dest)
                continue
            if canonical == "update_document":
                dest = item.get("destination")
                if type(dest) is str and dest in known_resources and dest not in reads:
                    reads.append(dest)
                item["destination"] = None
            if item not in receipts:
                receipts.append(item)
        req["required_reads"] = reads
        req["required_receipts"] = receipts

    # 2. Normalize capability_requests when no genuinely unsupported tool was asked
    cap_requests = data.get("capability_requests")
    if type(cap_requests) is list and not has_true_unsupported_intent(goal_text):
        for item in cap_requests:
            if type(item) is dict and type(item.get("name")) is str:
                if not has_true_unsupported_intent(item["name"]):
                    item["name"] = normalize_tool_name(item["name"])

    # 3. Normalize proposal.spec (agents, capabilities, policies, provider, budget_limit)
    prop = data.get("proposal")
    if type(prop) is dict and prop.get("status") == "PROPOSAL" and type(prop.get("spec")) is dict:
        spec = prop["spec"]
        if spec.get("provider") is None:
            providers = [
                {"destination": d["destination"], "model": d["models"][0]}
                for d in catalog.get("destinations", [])
                if type(d) is dict and d.get("kind") == "provider" and d.get("models")
            ]
            if providers:
                spec["provider"] = providers[0]
        if type(spec.get("policies")) is list:
            for pol in spec["policies"]:
                if type(pol) is dict and type(pol.get("applies_to")) is list:
                    pol["applies_to"] = [normalize_tool_name(t) for t in pol["applies_to"]]
        needed_permissions = []
        if type(spec.get("agents")) is list:
            for agent in spec["agents"]:
                if type(agent) is not dict or type(agent.get("capabilities")) is not list:
                    continue
                normalized_caps = []
                for cap in agent["capabilities"]:
                    if type(cap) is not dict:
                        normalized_caps.append(cap)
                        continue
                    cap = dict(cap)
                    canonical = normalize_tool_name(cap.get("tool"))
                    cap["tool"] = canonical
                    cap["purpose"] = default_purpose
                    if canonical in TOOLS:
                        tool_def = TOOLS[canonical]
                        if not tool_def.resource:
                            cap["resource"] = None
                        elif cap.get("resource") is None:
                            req_reads = (req or {}).get("required_reads") or []
                            if len(req_reads) == 1:
                                cap["resource"] = req_reads[0]
                            elif len(known_resources) == 1:
                                cap["resource"] = next(iter(known_resources))
                        if not tool_def.external:
                            cap["destination"] = None
                    if cap not in normalized_caps:
                        normalized_caps.append(cap)
                    dest = cap.get("destination")
                    res = cap.get("resource")
                    if type(dest) is str and dest not in known_destinations and dest.lower() in grounding:
                        needed_permissions.append(("recipient", dest, f"Authorize recipient {dest}"))
                    if type(res) is str and res not in known_resources and res.lower() in grounding:
                        needed_permissions.append(("resource", res, f"Authorize resource {res}"))
                agent["capabilities"] = normalized_caps

        # Ensure permission_requests includes grounded missing recipients/resources
        perm_list = list(data.get("permission_requests") or []) if type(data.get("permission_requests")) is list else []
        existing_refs = {p.get("reference") for p in perm_list if type(p) is dict}
        for kind, ref, reason in needed_permissions:
            if ref not in existing_refs:
                perm_list.append({"kind": kind, "reference": ref, "reason": reason[:64]})
                existing_refs.add(ref)
        data["permission_requests"] = perm_list

        # Align spec.budget_limit with requirements.max_amount and spending usage
        has_spending = any(
            type(a) is dict
            and any(type(c) is dict and c.get("tool") in TOOLS and TOOLS[c["tool"]].spending for c in (a.get("capabilities") or []))
            for a in (spec.get("agents") or [])
        )
        max_amt = req.get("max_amount") if type(req) is dict else None
        cat_budget = catalog.get("budget_limit")
        if has_spending and type(max_amt) is int and max_amt > 0:
            if type(spec.get("budget_limit")) is not int or spec["budget_limit"] < max_amt:
                spec["budget_limit"] = min(max_amt, cat_budget) if type(cat_budget) is int and cat_budget >= max_amt else max_amt
        elif not has_spending and not spec.get("policies"):
            spec["budget_limit"] = 0

    return freeze_json(data)


def normalize_worker_response(raw, *, messages=None, catalog=None, observations=None, delegation=None):
    """Normalize synonym tool and argument names in a worker decision before GuardedTools.stage."""
    if type(raw) is not dict:
        return raw
    data = deepcopy(raw)
    if messages is not None and (catalog is None or observations is None or delegation is None):
        try:
            ctx = json.loads(messages[-1]["content"])
            catalog = catalog if catalog is not None else ctx.get("catalog", [])
            observations = observations if observations is not None else ctx.get("observations", [])
            delegation = delegation if delegation is not None else ctx.get("delegation", {})
        except Exception:
            pass
    catalog = catalog or []
    observations = observations or []
    delegation = delegation or {}

    # Normalize top-level shape if model omitted 'kind': 'action'
    if "kind" not in data and "tool" in data:
        data["kind"] = "action"
    if data.get("kind") != "action":
        return freeze_json(data)

    tool = normalize_tool_name(data.get("tool"))
    data["tool"] = tool
    args = dict(data.get("args") or {}) if type(data.get("args")) is dict else {}

    # Promote misplaced top-level argument keys into args
    for extra_key in list(data.keys()):
        if extra_key not in {"kind", "tool", "args"}:
            args.setdefault(extra_key, data.pop(extra_key))

    alias_map = ARG_ALIASES.get(tool, {})
    normalized_args = {}
    subject_prefix = None
    for k, v in args.items():
        if tool == "send_email" and k in {"subject", "title", "topic"} and type(v) is str and v.strip():
            subject_prefix = v.strip()
            continue
        target_key = alias_map.get(k, k)
        if target_key not in normalized_args:
            normalized_args[target_key] = v

    if tool == "send_email" and subject_prefix and type(normalized_args.get("body")) is str:
        if not normalized_args["body"].startswith(subject_prefix):
            normalized_args["body"] = f"{subject_prefix}\n\n{normalized_args['body']}"

    if tool == "transfer_funds" and type(normalized_args.get("amount")) is str and normalized_args["amount"].isdigit():
        normalized_args["amount"] = int(normalized_args["amount"])

    # Fill pinned catalog digest for reviewed resources when omitted by worker
    digests = {r["resource"]: r["digest"] for r in catalog if type(r) is dict and "resource" in r and "digest" in r}
    if tool in {"read_document", "update_document", "deploy"}:
        res = normalized_args.get("resource")
        if res is None and len(digests) == 1:
             scoped_res = {r.get("resource") for r in (delegation.get("scope") or []) if type(r) is dict and r.get("tool") == tool}
             if len(scoped_res) == 1:
                 res = next(iter(scoped_res))
                 normalized_args["resource"] = res
        if type(res) is str:
            if res in digests and not normalized_args.get("digest"):
                normalized_args["digest"] = digests[res]
            elif not normalized_args.get("digest"):
                # Unreviewed resource (e.g. prompt injection): preserve valid sha256 syntax so
                # Z3 PolicyAuthority evaluates and records an explicit DENY (scope).
                normalized_args["digest"] = "sha256:" + "0" * 64

    if tool == "update_document" and not normalized_args.get("read_receipt"):
        res = normalized_args.get("resource")
        for ob in reversed(observations):
            if type(ob) is not dict:
                continue
            source = ob.get("source") or ob.get("detail", {}).get("source") or {}
            receipt_id = ob.get("receipt_id") or (ob.get("detail", {}).get("receipt") or {}).get("receipt_id")
            if source.get("resource") == res and receipt_id:
                normalized_args["read_receipt"] = receipt_id
                break

    if tool in TOOLS:
        required_keys = TOOLS[tool].required
        if set(normalized_args) > set(required_keys):
            normalized_args = {k: v for k, v in normalized_args.items() if k in required_keys}

    data["args"] = normalized_args
    return freeze_json(data)


class UniversalProtocol:
    """Drop-in protocol wrapper around dynamic-proposal-v12 with synonym normalization & false-UNSUPPORTED repair."""

    VERSION = v12.VERSION
    PLANNER_VERSION = v12.PLANNER_VERSION
    DYNAMIC = True
    EFFECTS = v12.EFFECTS
    ORIGIN_PATHS = v12.ORIGIN_PATHS
    EXTERNAL_EFFECTS = v12.EXTERNAL_EFFECTS

    @staticmethod
    def proposal_schema():
        return v12.proposal_schema()

    @staticmethod
    def response_schema(messages=None):
        return v12.response_schema(messages)

    @staticmethod
    def catalog_for_prompt(catalog):
        return v12.catalog_for_prompt(catalog)

    @staticmethod
    def expand(value):
        return v12.expand(normalize_planner_proposal(value))

    @staticmethod
    def scope_breakdown(raw_value, resolved_spec):
        return v12.scope_breakdown(normalize_planner_proposal(raw_value), resolved_spec)

    @staticmethod
    def messages(goal, task, catalog, *, previous=None, error=None, draft=None):
        result = v12.messages(goal, task, catalog, previous=previous, error=error, draft=draft)
        synonym_guide = (
            "Universal domain mapping: map everyday or business actions to the 6 registered tools "
            "(buying/paying/booking tickets/items/invoices -> transfer_funds; "
            "emailing/sending email confirmations/summaries -> send_email; "
            "reading files/notes/docs -> read_document; "
            "writing/updating/editing notes/docs -> update_document; "
            "deploying/releasing/confirming service -> deploy). "
            "Never return UNSUPPORTED for actions covered by these 6 tools; if a recipient is absent from "
            "allowed_catalog, return PROPOSAL with spec using the canonical tool and list the recipient in permission_requests. "
            "However, NEVER substitute send_email or another tool when the goal explicitly requests an unregistered channel "
            "or capability (such as WhatsApp, SMS, Telegram, Slack, Teams, shell, SQL, delete, or print); for those, return "
            "proposal.status=UNSUPPORTED with capability_requests. "
        )
        result[0] = {"role": "system", "content": result[0]["content"] + " " + synonym_guide}
        return result

    @classmethod
    def parse_dynamic_proposal(cls, value, task, goal, catalog, *, approved_requirements=None, permissions_resolved=False):
        normalized = normalize_planner_proposal(value, goal=goal, catalog=catalog)
        raw_prop = normalized.get("proposal") if type(normalized) is dict else None
        if (
            type(raw_prop) is dict
            and raw_prop.get("status") == "PROPOSAL"
            and goal != "Perform user task"
            and has_true_unsupported_intent(goal)
        ):
            raise ValueError(
                '/proposal/status: the goal explicitly requests an unregistered capability or external channel '
                '(such as WhatsApp/SMS/Slack/Teams/shell/SQL/delete/print); never substitute send_email or another '
                'registered tool. Return proposal.status="UNSUPPORTED", spec=null, permission_requests=[], '
                'required_receipts=[], proposal.unsupported=[reason], and specify the missing tool in capability_requests'
            )
        if (
            type(raw_prop) is dict
            and raw_prop.get("status") == "UNSUPPORTED"
            and goal != "Perform user task"
            and not has_true_unsupported_intent(goal)
        ):
            reasons = " ".join(str(x) for x in (raw_prop.get("unsupported") or []))
            cap_names = " ".join(
                str(c.get("name", "")) for c in (normalized.get("capability_requests") or []) if type(c) is dict
            )
            combined = f"{goal} {reasons} {cap_names}"
            if not has_true_unsupported_intent(combined):
                inferred_tool = normalize_tool_name(cap_names or goal)
                hint = inferred_tool if inferred_tool in TOOLS else "transfer_funds / send_email / read_document / update_document / deploy"
                raise ValueError(
                    f'/proposal/status: this goal is supported by registered canonical tool "{hint}"; '
                    'do not return UNSUPPORTED. Return proposal.status="PROPOSAL", capability_requests=[], '
                    'and list any recipient absent from allowed_catalog in permission_requests'
                )
        return v12.parse_dynamic_proposal(
            normalized,
            task,
            goal,
            catalog,
            approved_requirements=approved_requirements,
            permissions_resolved=permissions_resolved,
        )

    @classmethod
    def parse_proposal(cls, value, task, goal, catalog=None):
        resolved = cls.parse_dynamic_proposal(value, task, goal, catalog)
        if resolved["status"] in {"NEEDS_PERMISSION", "NEEDS_CAPABILITY"}:
            return resolved
        return resolved["proposal"]


class UniversalModelAdapter:
    """Wraps any ModelProvider (live Ollama or offline FakeModel) to normalize planner and worker outputs."""

    def __init__(self, delegate):
        self.delegate = delegate
        self.provider = delegate.provider
        self.model = delegate.model
        self.live = delegate.live
        self.mode = getattr(delegate, "mode", "live" if delegate.live else "fake")
        self.structured_worker_output = getattr(delegate, "structured_worker_output", False)
        if hasattr(delegate, "execution_binding"):
            self.execution_binding = delegate.execution_binding

    async def generate(self, messages, *, response_schema=None):
        sig = inspect.signature(self.delegate.generate)
        if "response_schema" in sig.parameters:
            res = await self.delegate.generate(messages, response_schema=response_schema)
        else:
            res = await self.delegate.generate(messages)
        output = res.get("output")
        if type(output) is dict:
            if "schema_version" in output and "proposal" in output and "requirements" in output:
                output = normalize_planner_proposal(output, messages=messages)
            elif "kind" in output or "tool" in output:
                output = normalize_worker_response(output, messages=messages)
            res = {**res, "output": output}
        return res


class UniversalScriptedWorker(ScriptedWorker):
    """ScriptedWorker that normalizes tool/argument synonyms before staging."""

    def __call__(self, view):
        raw = super().__call__(view)
        return normalize_worker_response(
            raw,
            catalog=view.get("catalog", []),
            observations=view.get("observations", []),
            delegation=view.get("agent", {}),
        )


def parse_doc_spec(spec_str, purpose=DEFAULT_PURPOSE):
    """Parse '--doc id=content_or_path[:PUBLIC|SENSITIVE|UNKNOWN]' into a workspace resource dict."""
    if "=" not in spec_str:
        raise ValueError("document spec must have format name=content_or_path[:LABEL]")
    name, rest = spec_str.split("=", 1)
    name = name.strip()
    valid_identity(name)
    label = "PUBLIC"
    for suffix in (":PUBLIC", ":SENSITIVE", ":UNKNOWN"):
        if rest.upper().endswith(suffix):
            label = suffix[1:]
            rest = rest[: -len(suffix)]
            break
    candidate_path = Path(rest)
    if candidate_path.is_file():
        content = candidate_path.read_text(encoding="utf-8")
    else:
        content = rest
    return {"resource": name, "content": content, "label": label, "purposes": [purpose]}


def build_universal_environment(
    goal,
    *,
    docs=(),
    recipients=(),
    provider="ollama",
    model=DEFAULT_UNIVERSAL_MODEL,
    purpose=DEFAULT_PURPOSE,
    budget_limit=None,
    max_agents=3,
):
    """Synthesize a zero-config workspace v2 inventory and compile its task environment."""
    resource_list = []
    for doc in docs:
        if type(doc) is str:
            resource_list.append(parse_doc_spec(doc, purpose=purpose))
        elif type(doc) is dict:
            item = dict(doc)
            item.setdefault("label", "PUBLIC")
            item.setdefault("purposes", [purpose])
            resource_list.append(item)
    if not resource_list:
        resource_list.append(
            {
                "resource": DEFAULT_NOTE_ID,
                "content": "Universal workspace active.",
                "label": "PUBLIC",
                "purposes": [purpose],
            }
        )
    destinations = [
        {
            "destination": provider,
            "kind": "provider",
            "endpoint": OLLAMA_ENDPOINT if provider == "ollama" else "https://api.openai.com/v1",
            "models": [model],
            "purposes": [purpose],
            "labels": ["PUBLIC", "SENSITIVE", "UNKNOWN"] if provider == "ollama" else ["PUBLIC", "UNKNOWN"],
        }
    ]
    seen_dests = {provider}
    for r in recipients:
        r_name = r.strip() if type(r) is str else r["destination"]
        if r_name and r_name not in seen_dests:
            destinations.append(
                {
                    "destination": r_name,
                    "kind": "recipient",
                    "endpoint": None,
                    "models": [],
                    "purposes": [purpose],
                    "labels": [],
                }
            )
            seen_dests.add(r_name)

    workspace = {
        "schema_version": 2,
        "purpose": purpose,
        "resources": resource_list,
        "destinations": destinations,
        "provider": {"destination": provider, "model": model},
        "enabled_tools": [
            "read_document",
            "update_document",
            "send_email",
            "transfer_funds",
            "deploy",
            "model_inference",
        ],
        "budget_limit": infer_goal_budget(goal, explicit_budget=budget_limit),
        "max_agents": max_agents,
        "limits": {
            "inference": {
                "max_calls": 8,
                "max_tokens": 65536,
                "max_output_tokens": 1600,
                "max_retries": 0,
                "timeout": 180,
            },
            "max_in_flight": 2,
            "max_steps": 6,
        },
        "planning": {"ttl": 3600, "max_repairs": 1, "max_replans": 2},
    }
    return workspace, task_environment(workspace, goal)


def run_universal_goal(
    goal,
    directory,
    *,
    docs=(),
    recipients=(),
    provider="ollama",
    model=DEFAULT_UNIVERSAL_MODEL,
    budget_limit=None,
    authorize_live=False,
    auto_approve=True,
    execute=True,
    clarification=None,
    planner_model=None,
    worker_model=None,
    scripted_responses=None,
    resource_inputs=None,
    ask=input,
):
    """Execute a universal zero-config goal end-to-end through Planner -> Broker -> Z3 -> CAS -> Outbox."""
    directory = Path(directory)
    if directory.exists():
        raise ValueError(f"output directory already exists: {directory}")
    directory.mkdir(parents=True)

    def save(name, value):
        path = directory / name
        path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        path.chmod(0o600)

    workspace, env = build_universal_environment(
        goal,
        docs=docs,
        recipients=recipients,
        provider=provider,
        model=model,
        budget_limit=budget_limit,
    )
    prepared = prepare_environment(env)
    limits = Limits(**prepared["intake_spec"]["limits"]["inference"])
    save(
        "invocation.json",
        {
            "entrypoint": "run_universal.py",
            "goal": goal,
            "output": str(directory),
            "environment_digest": prepared["digest"],
            "budget_limit": env["budget_limit"],
            "authorize_live": authorize_live,
            "observed": point(),
        },
    )
    save("environment-preview.json", {**prepared, "observed": point()})

    key = SigningKey.generate()
    key_path = directory / "signing.key"
    key_path.write_bytes(bytes(key))
    key_path.chmod(0o600)
    runtime = FrameworkRuntime(str(directory / "ledger.sqlite"), signing_key=key)
    service = None
    try:
        setup = initialize_environment(runtime, env, prepared["digest"])
        save("intake-preview.json", setup)
        user, approver = local_identities(runtime)
        runtime.broker.decide(setup["preview"]["review_id"], True, approver)
        activate_intake(runtime, approver)

        if planner_model is None:
            if not authorize_live:
                raise PermissionError("live model requires authorize_live=True or an offline planner_model")
            raw_planner = live_model(provider, model, limits)
        else:
            raw_planner = planner_model
        wrapped_planner = UniversalModelAdapter(raw_planner)

        progress = Progress(directory / "progress.jsonl", quiet=True)
        service = GoalService(
            runtime,
            wrapped_planner,
            progress=progress,
            protocol=UniversalProtocol,
            resource_inputs=resource_inputs,
        )
        context_resources = [r["resource"] for r in env["resources"] if r["resource"] != DEFAULT_NOTE_ID and r["label"] == "PUBLIC"]
        # Note: intake only reads context_resources if explicitly configured in intake_spec; workers read documents during execution.
        service.plan("goal", goal, "planning", env["task_id"], user)
        preview = service.status("goal", user, private=True)
        save("proposal-preview.json", preview)
        save("goal-artifact.json", service.export("goal", user))

        if preview["status"] == "CLARIFY" and clarification:
            service.plan("goal", goal, "planning", env["task_id"], user, replan=True, clarification=clarification)
            preview = service.status("goal", user, private=True)
            save("proposal-preview.json", preview)
            save("goal-artifact.json", service.export("goal", user))

        if preview["status"] == "NEEDS_CAPABILITY":
            decision = "approve" if auto_approve else ask("Approve capability specification only (execution blocked)? approve/reject/pause: ").strip()
            if decision not in {"approve", "reject", "pause"}:
                decision = "pause"
            service.decide("goal", decision, approver)
            result = {
                "status": "NEEDS_CAPABILITY",
                "execution_authorized": False,
                "capability_requests": preview.get("proposal", {}).get("capability_requests", []),
                "unsupported": preview.get("proposal", {}).get("proposal", {}).get("unsupported", []),
                "observed": point(),
            }
            save("goal-artifact.json", service.export("goal", user))
            save("result.json", result)
            return result

        if preview["status"] != "REVIEW_WAIT":
            result = {"status": preview["status"], "error": preview.get("error"), "observed": point()}
            save("result.json", result)
            return result

        decision = "approve" if auto_approve else ask("Approve business proposal & permissions? approve/reject/pause: ").strip()
        if decision not in {"approve", "reject", "pause"}:
            decision = "pause"
        service.decide("goal", decision, approver)
        if decision != "approve":
            result = {"status": "REJECTED" if decision == "reject" else "PAUSED", "observed": point()}
            save("goal-artifact.json", service.export("goal", user))
            save("result.json", result)
            return result

        if preview.get("bundle"):
            operator = Principal(
                approver.subject,
                approver.roles | {"admin", "owner"},
                approver.tasks,
                frozenset(resource_inputs or {}),
            )
        else:
            operator = approver
        service.activate("goal", operator)

        if not execute:
            result = {"status": "ACTIVE", "task_id": env["task_id"], "observed": point()}
            save("goal-artifact.json", service.export("goal", user))
            save("result.json", result)
            return result

        denials = []
        def _record_effect(node, ob):
            if type(ob) is dict and ob.get("status") in {"DENY", "EVALUATION_ERROR"}:
                denials.append({"status": ob["status"], **(ob.get("detail") or {})})

        def factory(task, caller, budget):
            if scripted_responses is not None:
                # If task spec has a provider, wrap scripted responses in a FakeModel with execution_binding
                active_spec = runtime.tasks.status(task, caller)["resolved"]["spec"]
                if active_spec.get("provider"):
                    from atomicroot.integration.providers import FakeModel
                    worker_fn = UniversalScriptedWorker(scripted_responses)
                    def respond(messages):
                        data = json.loads(messages[-1]["content"])
                        return worker_fn({
                            "node": data["node"],
                            "step": data["step"],
                            "catalog": data.get("catalog", []),
                            "observations": data.get("observations", []),
                            "agent": data.get("delegation", {}),
                        })
                    fmodel = FakeModel(respond, provider=active_spec["provider"]["destination"])
                    fmodel.model = active_spec["provider"]["model"]
                    fmodel.execution_binding = worker_fn.binding
                    bridge = ModelBridge(runtime, UniversalModelAdapter(fmodel), DisabledClassifier(), llm_limits=limits, jev_limits=limits, progress=progress, budget=budget)
                    return ConfigWorkflow(runtime, directory / "executor.sqlite", task=task, caller=caller, bridge=bridge, after_effect=_record_effect)
                return ConfigWorkflow(
                    runtime,
                    directory / "executor.sqlite",
                    task=task,
                    caller=caller,
                    worker=UniversalScriptedWorker(scripted_responses),
                    after_effect=_record_effect,
                )
            w_raw = worker_model or raw_planner
            w_wrapped = UniversalModelAdapter(w_raw)
            bridge = ModelBridge(
                runtime,
                w_wrapped,
                DisabledClassifier(),
                llm_limits=limits,
                jev_limits=limits,
                progress=progress,
                budget=budget,
            )
            return ConfigWorkflow(runtime, directory / "executor.sqlite", task=task, caller=caller, bridge=bridge, after_effect=_record_effect)

        exec_result = service.execute("goal", user, factory)
        with runtime.store.snapshot() as snap:
            outbox_rows = [
                {
                    "operation": op,
                    "status": st,
                    "payload": json.loads(pl),
                    "receipt": json.loads(rc) if rc else None,
                }
                for op, st, pl, rc in snap._conn.execute(
                    "SELECT operation,status,payload,receipt FROM outbox WHERE task=? AND payload NOT LIKE '%\"tool\":\"model_inference\"%'",
                    (env["task_id"],),
                ).fetchall()
            ]
        result = {
            **exec_result,
            "task_id": env["task_id"],
            "budget_limit": runtime.store.get_state("contract3:" + env["task_id"]).get("budget_limit", 0),
            "business_outbox": outbox_rows,
            "z3_denials": denials,
            "observed": point(),
        }
        save("goal-artifact.json", service.export("goal", user))
        save("result.json", result)
        return result
    finally:
        runtime.store.close()
