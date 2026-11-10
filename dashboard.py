"""
AtomicRoot Runtime Authorization Dashboard
FastAPI + SQLite Read-Only (?mode=ro&immutable=1) + Tailwind CSS + Mermaid.js
Complete single-file observability & verification dashboard for AtomicRoot runs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import webbrowser
from pathlib import Path
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

ROOT = Path(__file__).resolve().parent
RUNS_DIR = ROOT / ".runs"

app = FastAPI(title="AtomicRoot Runtime Authorization Dashboard", docs_url=None, redoc_url=None)


def get_sqlite_ro(path: Path | str) -> sqlite3.Connection:
    p = Path(path).resolve()
    uri = f"file:{p.as_posix()}?mode=ro&immutable=1"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def safe_read_json(path: Path) -> Optional[Any]:
    if not path.exists() or not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def classify_run_group(name: str, run_type: str) -> str:
    if name.startswith("v12-") and run_type != "whitebox":
        return "1_v12_suites"
    if run_type == "whitebox":
        return "2_whitebox"
    if name.startswith(("v11-", "pre-phase6-", "dynamic-live-v10")):
        return "3_v10_v11_suites"
    if run_type in ("suite", "legacy_suite"):
        return "4_other_suites"
    return "5_single_or_other"


def list_available_runs() -> List[Dict[str, Any]]:
    runs: List[Dict[str, Any]] = []
    if not RUNS_DIR.exists():
        return runs

    for d in sorted(RUNS_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if not d.is_dir():
            continue
        summary_file = d / "summary.json"
        whitebox_file = d / "whitebox-summary.json"
        prov_file = d / "provenance.json"

        run_info: Dict[str, Any] = {
            "id": d.name,
            "path": str(d),
            "mtime": d.stat().st_mtime,
            "type": "other",
            "group": "5_single_or_other",
            "title": d.name,
            "pass_rate": None,
            "total_runs": 0,
            "passed": 0,
            "model": None,
            "protocol": None,
            "commit": None,
            "freeze_matched": None,
            "has_infra_errors": False,
            "total_calls": None,
            "max_total_calls": None,
            "aggregate": None,
        }

        if whitebox_file.exists():
            run_info["type"] = "whitebox"
            wb = safe_read_json(whitebox_file) or {}
            blocked = wb.get("blocked", {})
            num = blocked.get("numerator", 0)
            den = blocked.get("denominator", wb.get("attacks", 0))
            run_info["total_runs"] = den
            run_info["passed"] = num
            run_info["pass_rate"] = f"{num}/{den} blocked"
            run_info["model"] = wb.get("model") or "Offline (No LLM)"
        elif summary_file.exists():
            s = safe_read_json(summary_file) or {}
            if "aggregate" in s and isinstance(s.get("runs"), list):
                run_info["type"] = "suite"
                agg = s.get("aggregate", {})
                op = agg.get("overall_pass_rate", {})
                num = op.get("numerator", 0)
                den = op.get("denominator", agg.get("total_runs", 0))
                run_info["total_runs"] = den
                run_info["passed"] = num
                run_info["pass_rate"] = f"{num}/{den}"
                run_info["model"] = s.get("model") or s.get("protocol")
                run_info["protocol"] = s.get("protocol")
                run_info["total_calls"] = s.get("total_calls")
                run_info["max_total_calls"] = s.get("max_total_calls")
                run_info["has_infra_errors"] = (agg.get("infra_error_runs", {}).get("numerator", 0) > 0)
                run_info["aggregate"] = agg
            else:
                run_info["type"] = "legacy_suite"
                run_info["model"] = s.get("model") or s.get("provider") or "Legacy"
        elif (d / "ledger.sqlite").exists() or (d / "result.json").exists() or (d / "proposal-preview.json").exists():
            run_info["type"] = "single"
            res = safe_read_json(d / "result.json") or {}
            st = res.get("status")
            if st:
                run_info["pass_rate"] = st
            run_info["total_runs"] = 1

        if prov_file.exists():
            p = safe_read_json(prov_file) or {}
            run_info["commit"] = p.get("git", {}).get("head", "")[:7]
            run_info["freeze_matched"] = p.get("freeze", {}).get("matched")
            if not run_info["protocol"]:
                run_info["protocol"] = p.get("protocol")
            if not run_info["model"]:
                run_info["model"] = p.get("model", {}).get("name") or p.get("protocol")

        run_info["group"] = classify_run_group(d.name, run_info["type"])
        runs.append(run_info)

    # Sort v12 suites first, then whitebox, then v10/v11, etc., keeping mtime order within group
    runs.sort(key=lambda r: (r["group"], -r["mtime"]))
    return runs


def verify_manifest_hashes(run_path: Path) -> Dict[str, Any]:
    manifest_file = run_path / "MANIFEST.sha256"
    if not manifest_file.exists():
        return {"exists": False, "verified": False, "total_files": 0, "bad_hashes": 0, "extra_files": 0, "missing_files": 0}

    bad = 0
    manifest_files = set()
    for line in manifest_file.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        h, f = parts[0], parts[1].strip()
        norm_f = os.path.normpath(f)
        manifest_files.add(norm_f)
        fp = run_path / norm_f
        if not fp.exists() or hashlib.sha256(fp.read_bytes()).hexdigest() != h:
            bad += 1

    actual_files = set()
    for root, _, files in os.walk(run_path):
        for fn in files:
            rel = os.path.normpath(os.path.relpath(os.path.join(root, fn), run_path))
            if rel != "MANIFEST.sha256":
                actual_files.add(rel)

    extra = sorted(actual_files - manifest_files)
    missing = sorted(manifest_files - actual_files)
    return {
        "exists": True,
        "verified": (bad == 0 and len(extra) == 0 and len(missing) == 0),
        "total_files": len(manifest_files),
        "bad_hashes": bad,
        "extra_files": len(extra),
        "missing_files": len(missing),
        "extra_list": extra[:10],
        "missing_list": missing[:10],
    }


def get_run_details(run_id: str) -> Dict[str, Any]:
    run_path = RUNS_DIR / run_id
    if not run_path.exists() or not run_path.is_dir():
        raise HTTPException(status_code=404, detail="Run not found")

    whitebox_file = run_path / "whitebox-summary.json"
    summary_file = run_path / "summary.json"
    prov_file = run_path / "provenance.json"
    manifest_file = run_path / "MANIFEST.sha256"

    provenance = safe_read_json(prov_file) or {}
    manifest_info = {"exists": manifest_file.exists(), "total_files": 0}
    if manifest_file.exists():
        try:
            manifest_info["total_files"] = len([
                l for l in manifest_file.read_text(encoding="utf-8").splitlines() if l.strip()
            ])
        except Exception:
            pass

    if whitebox_file.exists():
        wb = safe_read_json(whitebox_file) or {}
        return {
            "type": "whitebox",
            "id": run_id,
            "provenance": provenance,
            "manifest": manifest_info,
            "attacks": wb.get("attacks", 0),
            "blocked": wb.get("blocked", {}),
            "case_file": wb.get("case_file"),
            "case_file_digest": wb.get("case_file_digest"),
            "results": wb.get("results", []),
            "summary": wb,
        }

    if summary_file.exists():
        s = safe_read_json(summary_file) or {}
        if "aggregate" in s and isinstance(s.get("runs"), list):
            det_by_case = s.get("determinism_by_case")
            if not det_by_case:
                grouped_runs: Dict[str, List[Dict[str, Any]]] = {}
                for r_item in s.get("runs", []):
                    cname = r_item.get("case")
                    if cname:
                        grouped_runs.setdefault(cname, []).append(r_item)
                if any(len(v) >= 2 for v in grouped_runs.values()):
                    det_by_case = {}
                    for cname, r_list in grouped_runs.items():
                        if len(r_list) >= 2:
                            digests = sorted({str(x.get("planner_output_digest") or "") for x in r_list if x.get("planner_output_digest")})
                            det_by_case[cname] = {
                                "runs": len(r_list),
                                "unique_digests": digests,
                                "identical": len(digests) == 1,
                            }
            return {
                "type": "suite",
                "id": run_id,
                "provenance": provenance,
                "manifest": manifest_info,
                "model": s.get("model"),
                "protocol": s.get("protocol"),
                "set": s.get("set"),
                "reviewer": s.get("reviewer"),
                "total_calls": s.get("total_calls"),
                "max_total_calls": s.get("max_total_calls"),
                "aggregate": s.get("aggregate", {}),
                "determinism_by_case": det_by_case,
                "runs": s.get("runs", []),
            }
        else:
            # Legacy summary.json or custom run summary
            return {
                "type": "generic",
                "id": run_id,
                "provenance": provenance,
                "manifest": manifest_info,
                "summary": s,
                "files": sorted([p.name for p in run_path.iterdir()]),
            }

    # If single run directory (contains ledger.sqlite / result.json / proposal-preview.json)
    if (run_path / "ledger.sqlite").exists() or (run_path / "result.json").exists() or (run_path / "proposal-preview.json").exists():
        res = safe_read_json(run_path / "result.json") or {}
        pp = safe_read_json(run_path / "proposal-preview.json") or {}
        status = res.get("status") or pp.get("status") or "COMPLETED"
        passed = status in ("SATISFIED", "CLARIFY", "NEEDS_CAPABILITY")
        synthetic_case = {
            "run_id": ".",
            "case": run_id,
            "pattern": "single-run",
            "outcome": status,
            "expected_outcome": status,
            "passed": passed,
            "planning_status": pp.get("status") or status,
            "execution_status": res.get("status"),
            "inference_attempts": len(pp.get("calls", [])) if isinstance(pp.get("calls"), list) else 1,
            "goal_oracle": {"outcome_ok": passed, "missing_required": [], "forbidden_effects": [], "intent_correct": passed},
            "scope_breakdown": pp.get("scope_breakdown"),
        }
        return {
            "type": "suite",
            "id": run_id,
            "provenance": provenance,
            "manifest": manifest_info,
            "model": pp.get("prompt_version") or "Single Run",
            "protocol": pp.get("prompt_version"),
            "set": "single",
            "reviewer": "local",
            "total_calls": synthetic_case["inference_attempts"],
            "max_total_calls": None,
            "aggregate": {
                "total_runs": 1,
                "distinct_goal_texts": 1,
                "overall_pass_rate": {"numerator": 1 if passed else 0, "denominator": 1, "wilson95": [0.0, 1.0]},
                "forbidden_effect_runs": {"numerator": 0, "denominator": 1, "wilson95": [0.0, 1.0]},
                "accepted_violation_rate": {"numerator": 0, "denominator": 1, "wilson95": [0.0, 1.0]},
                "executable_completion_rate": {"numerator": 1 if status == "SATISFIED" else 0, "denominator": 1, "wilson95": [0.0, 1.0]},
                "infra_error_runs": {"numerator": 0, "denominator": 1, "wilson95": [0.0, 1.0]},
            },
            "runs": [synthetic_case],
        }

    # Check if run folder contains subdirectories that have ledger.sqlite (like v11-determinism-2 or dynamic-live-v8)
    subcases = []
    for sub in sorted(run_path.iterdir()):
        if sub.is_dir() and ((sub / "ledger.sqlite").exists() or (sub / "progress.jsonl").exists()):
            res = safe_read_json(sub / "result.json") or {}
            pp = safe_read_json(sub / "proposal-preview.json") or {}
            st = res.get("status") or pp.get("status") or "UNKNOWN"
            subcases.append({
                "run_id": sub.name,
                "case": sub.name,
                "pattern": "subcase",
                "outcome": st,
                "expected_outcome": st,
                "passed": st == "SATISFIED",
                "planning_status": pp.get("status"),
                "execution_status": res.get("status"),
                "inference_attempts": 1,
                "goal_oracle": {"missing_required": [], "forbidden_effects": []},
                "scope_breakdown": pp.get("scope_breakdown"),
            })
    if subcases:
        passed_cnt = sum(1 for c in subcases if c["passed"])
        return {
            "type": "suite",
            "id": run_id,
            "provenance": provenance,
            "manifest": manifest_info,
            "model": provenance.get("model", {}).get("name") or provenance.get("protocol") or "Partial / Batch Suite",
            "protocol": provenance.get("protocol"),
            "set": "partial",
            "reviewer": provenance.get("reviewer"),
            "total_calls": None,
            "max_total_calls": None,
            "aggregate": {
                "total_runs": len(subcases),
                "distinct_goal_texts": len(subcases),
                "overall_pass_rate": {"numerator": passed_cnt, "denominator": len(subcases), "wilson95": []},
                "forbidden_effect_runs": {"numerator": 0, "denominator": len(subcases), "wilson95": []},
                "accepted_violation_rate": {"numerator": 0, "denominator": len(subcases), "wilson95": []},
                "executable_completion_rate": {"numerator": passed_cnt, "denominator": len(subcases), "wilson95": []},
                "infra_error_runs": {"numerator": 0, "denominator": len(subcases), "wilson95": []},
            },
            "runs": subcases,
        }

    # Generic fallback for any other folder in .runs/
    files_preview = {}
    for p in sorted(run_path.iterdir())[:20]:
        if p.is_file() and p.suffix in (".json", ".txt", ".log", ".md"):
            try:
                files_preview[p.name] = p.read_text(encoding="utf-8", errors="replace")[:4000]
            except Exception:
                pass
    return {
        "type": "generic",
        "id": run_id,
        "provenance": provenance,
        "manifest": manifest_info,
        "summary": files_preview,
        "files": sorted([p.name for p in run_path.iterdir()]),
    }


def extract_ledger_details(db_file: Path) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "goal": "",
        "proposal": None,
        "proposals_all": [],
        "reviews": [],
        "resolved_tasks": [],
        "outbox": [],
        "authorizations": [],
        "trace_events": [],
        "service_events": [],
        "conflict_keys": [],
        "memos": [],
        "inference_attempts": [],
        "execution_outputs": [],
        "receiver_receipts": [],
    }
    if not db_file.exists():
        return result

    try:
        conn = get_sqlite_ro(db_file)

        # Goal session
        try:
            row = conn.execute("SELECT id, owner, task, intake, data FROM goal_sessions LIMIT 1").fetchone()
            if row and row["data"]:
                gdata = json.loads(row["data"])
                result["goal"] = gdata.get("goal", "")
        except Exception:
            pass

        # Proposals
        try:
            for row in conn.execute("SELECT id, task, digest, status, activated_version, data, review FROM proposals"):
                pdata = json.loads(row["data"]) if row["data"] else {}
                r_item = {
                    "id": row["id"],
                    "task": row["task"],
                    "digest": row["digest"],
                    "status": row["status"],
                    "activated_version": row["activated_version"],
                    "data": pdata,
                }
                result["proposals_all"].append(r_item)
                if pdata and pdata.get("spec") and not result["proposal"]:
                    result["proposal"] = pdata
        except Exception:
            pass

        # Reviews (Approval Broker grants)
        try:
            for row in conn.execute("SELECT id, kind, task, status, expires, approver, data FROM reviews"):
                result["reviews"].append({
                    "id": row["id"],
                    "kind": row["kind"],
                    "task": row["task"],
                    "status": row["status"],
                    "expires": row["expires"],
                    "approver": row["approver"],
                    "data": json.loads(row["data"]) if row["data"] else {},
                })
        except Exception:
            pass

        # Inference Memos
        try:
            for row in conn.execute("SELECT id, binding, response FROM inference_memo WHERE response IS NOT NULL"):
                resp = json.loads(row["response"])
                out = resp.get("output")
                result["memos"].append({
                    "id": row["id"],
                    "binding": row["binding"],
                    "output": out,
                    "raw": resp,
                })
                if isinstance(out, dict) and out.get("proposal"):
                    # Prefer the latest valid proposal from planner memo
                    result["proposal"] = out["proposal"]
                    result["planner_envelope"] = out
        except Exception:
            pass

        # Inference Attempts
        try:
            for row in conn.execute(
                "SELECT id, call_id, budget, kind, model, started, status, usage, error, reserved_tokens, reserved_cost FROM inference_attempts"
            ):
                result["inference_attempts"].append({
                    "id": row["id"],
                    "call_id": row["call_id"],
                    "budget": row["budget"],
                    "kind": row["kind"],
                    "model": row["model"],
                    "started": row["started"],
                    "status": row["status"],
                    "usage": json.loads(row["usage"]) if row["usage"] else None,
                    "error": row["error"],
                    "reserved_tokens": row["reserved_tokens"],
                })
        except Exception:
            pass

        # Outbox
        try:
            for row in conn.execute(
                "SELECT task, operation, ticket, agent, digest, payload, status, attempts, amount, receipt, error FROM outbox"
            ):
                result["outbox"].append({
                    "task": row["task"],
                    "operation": row["operation"],
                    "ticket": row["ticket"],
                    "agent": row["agent"],
                    "digest": row["digest"],
                    "status": row["status"],
                    "attempts": row["attempts"],
                    "amount": row["amount"],
                    "payload": json.loads(row["payload"]) if row["payload"] else {},
                    "receipt": json.loads(row["receipt"]) if row["receipt"] else None,
                    "error": row["error"],
                })
        except Exception:
            pass

        # Authorizations (Issued tickets)
        try:
            for row in conn.execute("SELECT ticket, task, operation, data FROM authorizations"):
                result["authorizations"].append({
                    "ticket": row["ticket"],
                    "task": row["task"],
                    "operation": row["operation"],
                    "data": json.loads(row["data"]) if row["data"] else {},
                })
        except Exception:
            pass

        # Trace Events (Trace Store)
        try:
            for row in conn.execute(
                "SELECT seq, event_id, task_id, agent_id, tool, args_hash, ticket_id, nonce, write_set, timestamp, args FROM trace_events ORDER BY seq"
            ):
                result["trace_events"].append({
                    "seq": row["seq"],
                    "event_id": row["event_id"],
                    "task_id": row["task_id"],
                    "agent_id": row["agent_id"],
                    "tool": row["tool"],
                    "args_hash": row["args_hash"],
                    "ticket_id": row["ticket_id"],
                    "nonce": row["nonce"],
                    "write_set": json.loads(row["write_set"]) if row["write_set"] else [],
                    "timestamp": row["timestamp"],
                    "args": json.loads(row["args"]) if row["args"] else {},
                })
        except Exception:
            pass

        # Service Events
        try:
            for row in conn.execute("SELECT seq, kind, actor, data, timestamp FROM service_events ORDER BY seq"):
                result["service_events"].append({
                    "seq": row["seq"],
                    "kind": row["kind"],
                    "actor": row["actor"],
                    "timestamp": row["timestamp"],
                    "data": json.loads(row["data"]) if row["data"] else {},
                })
        except Exception:
            pass

        # Conflict Keys (Snapshot versions)
        try:
            for row in conn.execute("SELECT key, version, value FROM conflict_keys ORDER BY key"):
                val = row["value"]
                try:
                    val = json.loads(val)
                except Exception:
                    pass
                result["conflict_keys"].append({
                    "key": row["key"],
                    "version": row["version"],
                    "value": val,
                })
        except Exception:
            pass

        # Execution Outputs
        try:
            for row in conn.execute("SELECT task, run, id, digest, data FROM execution_outputs"):
                result["execution_outputs"].append({
                    "task": row["task"],
                    "run": row["run"],
                    "id": row["id"],
                    "digest": row["digest"],
                    "data": json.loads(row["data"]) if row["data"] else {},
                })
        except Exception:
            pass

        # Receiver Receipts
        try:
            for row in conn.execute("SELECT task, operation, digest, receipt FROM receiver_receipts"):
                result["receiver_receipts"].append({
                    "task": row["task"],
                    "operation": row["operation"],
                    "digest": row["digest"],
                    "receipt": json.loads(row["receipt"]) if row["receipt"] else {},
                })
        except Exception:
            pass

        conn.close()
    except Exception as e:
        print(f"Error reading SQLite {db_file}: {e}")

    return result


def get_case_details(run_id: str, case_run_id: str) -> Dict[str, Any]:
    run_path = RUNS_DIR / run_id
    case_path = run_path if case_run_id == "." else (run_path / case_run_id)
    if not case_path.exists() or not case_path.is_dir():
        raise HTTPException(status_code=404, detail="Case run folder not found")

    summary_file = run_path / "summary.json"
    case_summary = None
    if summary_file.exists():
        s = safe_read_json(summary_file) or {}
        for r in s.get("runs", []):
            if r.get("run_id") == case_run_id:
                case_summary = r
                break

    # Read progress.jsonl
    progress_file = case_path / "progress.jsonl"
    events: List[Dict[str, Any]] = []
    if progress_file.exists():
        for line in progress_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip():
                try:
                    events.append(json.loads(line))
                except Exception:
                    pass

    # Read auxiliary JSON files in case folder & parent run folder
    proposal_preview = safe_read_json(case_path / "proposal-preview.json")
    proposal_preview_rev0 = safe_read_json(case_path / "proposal-preview-rev0.json")
    environment_preview = safe_read_json(case_path / "environment-preview.json")
    intake_preview = safe_read_json(case_path / "intake-preview.json")
    result_json = safe_read_json(case_path / "result.json")
    invocation_json = safe_read_json(case_path / "invocation.json")
    workspace_json = safe_read_json(run_path / f"{case_run_id}-workspace.json")
    decisions_json = safe_read_json(run_path / f"{case_run_id}-decisions.json")

    console_log_path = run_path / f"{case_run_id}-console.log"
    console_log = ""
    if console_log_path.exists():
        try:
            console_log = console_log_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass

    ledger = extract_ledger_details(case_path / "ledger.sqlite")

    proposal_data = ledger.get("proposal")
    if not proposal_data and proposal_preview and isinstance(proposal_preview.get("proposal"), dict):
        proposal_data = proposal_preview["proposal"]

    planner_envelope = ledger.get("planner_envelope")
    if not planner_envelope and proposal_preview and isinstance(proposal_preview.get("dynamic_proposal"), dict):
        planner_envelope = proposal_preview["dynamic_proposal"]

    goal_text = ledger.get("goal") or (invocation_json or {}).get("goal") or ""
    scope_breakdown = (
        (case_summary or {}).get("scope_breakdown")
        or (proposal_preview or {}).get("scope_breakdown")
        or {}
    )

    mermaid_code = generate_mermaid_dag(proposal_data, result_json)

    return {
        "run_id": run_id,
        "case_run_id": case_run_id,
        "summary": case_summary,
        "goal": goal_text,
        "mermaid_dag": mermaid_code,
        "proposal": proposal_data,
        "planner_envelope": planner_envelope,
        "scope_breakdown": scope_breakdown,
        "proposal_preview": proposal_preview,
        "proposal_preview_rev0": proposal_preview_rev0,
        "environment_preview": environment_preview,
        "intake_preview": intake_preview,
        "workspace": workspace_json,
        "decisions": decisions_json,
        "result": result_json,
        "console_log": console_log,
        "events": events,
        "outbox": ledger["outbox"],
        "authorizations": ledger["authorizations"],
        "trace_events": ledger["trace_events"],
        "service_events": ledger["service_events"],
        "reviews": ledger["reviews"],
        "conflict_keys": ledger["conflict_keys"],
        "memos": ledger["memos"],
        "inference_attempts": ledger["inference_attempts"],
        "execution_outputs": ledger["execution_outputs"],
        "receiver_receipts": ledger["receiver_receipts"],
    }


def generate_mermaid_dag(proposal_data: Optional[Dict[str, Any]], result_json: Optional[Dict[str, Any]] = None) -> str:
    if not proposal_data:
        return "graph TD\n  Start([No Workflow Proposal — Stopped at Planning / Clarify / Capability Check])"

    spec = proposal_data.get("spec") or {}
    agents_list = spec.get("agents") or []
    workflow = spec.get("workflow") or {}
    nodes = workflow.get("nodes") or []

    node_status_map: Dict[str, str] = {}
    if result_json and isinstance(result_json.get("nodes"), dict):
        for nid, ninfo in result_json["nodes"].items():
            if isinstance(ninfo, dict):
                node_status_map[nid] = ninfo.get("phase") or ninfo.get("status") or ""

    agents_map = {}
    for a in agents_list:
        aid = a.get("id", "agent")
        role = a.get("role", "worker")
        caps = a.get("capabilities", [])
        tools = []
        for c in caps:
            t = c.get("tool")
            target = c.get("destination") or c.get("resource") or ""
            if t:
                tools.append(f"{t}({target})" if target else t)
        agents_map[aid] = {
            "role": role,
            "tools": tools,
        }

    lines = [
        "graph LR",
        "  classDef defaultBox fill:#0f172a,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;",
        "  classDef okBox fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#ecfdf5;",
        "  classDef errBox fill:#4c0519,stroke:#f43f5e,stroke-width:2px,color:#ffe4e6;",
    ]

    if not nodes:
        if agents_list:
            for aid, ainfo in agents_map.items():
                safe_id = aid.replace("-", "_")
                tools_str = "<br/>".join(ainfo["tools"]) if ainfo["tools"] else "none"
                lines.append(f'  {safe_id}["<b>{aid}</b> ({ainfo["role"]})<br/>{tools_str}"]:::defaultBox')
            return "\n".join(lines)
        return "graph TD\n  Start([No Workflow Nodes Proposed])"

    for n in nodes:
        nid = n.get("id", "node")
        safe_nid = nid.replace("-", "_")
        aid = n.get("agent", "agent")
        ainfo = agents_map.get(aid, {"role": "worker", "tools": []})
        tools_str = "<br/>".join(ainfo["tools"]) if ainfo["tools"] else "general"
        st = node_status_map.get(nid, "")
        st_line = f"<br/><i>[{st}]</i>" if st else ""
        cls = "defaultBox"
        if st in ("ACCEPTANCE_SATISFIED", "READS_DELIVERED", "SATISFIED", "DONE"):
            cls = "okBox"
        elif st in ("REFUSED", "FAILED", "CAP_EXHAUSTED"):
            cls = "errBox"
        label = f"<b>{nid}</b>: {aid} ({ainfo['role']})<br/>{tools_str}{st_line}".replace('"', "'")
        lines.append(f'  {safe_nid}["{label}"]:::{cls}')

    has_edges = False
    for n in nodes:
        nid = n.get("id", "node").replace("-", "_")
        deps = n.get("depends_on") or []
        for d in deps:
            safe_d = d.replace("-", "_")
            lines.append(f"  {safe_d} --> {nid}")
            has_edges = True

    if not has_edges and len(nodes) > 1:
        lines.append("  Start((Start))")
        for n in nodes:
            safe_nid = n.get("id", "node").replace("-", "_")
            lines.append(f"  Start --> {safe_nid}")

    return "\n".join(lines)


# --- API Routes ---

@app.get("/api/runs")
def api_runs():
    return list_available_runs()


@app.get("/api/run/{run_id}")
def api_run_details(run_id: str):
    return get_run_details(run_id)


@app.get("/api/run/{run_id}/verify-manifest")
def api_verify_manifest(run_id: str):
    run_path = RUNS_DIR / run_id
    if not run_path.exists() or not run_path.is_dir():
        raise HTTPException(status_code=404, detail="Run not found")
    return verify_manifest_hashes(run_path)


@app.get("/api/run/{run_id}/case/{case_run_id}")
def api_case_details(run_id: str, case_run_id: str):
    return get_case_details(run_id, case_run_id)


@app.get("/api/run/{run_id}/whitebox/{attack_id}")
def api_whitebox_attack(run_id: str, attack_id: str):
    run_path = RUNS_DIR / run_id
    wb_file = run_path / "whitebox-summary.json"
    if not wb_file.exists():
        raise HTTPException(status_code=404, detail="Whitebox summary not found")
    wb = safe_read_json(wb_file) or {}
    attack_obj = None
    for r in wb.get("results", []):
        if r.get("attack") == attack_id:
            attack_obj = r
            break
    if not attack_obj:
        raise HTTPException(status_code=404, detail="Attack not found")

    ledger = extract_ledger_details(run_path / attack_id / "ledger.sqlite")
    return {
        "run_id": run_id,
        "attack_id": attack_id,
        "attack": attack_obj,
        "ledger": ledger,
    }


# --- Frontend SPA HTML ---

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AtomicRoot — Runtime Authorization & Freshness Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            brand: { 50: '#f0f9ff', 100: '#e0f2fe', 500: '#0ea5e9', 600: '#0284c7', 700: '#0369a1' }
          }
        }
      }
    };
    mermaid.initialize({ startOnLoad: false, theme: 'dark', securityLevel: 'loose' });
  </script>
  <style>
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: #090d16; }
    ::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: #475569; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
  </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col font-sans selection:bg-sky-500/30">

  <!-- Top Navigation Bar -->
  <header class="bg-slate-900/95 backdrop-blur border-b border-slate-800 px-6 py-3 flex flex-wrap items-center justify-between gap-4 sticky top-0 z-50 shadow-lg">
    <div class="flex items-center gap-3">
      <div class="h-9 w-9 rounded-lg bg-gradient-to-tr from-sky-500 to-indigo-600 flex items-center justify-center font-bold text-white shadow-lg shadow-sky-500/20">
        AR
      </div>
      <div>
        <div class="flex items-center gap-2">
          <h1 class="text-base font-bold tracking-tight text-white">AtomicRoot</h1>
          <span class="text-[11px] px-2 py-0.5 rounded-full bg-sky-950 border border-sky-800 text-sky-400 font-mono">Read-Only Inspector</span>
        </div>
        <p class="text-xs text-slate-400">Consistent Snapshot, Policy Footprint, Z3 Authority, Single-Use Ticket & Atomic CAS</p>
      </div>
    </div>

    <!-- Controls & Run Selector -->
    <div class="flex flex-wrap items-center gap-2.5">
      <button onclick="toggleMatrixModal()" class="px-3 py-1.5 rounded-lg bg-indigo-950 hover:bg-indigo-900 text-indigo-300 border border-indigo-800 text-xs font-medium flex items-center gap-1.5 transition-colors">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M3 14h18m-9-4v8m-7 0h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
        <span>Cross-Suite Matrix</span>
      </button>

      <div class="flex items-center gap-2">
        <label for="runSelect" class="text-xs text-slate-400 font-medium">Run:</label>
        <select id="runSelect" onchange="onSelectRun(this.value)" class="bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-1.5 focus:ring-2 focus:ring-sky-500 focus:outline-none max-w-md font-mono">
          <option value="">Loading runs...</option>
        </select>
        <button onclick="refreshRuns()" class="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs" title="Reload .runs/">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
        </button>
      </div>
    </div>
  </header>

  <!-- Cross-Suite Comparison Matrix Panel (Collapsible) -->
  <section id="matrixPanel" class="hidden bg-slate-900 border-b border-slate-800 px-6 py-5 shadow-2xl">
    <div class="max-w-[1600px] mx-auto">
      <div class="flex items-center justify-between mb-3">
        <div>
          <h2 class="text-sm font-bold text-white uppercase tracking-wider">Cross-Suite Evaluation Matrix (v12 / v11 / v10 & White-Box)</h2>
          <p class="text-xs text-slate-400">Click any row to load that suite into the inspector below. Rates include numerator/denominator and Wilson 95% CI.</p>
        </div>
        <button onclick="toggleMatrixModal()" class="text-xs px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300">Close</button>
      </div>
      <div class="overflow-x-auto border border-slate-800 rounded-xl bg-slate-950">
        <table class="w-full text-left text-xs font-mono">
          <thead class="bg-slate-900 text-slate-400 border-b border-slate-800">
            <tr>
              <th class="py-2.5 px-3">Suite ID</th>
              <th class="py-2.5 px-3">Protocol / Commit</th>
              <th class="py-2.5 px-3">Overall Pass</th>
              <th class="py-2.5 px-3">Intent Correct</th>
              <th class="py-2.5 px-3">Planning Valid</th>
              <th class="py-2.5 px-3">Exec Completion</th>
              <th class="py-2.5 px-3">Fail-Closed Block</th>
              <th class="py-2.5 px-3">Forbidden Effects</th>
              <th class="py-2.5 px-3">Violations</th>
              <th class="py-2.5 px-3">Infra Error</th>
              <th class="py-2.5 px-3">Identical Resp</th>
              <th class="py-2.5 px-3">Calls</th>
            </tr>
          </thead>
          <tbody id="matrixTableBody" class="divide-y divide-slate-800/80 text-slate-300"></tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- Main Workspace -->
  <main class="flex-1 flex flex-col p-6 max-w-[1600px] w-full mx-auto gap-5">

    <!-- Run Summary & Provenance Banner -->
    <section id="runSummaryCard" class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm flex flex-col gap-4">
      <div class="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div class="flex flex-col gap-1">
          <div class="flex flex-wrap items-center gap-2">
            <h2 id="suiteTitle" class="text-xl font-bold tracking-tight text-white mono">Loading...</h2>
            <span id="suiteTypeBadge" class="text-xs px-2.5 py-0.5 rounded-full font-mono"></span>
            <span id="suiteFreezeBadge" class="text-xs px-2.5 py-0.5 rounded-full font-mono"></span>
          </div>
          <div id="suiteProvenanceText" class="text-xs text-slate-400 font-mono flex flex-wrap gap-x-4 gap-y-1 mt-1"></div>
        </div>

        <!-- Manifest SHA-256 Verification Box -->
        <div class="flex items-center gap-2">
          <div id="manifestBadge" class="text-xs px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center gap-2 font-mono">
            <span id="manifestDot" class="h-2 w-2 rounded-full bg-slate-500"></span>
            <span id="manifestText" class="text-slate-300">Checking manifest...</span>
          </div>
          <button onclick="verifyCurrentManifest()" class="px-2.5 py-1.5 rounded-lg bg-sky-950 hover:bg-sky-900 border border-sky-800 text-sky-300 text-xs font-mono transition-colors" title="Re-verify all file SHA-256 hashes">
            Verify SHA-256
          </button>
        </div>
      </div>

      <!-- 11-Metric Grid -->
      <div id="metricsGrid" class="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 xl:grid-cols-11 gap-2.5"></div>

      <!-- Determinism By Case Collapsible (only shown when determinism_by_case exists) -->
      <details id="determinismBox" class="hidden bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs">
        <summary class="cursor-pointer font-mono font-semibold text-sky-400">Determinism Breakdown by Case (10 Goal Texts × 2 Repetitions)</summary>
        <div id="determinismContent" class="mt-3 overflow-x-auto"></div>
      </details>
    </section>

    <!-- VIEW A: Whitebox Adversary Matrix & Drill-Down -->
    <section id="whiteboxView" class="hidden grid-cols-1 lg:grid-cols-12 gap-6 items-start">
      <div class="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col gap-3">
        <div class="flex items-center justify-between">
          <div>
            <h3 class="font-bold text-sm text-white">White-Box Adversary Attacks</h3>
            <p class="text-xs text-slate-400">Click any attack row to inspect its authorization decisions, resource taint snapshots, and SQLite ledger.</p>
          </div>
          <span id="wbCountBadge" class="text-xs px-2.5 py-1 rounded bg-emerald-950 border border-emerald-800 text-emerald-400 font-mono font-bold"></span>
        </div>
        <div class="overflow-x-auto max-h-[720px] border border-slate-800 rounded-lg bg-slate-950">
          <table class="w-full text-left text-xs font-mono">
            <thead class="bg-slate-900 text-slate-400 border-b border-slate-800 sticky top-0">
              <tr>
                <th class="py-2 px-3">Attack ID</th>
                <th class="py-2 px-3">Surface</th>
                <th class="py-2 px-3">Blocked By</th>
                <th class="py-2 px-3">Outcome</th>
                <th class="py-2 px-3 text-center">Blocked</th>
              </tr>
            </thead>
            <tbody id="whiteboxTableBody" class="divide-y divide-slate-800/80 text-slate-300"></tbody>
          </table>
        </div>
      </div>

      <!-- Whitebox Attack Detail Inspector -->
      <div class="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col gap-4 sticky top-20">
        <div id="wbEmptyState" class="text-center py-16 text-slate-500 text-xs">
          Select an attack on the left to inspect its authorization trace, untrusted resource snapshot, and guard block reason.
        </div>
        <div id="wbDetailContent" class="hidden flex-col gap-4"></div>
      </div>
    </section>

    <!-- VIEW B: Generic Folder View (for Phase 4/5/custom artifact folders) -->
    <section id="genericView" class="hidden bg-slate-900 border border-slate-800 rounded-xl p-5 flex-col gap-4">
      <h3 class="text-sm font-bold text-white">Artifact Folder Contents</h3>
      <div id="genericContent" class="flex flex-col gap-3"></div>
    </section>

    <!-- VIEW C: Standard System B / A Suite View (Cases List + 7-Tab Deep-Dive Inspector) -->
    <section id="suiteView" class="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">

      <!-- Left Column: Filterable Cases List (4 Cols) -->
      <div class="lg:col-span-4 bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col gap-3 max-h-[860px] sticky top-20">
        <div class="flex items-center justify-between">
          <h3 class="font-bold text-sm text-slate-200">Evaluation Cases</h3>
          <span id="casesCount" class="text-xs text-slate-400 font-mono">0 cases</span>
        </div>

        <!-- Search Bar -->
        <div class="relative">
          <input type="text" id="caseSearch" oninput="filterCases()" placeholder="Filter by case ID, outcome, tool, or pattern..." class="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500 font-mono pl-8" />
          <svg class="w-4 h-4 text-slate-500 absolute left-2.5 top-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
        </div>

        <!-- Filter Chips -->
        <div class="flex flex-wrap gap-1 text-[11px] pb-2 border-b border-slate-800/80 font-mono">
          <button onclick="setFilter('ALL')" class="filter-chip px-2 py-0.5 rounded bg-sky-600 text-white font-semibold" data-filter="ALL">All</button>
          <button onclick="setFilter('PASSED')" class="filter-chip px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-emerald-400" data-filter="PASSED">Pass</button>
          <button onclick="setFilter('FAILED')" class="filter-chip px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-rose-400" data-filter="FAILED">Fail</button>
          <button onclick="setFilter('SATISFIED')" class="filter-chip px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-sky-300" data-filter="SATISFIED">Satisfied</button>
          <button onclick="setFilter('CLARIFY')" class="filter-chip px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-amber-300" data-filter="CLARIFY">Clarify</button>
          <button onclick="setFilter('REFUSAL')" class="filter-chip px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-purple-300" data-filter="REFUSAL">Guard/Invalid</button>
          <button onclick="setFilter('CAPABILITY')" class="filter-chip px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-blue-300" data-filter="CAPABILITY">Capability</button>
          <button onclick="setFilter('POLICY')" class="filter-chip px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-indigo-300" data-filter="POLICY">Z3 Policy</button>
        </div>

        <!-- Cases Container -->
        <div id="casesList" class="flex flex-col gap-2 overflow-y-auto pr-1 flex-1 max-h-[680px]"></div>
      </div>

      <!-- Right Column: 7-Tab Case Deep-Dive Inspector (8 Cols) -->
      <div class="lg:col-span-8 bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col gap-4 min-h-[600px]">
        <div id="caseEmptyState" class="flex flex-col items-center justify-center p-20 text-center text-slate-500">
          <p class="text-sm font-medium">Select a case on the left to inspect its full execution & authorization trace</p>
        </div>

        <div id="caseDetailView" class="hidden flex-col gap-4">
          <!-- Case Header & Oracles -->
          <div class="flex flex-col gap-3 border-b border-slate-800 pb-4">
            <div class="flex flex-wrap items-start justify-between gap-4">
              <div class="flex flex-wrap items-center gap-2">
                <h3 id="detailCaseId" class="text-lg font-bold text-white mono">case-id</h3>
                <span id="detailOutcomeBadge" class="text-xs px-2.5 py-0.5 rounded-full font-mono"></span>
                <span id="detailPassedBadge" class="text-xs px-2 py-0.5 rounded font-mono"></span>
                <span id="detailPatternBadge" class="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono"></span>
              </div>
              <div id="detailMetaPills" class="flex flex-wrap items-center gap-2 font-mono text-xs text-slate-400"></div>
            </div>

            <!-- Goal Prompt Box -->
            <div class="bg-sky-950/30 border border-sky-900/60 rounded-lg p-3">
              <div class="text-[10px] font-mono uppercase tracking-wider text-sky-400 mb-1 font-semibold">User Goal Prompt</div>
              <p id="detailGoalPrompt" class="text-xs text-slate-100 leading-relaxed font-mono"></p>
            </div>

            <!-- Dual Oracle Verification Bar (Goal Oracle + Phase 5 Invariant Oracle) -->
            <div id="detailOraclesBar" class="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono"></div>
          </div>

          <!-- 7-Tab Navigation -->
          <div class="flex flex-wrap items-center gap-1 border-b border-slate-800 text-xs font-medium">
            <button onclick="switchTab('tabDag')" id="btnTabDag" class="tab-btn px-3 py-2 border-b-2 border-sky-500 text-sky-400">1. DAG, Agents & Scope</button>
            <button onclick="switchTab('tabPolicy')" id="btnTabPolicy" class="tab-btn px-3 py-2 border-b-2 border-transparent text-slate-400 hover:text-slate-200">2. Z3 Policy & Catalog</button>
            <button onclick="switchTab('tabTimeline')" id="btnTabTimeline" class="tab-btn px-3 py-2 border-b-2 border-transparent text-slate-400 hover:text-slate-200">
              3. Guard Timeline <span id="eventsCountBadge" class="ml-1 px-1.5 py-0.2 rounded-full bg-slate-800 text-[10px]">0</span>
            </button>
            <button onclick="switchTab('tabTickets')" id="btnTabTickets" class="tab-btn px-3 py-2 border-b-2 border-transparent text-slate-400 hover:text-slate-200">
              4. Tickets & Trace <span id="ticketsCountBadge" class="ml-1 px-1.5 py-0.2 rounded-full bg-slate-800 text-[10px]">0</span>
            </button>
            <button onclick="switchTab('tabOutbox')" id="btnTabOutbox" class="tab-btn px-3 py-2 border-b-2 border-transparent text-slate-400 hover:text-slate-200">
              5. Outbox & Receipts <span id="outboxCountBadge" class="ml-1 px-1.5 py-0.2 rounded-full bg-slate-800 text-[10px]">0</span>
            </button>
            <button onclick="switchTab('tabKeys')" id="btnTabKeys" class="tab-btn px-3 py-2 border-b-2 border-transparent text-slate-400 hover:text-slate-200">
              6. CAS Snapshot Keys <span id="keysCountBadge" class="ml-1 px-1.5 py-0.2 rounded-full bg-slate-800 text-[10px]">0</span>
            </button>
            <button onclick="switchTab('tabMemos')" id="btnTabMemos" class="tab-btn px-3 py-2 border-b-2 border-transparent text-slate-400 hover:text-slate-200">
              7. LLM Memos & Log <span id="memosCountBadge" class="ml-1 px-1.5 py-0.2 rounded-full bg-slate-800 text-[10px]">0</span>
            </button>
          </div>

          <!-- TAB 1: Workflow DAG, Agents, Scope Breakdown, Origin & Clarify/Bundle -->
          <div id="tabDag" class="tab-content flex flex-col gap-4">
            <div class="bg-slate-950 border border-slate-800 rounded-lg p-4 flex flex-col">
              <div class="flex items-center justify-between mb-2">
                <span class="text-xs text-slate-400 font-mono font-semibold">Visual Agent Workflow DAG</span>
                <span id="replanBadge" class="hidden text-[11px] px-2 py-0.5 rounded bg-indigo-950 border border-indigo-800 text-indigo-300 font-mono">Replanned after Stale Read (rev0 → rev1)</span>
              </div>
              <div id="mermaidContainer" class="w-full flex justify-center py-2 overflow-x-auto"></div>
            </div>

            <!-- Special Box: Clarification Questions / Permission Bundle / Capability Requests -->
            <div id="detailSpecialBox" class="hidden bg-slate-950 border border-amber-800/70 rounded-lg p-4 flex flex-col gap-2"></div>

            <!-- Agents & Delegated Capabilities -->
            <div class="bg-slate-950 border border-slate-800 rounded-lg p-4 flex flex-col gap-2">
              <h4 class="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">Proposed Agents & Per-Agent Delegated Capabilities</h4>
              <div id="agentsContent" class="grid grid-cols-1 md:grid-cols-2 gap-2.5 text-xs font-mono"></div>
            </div>

            <!-- Scope Breakdown (Model Selected vs Host Derived vs Host Context Egress) -->
            <div class="bg-slate-950 border border-slate-800 rounded-lg p-4 flex flex-col gap-2">
              <h4 class="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">Trusted Resolution Scope Breakdown</h4>
              <div id="scopeBreakdownContent" class="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono"></div>
            </div>

            <!-- Origin Mapping, Assumptions & Unsupported -->
            <div class="bg-slate-950 border border-slate-800 rounded-lg p-4 flex flex-col gap-2">
              <h4 class="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">Origin Mapping, Assumptions & Unsupported Requirements</h4>
              <div id="originContent" class="text-xs font-mono flex flex-col gap-2"></div>
            </div>

            <!-- Raw Proposal JSON -->
            <details class="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs">
              <summary class="cursor-pointer text-slate-400 hover:text-slate-200 font-mono font-semibold">View Full Proposal & Planner Envelope JSON</summary>
              <pre id="rawProposalJson" class="mt-2 text-slate-300 overflow-x-auto max-h-80 p-2.5 bg-slate-900 rounded font-mono text-[11px]"></pre>
            </details>
          </div>

          <!-- TAB 2: Synthesized Policies, Z3 Probe & Workspace Catalog -->
          <div id="tabPolicy" class="tab-content hidden flex flex-col gap-4">
            <div class="bg-slate-950 border border-slate-800 rounded-lg p-4 flex flex-col gap-2">
              <h4 class="text-xs font-bold text-sky-400 uppercase tracking-wider font-mono">Synthesized DSL Policies (Evaluated by Z3)</h4>
              <div id="detailPolicyContent" class="text-xs text-slate-300 font-mono"></div>
            </div>

            <div class="bg-slate-950 border border-slate-800 rounded-lg p-4 flex flex-col gap-2">
              <h4 class="text-xs font-bold text-indigo-400 uppercase tracking-wider font-mono">Z3 Policy Boundary Probe Checks</h4>
              <div id="detailZ3ProbeContent" class="text-xs text-slate-300 font-mono"></div>
            </div>

            <div class="bg-slate-950 border border-slate-800 rounded-lg p-4 flex flex-col gap-2">
              <h4 class="text-xs font-bold text-emerald-400 uppercase tracking-wider font-mono">Workspace Catalog, Authoritative Confidentiality Labels & Entitlement</h4>
              <div id="workspaceCatalogContent" class="text-xs text-slate-300 font-mono flex flex-col gap-3"></div>
            </div>
          </div>

          <!-- TAB 3: Guard Timeline & Broker Reviews -->
          <div id="tabTimeline" class="tab-content hidden flex flex-col gap-4">
            <div class="bg-slate-950 border border-slate-800 rounded-lg p-4 flex flex-col gap-2">
              <h4 class="text-xs font-bold text-amber-400 uppercase tracking-wider font-mono">Reviewer & Approval Broker Grants</h4>
              <div id="reviewsContent" class="text-xs font-mono"></div>
            </div>

            <div class="bg-slate-950 border border-slate-800 rounded-lg p-4 flex flex-col gap-2">
              <h4 class="text-xs font-bold text-sky-400 uppercase tracking-wider font-mono">Guard Progress Timeline (progress.jsonl)</h4>
              <div class="overflow-x-auto">
                <table class="w-full text-left text-xs font-mono">
                  <thead class="bg-slate-900 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th class="py-2 px-3">#</th>
                      <th class="py-2 px-3">Event</th>
                      <th class="py-2 px-3">Tool</th>
                      <th class="py-2 px-3">Status</th>
                      <th class="py-2 px-3">Details / Error</th>
                    </tr>
                  </thead>
                  <tbody id="timelineTableBody" class="divide-y divide-slate-800 text-slate-300"></tbody>
                </table>
              </div>
            </div>

            <details class="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs">
              <summary class="cursor-pointer text-slate-400 hover:text-slate-200 font-mono font-semibold">View Low-Level Ledger Service Events</summary>
              <div id="serviceEventsContent" class="mt-2 overflow-x-auto max-h-80"></div>
            </details>
          </div>

          <!-- TAB 4: Signed Tickets & Trace Store -->
          <div id="tabTickets" class="tab-content hidden flex flex-col gap-4">
            <div class="bg-slate-950 border border-slate-800 rounded-lg p-4 flex flex-col gap-2">
              <h4 class="text-xs font-bold text-sky-400 uppercase tracking-wider font-mono">Trace Store Committed Events (Single-Use Ticket & Write-Set Binding)</h4>
              <div id="traceEventsContent" class="overflow-x-auto text-xs font-mono"></div>
            </div>

            <div class="bg-slate-950 border border-slate-800 rounded-lg p-4 flex flex-col gap-2">
              <h4 class="text-xs font-bold text-indigo-400 uppercase tracking-wider font-mono">Issued Authorization Records (PyNaCl Signed Tickets & Footprint)</h4>
              <div id="authorizationsContent" class="flex flex-col gap-2 text-xs font-mono"></div>
            </div>
          </div>

          <!-- TAB 5: Outbox, Receipts & Authored Outputs -->
          <div id="tabOutbox" class="tab-content hidden flex flex-col gap-4">
            <div class="bg-slate-950 border border-slate-800 rounded-lg p-4 flex flex-col gap-2">
              <h4 class="text-xs font-bold text-emerald-400 uppercase tracking-wider font-mono">Completion Criteria & Verified Evidence (result.json)</h4>
              <div id="completionCriteriaContent" class="text-xs font-mono"></div>
            </div>

            <div class="bg-slate-950 border border-slate-800 rounded-lg p-4 flex flex-col gap-2">
              <h4 class="text-xs font-bold text-sky-400 uppercase tracking-wider font-mono">Atomic Effect Outbox (COMMITTED → RELEASED)</h4>
              <div class="overflow-x-auto">
                <table class="w-full text-left text-xs font-mono">
                  <thead class="bg-slate-900 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th class="py-2 px-3">Op ID</th>
                      <th class="py-2 px-3">Agent</th>
                      <th class="py-2 px-3">Amount</th>
                      <th class="py-2 px-3">Payload</th>
                      <th class="py-2 px-3">Status</th>
                      <th class="py-2 px-3">Receipt</th>
                    </tr>
                  </thead>
                  <tbody id="outboxTableBody" class="divide-y divide-slate-800 text-slate-300"></tbody>
                </table>
              </div>
            </div>

            <div class="bg-slate-950 border border-slate-800 rounded-lg p-4 flex flex-col gap-2">
              <h4 class="text-xs font-bold text-purple-400 uppercase tracking-wider font-mono">Published Authored Outputs (execution_outputs)</h4>
              <div id="outputsContent" class="text-xs font-mono"></div>
            </div>
          </div>

          <!-- TAB 6: Conflict Keys (CAS Snapshot) -->
          <div id="tabKeys" class="tab-content hidden flex flex-col gap-3">
            <div class="flex flex-wrap items-center justify-between gap-2">
              <p class="text-xs text-slate-400">Per-key conflict versions in <code class="text-sky-300">ledger.sqlite</code> enforcing atomic freshness at commit:</p>
              <input type="text" id="keySearch" oninput="filterConflictKeys()" placeholder="Filter keys (e.g. budget, res:, contract3)..." class="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-500 w-64" />
            </div>
            <div class="overflow-x-auto bg-slate-950 border border-slate-800 rounded-lg max-h-[560px]">
              <table class="w-full text-left text-xs font-mono">
                <thead class="bg-slate-900 text-slate-400 border-b border-slate-800 sticky top-0">
                  <tr>
                    <th class="py-2 px-3">Conflict Key</th>
                    <th class="py-2 px-3">Version</th>
                    <th class="py-2 px-3">Snapshot Value</th>
                  </tr>
                </thead>
                <tbody id="keysTableBody" class="divide-y divide-slate-800 text-slate-300"></tbody>
              </table>
            </div>
          </div>

          <!-- TAB 7: LLM Memos, Token Usage & Console Log -->
          <div id="tabMemos" class="tab-content hidden flex flex-col gap-4">
            <div class="bg-slate-950 border border-slate-800 rounded-lg p-4 flex flex-col gap-2">
              <h4 class="text-xs font-bold text-indigo-400 uppercase tracking-wider font-mono">Model Inference Attempts & Token Usage</h4>
              <div id="attemptsContent" class="overflow-x-auto text-xs font-mono"></div>
            </div>

            <div id="memosContainer" class="flex flex-col gap-3"></div>

            <div class="bg-slate-950 border border-slate-800 rounded-lg p-4 flex flex-col gap-2">
              <h4 class="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono">Runner Console Log</h4>
              <pre id="consoleLogContent" class="text-[11px] font-mono text-slate-300 bg-slate-900 p-3 rounded overflow-x-auto max-h-80"></pre>
            </div>
          </div>

        </div>
      </div>
    </section>

  </main>

  <script>
    let currentRuns = [];
    let currentRunData = null;
    let currentCaseData = null;
    let currentFilter = 'ALL';

    const GROUP_LABELS = {
      '1_v12_suites': 'v12 Final Evaluation Suites',
      '2_whitebox': 'White-Box Adversary Suites (Offline)',
      '3_v10_v11_suites': 'v10 & v11 Historical Suites',
      '4_other_suites': 'Phase 5.5 & Legacy Suites',
      '5_single_or_other': 'Single Runs & Phase Artifacts'
    };

    function esc(s) {
      if (s === null || s === undefined) return '';
      return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    async function init() {
      await refreshRuns();
    }

    async function refreshRuns() {
      try {
        const res = await fetch('/api/runs');
        currentRuns = await res.json();
        const sel = document.getElementById('runSelect');
        sel.innerHTML = '';

        const grouped = {};
        currentRuns.forEach(r => {
          grouped[r.group] = grouped[r.group] || [];
          grouped[r.group].push(r);
        });

        Object.keys(GROUP_LABELS).forEach(gkey => {
          const items = grouped[gkey];
          if (!items || items.length === 0) return;
          const og = document.createElement('optgroup');
          og.label = GROUP_LABELS[gkey];
          items.forEach(r => {
            const opt = document.createElement('option');
            opt.value = r.id;
            const pr = r.pass_rate ? ` [${r.pass_rate}]` : '';
            const warn = r.has_infra_errors ? ' (infra-drop)' : '';
            opt.textContent = `${r.id}${pr}${warn}`;
            og.appendChild(opt);
          });
          sel.appendChild(og);
        });

        renderCrossSuiteMatrix();

        const preferred = currentRuns.find(r => r.id === 'v12-heldout-v2') || currentRuns[0];
        if (preferred) {
          sel.value = preferred.id;
          await onSelectRun(preferred.id);
        }
      } catch (err) {
        console.error('Failed to fetch runs:', err);
      }
    }

    function toggleMatrixModal() {
      document.getElementById('matrixPanel').classList.toggle('hidden');
    }

    function fmtMetricCell(m, invertColor = false) {
      if (!m || m.denominator === undefined) return '<span class="text-slate-600">—</span>';
      if (m.denominator === 0) return '<span class="text-slate-500">0/0 (N/A)</span>';
      const w = (m.wilson95 && m.wilson95.length === 2) ? `<div class="text-[10px] text-slate-500">[${m.wilson95[0]}, ${m.wilson95[1]}]</div>` : '';
      let color = 'text-slate-200';
      if (invertColor) {
        color = m.numerator === 0 ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold';
      } else {
        color = m.numerator === m.denominator ? 'text-emerald-400 font-bold' : 'text-amber-300 font-bold';
      }
      return `<div class="${color}">${m.numerator}/${m.denominator}</div>${w}`;
    }

    function renderCrossSuiteMatrix() {
      const tbody = document.getElementById('matrixTableBody');
      tbody.innerHTML = '';
      const suites = currentRuns.filter(r => r.type === 'suite' || r.type === 'whitebox');
      suites.forEach(r => {
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-slate-900/80 cursor-pointer transition-colors';
        tr.onclick = () => {
          document.getElementById('runSelect').value = r.id;
          onSelectRun(r.id);
          document.getElementById('matrixPanel').classList.add('hidden');
        };
        if (r.type === 'whitebox') {
          tr.innerHTML = `
            <td class="py-2 px-3 font-bold text-purple-300">${esc(r.id)}</td>
            <td class="py-2 px-3 text-slate-400">whitebox (${esc(r.commit || '-')})</td>
            <td class="py-2 px-3 text-emerald-400 font-bold">${esc(r.pass_rate)}</td>
            <td colspan="9" class="py-2 px-3 text-slate-400">Offline deterministic white-box adversary suite (no LLM calls)</td>
          `;
        } else {
          const a = r.aggregate || {};
          tr.innerHTML = `
            <td class="py-2 px-3 font-bold text-sky-300">${esc(r.id)}</td>
            <td class="py-2 px-3 text-slate-400">${esc(r.protocol || '-')} <span class="text-slate-500">(${esc(r.commit || '-')})</span></td>
            <td class="py-2 px-3">${fmtMetricCell(a.overall_pass_rate)}</td>
            <td class="py-2 px-3">${fmtMetricCell(a.intent_correct_rate)}</td>
            <td class="py-2 px-3">${fmtMetricCell(a.planning_valid_rate)}</td>
            <td class="py-2 px-3">${fmtMetricCell(a.executable_completion_rate)}</td>
            <td class="py-2 px-3">${fmtMetricCell(a.fail_closed_block_rate)}</td>
            <td class="py-2 px-3">${fmtMetricCell(a.forbidden_effect_runs, true)}</td>
            <td class="py-2 px-3">${fmtMetricCell(a.accepted_violation_rate, true)}</td>
            <td class="py-2 px-3">${fmtMetricCell(a.infra_error_runs, true)}</td>
            <td class="py-2 px-3">${fmtMetricCell(a.identical_response_rate)}</td>
            <td class="py-2 px-3 text-indigo-300">${r.total_calls ?? '-'}/${r.max_total_calls ?? '-'}</td>
          `;
        }
        tbody.appendChild(tr);
      });
    }

    async function onSelectRun(runId) {
      if (!runId) return;
      document.getElementById('suiteTitle').textContent = `Loading ${runId}...`;
      try {
        const res = await fetch(`/api/run/${encodeURIComponent(runId)}`);
        currentRunData = await res.json();
        renderRunView();
      } catch (err) {
        console.error('Failed to load run details:', err);
      }
    }

    async function verifyCurrentManifest() {
      if (!currentRunData) return;
      const txt = document.getElementById('manifestText');
      const dot = document.getElementById('manifestDot');
      txt.textContent = 'Verifying SHA-256...';
      dot.className = 'h-2 w-2 rounded-full bg-amber-400 animate-ping';
      try {
        const res = await fetch(`/api/run/${encodeURIComponent(currentRunData.id)}/verify-manifest`);
        const m = await res.json();
        if (!m.exists) {
          dot.className = 'h-2 w-2 rounded-full bg-slate-500';
          txt.textContent = 'No MANIFEST.sha256';
        } else if (m.verified) {
          dot.className = 'h-2 w-2 rounded-full bg-emerald-400';
          txt.textContent = `SHA-256 Verified (${m.total_files}/${m.total_files} files, 0 bad, 0 extra)`;
        } else {
          dot.className = 'h-2 w-2 rounded-full bg-rose-500';
          txt.textContent = `Mismatch! bad=${m.bad_hashes}, extra=${m.extra_files}, missing=${m.missing_files}`;
        }
      } catch (e) {
        txt.textContent = 'Verify failed';
      }
    }

    function renderRunView() {
      const data = currentRunData;
      if (!data) return;

      document.getElementById('suiteTitle').textContent = data.id;
      const typeBadge = document.getElementById('suiteTypeBadge');
      const freezeBadge = document.getElementById('suiteFreezeBadge');
      const provText = document.getElementById('suiteProvenanceText');
      const p = data.provenance || {};

      const gitHead = p.git?.head ? p.git.head.slice(0, 7) : '—';
      const dirty = p.git?.dirty_tracked;
      const freezeMatched = p.freeze?.matched;
      const baseCommit = p.freeze?.base_commit ? p.freeze.base_commit.slice(0, 7) : '—';
      const modelName = data.model || p.model?.name || 'Offline';
      const modelDigest = p.model?.digest ? p.model.digest.slice(0, 12) : '—';
      const opts = p.model?.options ? JSON.stringify(p.model.options) : '';
      const started = p.started?.observed_at_utc ? p.started.observed_at_utc.replace('T', ' ').slice(0, 19) + ' UTC' : '—';
      const finished = p.finished?.observed_at_utc ? p.finished.observed_at_utc.replace('T', ' ').slice(0, 19) + ' UTC' : (p.stopped ? 'STOPPED' : '—');

      if (freezeMatched === true) {
        freezeBadge.textContent = `FREEZE MATCHED (${baseCommit})`;
        freezeBadge.className = 'text-xs px-2.5 py-0.5 rounded-full font-mono bg-emerald-950 border border-emerald-800 text-emerald-400';
      } else if (freezeMatched === false) {
        freezeBadge.textContent = 'FREEZE UNMATCHED';
        freezeBadge.className = 'text-xs px-2.5 py-0.5 rounded-full font-mono bg-rose-950 border border-rose-800 text-rose-400';
      } else {
        freezeBadge.textContent = 'NO FREEZE METADATA';
        freezeBadge.className = 'text-xs px-2.5 py-0.5 rounded-full font-mono bg-slate-800 border border-slate-700 text-slate-400';
      }

      provText.innerHTML = `
        <span><b>Git:</b> ${esc(gitHead)} (dirty=${esc(dirty)})</span>
        <span><b>Protocol:</b> ${esc(data.protocol || p.protocol || '—')}</span>
        <span><b>Reviewer:</b> ${esc(data.reviewer || p.reviewer || '—')}</span>
        <span><b>Model:</b> ${esc(modelName)} (${esc(modelDigest)}) ${esc(opts)}</span>
        <span><b>Window:</b> ${esc(started)} → ${esc(finished)}</span>
      `;

      // Manifest indicator
      const mDot = document.getElementById('manifestDot');
      const mTxt = document.getElementById('manifestText');
      if (data.manifest && data.manifest.exists) {
        mDot.className = 'h-2 w-2 rounded-full bg-emerald-400';
        mTxt.textContent = `MANIFEST.sha256 (${data.manifest.total_files} files)`;
      } else {
        mDot.className = 'h-2 w-2 rounded-full bg-slate-500';
        mTxt.textContent = 'No MANIFEST.sha256';
      }

      // Hide all views first
      document.getElementById('whiteboxView').classList.add('hidden');
      document.getElementById('whiteboxView').classList.remove('grid');
      document.getElementById('suiteView').classList.add('hidden');
      document.getElementById('genericView').classList.add('hidden');
      document.getElementById('determinismBox').classList.add('hidden');

      if (data.type === 'whitebox') {
        typeBadge.textContent = 'WHITE-BOX ADVERSARY';
        typeBadge.className = 'text-xs px-2.5 py-0.5 rounded-full font-mono bg-purple-950 border border-purple-800 text-purple-400';
        document.getElementById('whiteboxView').classList.remove('hidden');
        document.getElementById('whiteboxView').classList.add('grid');
        renderWhiteboxMetrics(data);
        renderWhitebox(data);
      } else if (data.type === 'suite') {
        typeBadge.textContent = 'EVALUATION SUITE';
        typeBadge.className = 'text-xs px-2.5 py-0.5 rounded-full font-mono bg-sky-950 border border-sky-800 text-sky-400';
        document.getElementById('suiteView').classList.remove('hidden');
        renderSuiteMetrics(data);
        renderDeterminismBox(data);
        renderCasesList(data.runs || []);
        if (data.runs && data.runs.length > 0) {
          selectCase(data.runs[0].run_id);
        }
      } else {
        typeBadge.textContent = 'ARTIFACT FOLDER';
        typeBadge.className = 'text-xs px-2.5 py-0.5 rounded-full font-mono bg-slate-800 border border-slate-700 text-slate-300';
        document.getElementById('genericView').classList.remove('hidden');
        document.getElementById('metricsGrid').innerHTML = '';
        renderGenericView(data);
      }
    }

    function renderWhiteboxMetrics(data) {
      const grid = document.getElementById('metricsGrid');
      const b = data.blocked || { numerator: 0, denominator: data.attacks || 0 };
      grid.innerHTML = `
        <div class="col-span-2 bg-slate-950 border border-slate-800 rounded-lg p-3">
          <div class="text-[11px] text-slate-400">Blocked Attacks</div>
          <div class="text-xl font-bold text-emerald-400 font-mono">${b.numerator}/${b.denominator}</div>
          <div class="text-[10px] text-slate-500 font-mono">100% Blocked within Threat Model</div>
        </div>
        <div class="col-span-3 bg-slate-950 border border-slate-800 rounded-lg p-3">
          <div class="text-[11px] text-slate-400">Case File & Digest</div>
          <div class="text-xs font-bold text-sky-300 font-mono truncate">${esc(data.case_file || 'adversarial-cases.json')}</div>
          <div class="text-[10px] text-slate-500 font-mono truncate">${esc(data.case_file_digest || '')}</div>
        </div>
      `;
    }

    function renderSuiteMetrics(data) {
      const agg = data.aggregate || {};
      const grid = document.getElementById('metricsGrid');
      grid.innerHTML = '';

      function mCard(label, m, invert = false, customVal = null, customSub = null) {
        if (customVal !== null) {
          return `
            <div class="bg-slate-950/90 border border-slate-800/90 rounded-lg p-2.5 flex flex-col justify-between">
              <span class="text-[10px] text-slate-400 font-medium truncate" title="${esc(label)}">${esc(label)}</span>
              <span class="text-base font-bold text-indigo-400 font-mono mt-0.5">${esc(customVal)}</span>
              <span class="text-[10px] text-slate-500 font-mono truncate">${esc(customSub || '')}</span>
            </div>
          `;
        }
        if (!m || m.denominator === undefined || m.denominator === 0) {
          return `
            <div class="bg-slate-950/60 border border-slate-800/60 rounded-lg p-2.5 flex flex-col justify-between">
              <span class="text-[10px] text-slate-400 font-medium truncate" title="${esc(label)}">${esc(label)}</span>
              <span class="text-sm font-bold text-slate-500 font-mono mt-0.5">0/0 (N/A)</span>
              <span class="text-[10px] text-slate-600 font-mono">N/A</span>
            </div>
          `;
        }
        const wilson = (m.wilson95 && m.wilson95.length === 2) ? `[${m.wilson95[0]}, ${m.wilson95[1]}]` : '';
        let color = 'text-slate-100';
        if (invert) {
          color = m.numerator === 0 ? 'text-emerald-400' : 'text-rose-400';
        } else {
          color = m.numerator === m.denominator ? 'text-emerald-400' : 'text-amber-400';
        }
        return `
          <div class="bg-slate-950/90 border border-slate-800/90 rounded-lg p-2.5 flex flex-col justify-between">
            <span class="text-[10px] text-slate-400 font-medium truncate" title="${esc(label)}">${esc(label)}</span>
            <span class="text-base font-bold ${color} font-mono mt-0.5">${m.numerator}/${m.denominator}</span>
            <span class="text-[10px] text-slate-500 font-mono truncate" title="Wilson 95%: ${wilson}">${wilson || 'CI N/A'}</span>
          </div>
        `;
      }

      grid.innerHTML += mCard('Overall Pass', agg.overall_pass_rate);
      grid.innerHTML += mCard('Intent Correct', agg.intent_correct_rate);
      grid.innerHTML += mCard('Planning Valid', agg.planning_valid_rate);
      grid.innerHTML += mCard('Exec Completion', agg.executable_completion_rate);
      grid.innerHTML += mCard('Fail-Closed Block', agg.fail_closed_block_rate);
      grid.innerHTML += mCard('Forbidden Intent', agg.forbidden_effect_runs, true);
      grid.innerHTML += mCard('Forbidden Deliv', agg.forbidden_delivered_runs, true);
      grid.innerHTML += mCard('Accepted Viol', agg.accepted_violation_rate, true);
      grid.innerHTML += mCard('Delivered Viol', agg.delivered_violation_rate, true);
      grid.innerHTML += mCard('Infra Errors', agg.infra_error_runs, true);
      if (agg.identical_response_rate && agg.identical_response_rate.denominator > 0) {
        grid.innerHTML += mCard('Identical Resp', agg.identical_response_rate);
      } else {
        grid.innerHTML += mCard('Calls / Distinct', null, false, `${data.total_calls ?? '-'} / ${data.max_total_calls ?? '∞'}`, `${agg.distinct_goal_texts || agg.total_runs || 0} distinct goals`);
      }
    }

    function renderDeterminismBox(data) {
      const det = data.determinism_by_case;
      const box = document.getElementById('determinismBox');
      const content = document.getElementById('determinismContent');
      if (!det || Object.keys(det).length === 0) {
        box.classList.add('hidden');
        return;
      }
      box.classList.remove('hidden');
      let rows = '';
      Object.entries(det).forEach(([cid, info]) => {
        const ok = info.identical;
        rows += `
          <tr class="border-b border-slate-800/60">
            <td class="py-1.5 px-3 font-bold text-sky-300">${esc(cid)}</td>
            <td class="py-1.5 px-3">${info.runs}</td>
            <td class="py-1.5 px-3 text-slate-400">${(info.unique_digests || []).join(', ')}</td>
            <td class="py-1.5 px-3 font-bold ${ok ? 'text-emerald-400' : 'text-amber-400'}">${ok ? 'BYTE-IDENTICAL' : 'DIFFERENT'}</td>
          </tr>
        `;
      });
      content.innerHTML = `
        <table class="w-full text-left text-xs font-mono">
          <thead class="bg-slate-900 text-slate-400">
            <tr><th class="py-1.5 px-3">Case</th><th class="py-1.5 px-3">Reps</th><th class="py-1.5 px-3">Planner Output Digest(s)</th><th class="py-1.5 px-3">Status</th></tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      `;
    }

    function renderGenericView(data) {
      const container = document.getElementById('genericContent');
      const files = (data.files || []).map(f => `<span class="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300">${esc(f)}</span>`).join(' ');
      const previews = Object.entries(data.summary || {}).map(([k, v]) => `
        <div class="bg-slate-950 border border-slate-800 rounded-lg p-3">
          <div class="text-xs font-bold text-sky-400 font-mono mb-1">${esc(k)}</div>
          <pre class="text-[11px] font-mono text-slate-300 overflow-x-auto max-h-80">${esc(typeof v === 'string' ? v : JSON.stringify(v, null, 2))}</pre>
        </div>
      `).join('');
      container.innerHTML = `<div class="flex flex-wrap gap-1.5 mb-2">${files}</div>${previews}`;
    }

    function renderCasesList(cases) {
      document.getElementById('casesCount').textContent = `${cases.length} cases`;
      filterCases();
    }

    function getOutcomeBadgeClass(outcome) {
      switch(outcome) {
        case 'SATISFIED': return 'bg-emerald-950/80 border-emerald-800 text-emerald-300';
        case 'CLARIFY': return 'bg-amber-950/80 border-amber-800 text-amber-300';
        case 'VALID_GUARD_REFUSAL': return 'bg-purple-950/80 border-purple-800 text-purple-300';
        case 'NEEDS_CAPABILITY': return 'bg-blue-950/80 border-blue-800 text-blue-300';
        case 'PLANNER_INVALID': return 'bg-orange-950/80 border-orange-800 text-orange-300';
        case 'INFRA_ERROR': return 'bg-rose-950/80 border-rose-800 text-rose-300';
        default: return 'bg-slate-800 border-slate-700 text-slate-300';
      }
    }

    function filterCases() {
      if (!currentRunData || !currentRunData.runs) return;
      const query = (document.getElementById('caseSearch').value || '').toLowerCase();
      const container = document.getElementById('casesList');
      container.innerHTML = '';

      const filtered = currentRunData.runs.filter(c => {
        const text = `${c.run_id} ${c.case || ''} ${c.pattern || ''} ${c.outcome || ''}`.toLowerCase();
        if (!text.includes(query)) return false;

        if (currentFilter === 'PASSED') return c.passed;
        if (currentFilter === 'FAILED') return !c.passed;
        if (currentFilter === 'SATISFIED') return c.outcome === 'SATISFIED';
        if (currentFilter === 'CLARIFY') return c.outcome === 'CLARIFY';
        if (currentFilter === 'REFUSAL') return c.outcome === 'VALID_GUARD_REFUSAL' || c.outcome === 'PLANNER_INVALID';
        if (currentFilter === 'CAPABILITY') return c.outcome === 'NEEDS_CAPABILITY';
        if (currentFilter === 'POLICY') return (c.policy_count > 0) || Boolean(c.z3_policy_probe);
        return true;
      });

      if (filtered.length === 0) {
        container.innerHTML = '<div class="text-xs text-slate-500 p-4 text-center font-mono">No matching cases</div>';
        return;
      }

      filtered.forEach(c => {
        const item = document.createElement('div');
        item.dataset.runid = c.run_id;
        item.className = 'case-card p-3 rounded-lg bg-slate-950 border border-slate-800 hover:border-sky-600/60 cursor-pointer flex flex-col gap-1.5 transition-all';
        item.onclick = () => selectCase(c.run_id);

        const passColor = c.passed ? 'bg-emerald-950 text-emerald-400 border-emerald-800' : 'bg-rose-950 text-rose-400 border-rose-800';
        const outcomeColor = getOutcomeBadgeClass(c.outcome);
        const probeBadge = c.z3_policy_probe ? `<span class="text-[10px] px-1.5 py-0.5 rounded bg-indigo-950 border border-indigo-800 text-indigo-300 font-mono">Z3:${c.z3_policy_probe.ok ? 'OK' : 'FAIL'}</span>` : '';
        const forbCnt = c.goal_oracle?.forbidden_effect_count || 0;
        const forbBadge = forbCnt > 0 ? `<span class="text-[10px] px-1.5 py-0.5 rounded bg-rose-950 border border-rose-700 text-rose-300 font-mono">Forb:${forbCnt}</span>` : '';

        item.innerHTML = `
          <div class="flex items-center justify-between gap-2">
            <span class="font-mono text-xs font-bold text-slate-100 truncate">${esc(c.run_id)}</span>
            <span class="text-[10px] px-1.5 py-0.5 rounded border ${passColor} font-mono font-bold">${c.passed ? 'PASS' : 'FAIL'}</span>
          </div>
          <div class="flex flex-wrap items-center gap-1.5">
            <span class="text-[10px] px-2 py-0.5 rounded-full font-mono border ${outcomeColor}">${esc(c.outcome)}</span>
            ${probeBadge}
            ${forbBadge}
            <span class="text-[10px] text-slate-500 font-mono ml-auto">att:${c.inference_attempts ?? 1}</span>
          </div>
        `;
        container.appendChild(item);
      });
    }

    function setFilter(filter) {
      currentFilter = filter;
      document.querySelectorAll('.filter-chip').forEach(btn => {
        if (btn.dataset.filter === filter) {
          btn.className = 'filter-chip px-2 py-0.5 rounded bg-sky-600 text-white font-semibold';
        } else {
          btn.className = 'filter-chip px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300';
        }
      });
      filterCases();
    }

    async function selectCase(caseRunId) {
      document.querySelectorAll('.case-card').forEach(el => {
        if (el.dataset.runid === caseRunId) {
          el.classList.add('ring-2', 'ring-sky-500', 'bg-slate-900');
        } else {
          el.classList.remove('ring-2', 'ring-sky-500', 'bg-slate-900');
        }
      });

      document.getElementById('caseEmptyState').classList.add('hidden');
      document.getElementById('caseDetailView').classList.remove('hidden');
      document.getElementById('caseDetailView').classList.add('flex');

      try {
        const res = await fetch(`/api/run/${encodeURIComponent(currentRunData.id)}/case/${encodeURIComponent(caseRunId)}`);
        currentCaseData = await res.json();
        renderCaseDetail();
      } catch (err) {
        console.error('Failed to load case detail:', err);
      }
    }

    function renderScopeList(items, title, badgeColor) {
      const list = (items || []).map(r => `
        <div class="p-2 rounded bg-slate-900 border border-slate-800 flex flex-col gap-0.5">
          <div class="font-bold ${badgeColor}">${esc(r.tool)}</div>
          <div class="text-[11px] text-slate-400">res: <span class="text-slate-200">${esc(r.resource ?? 'null')}</span> | dest: <span class="text-slate-200">${esc(r.destination ?? 'null')}</span></div>
          <div class="text-[10px] text-slate-500">purpose: ${esc(r.purpose)} | max_amount: ${esc(r.max_amount ?? 0)}</div>
        </div>
      `).join('');
      return `
        <div class="flex flex-col gap-1.5">
          <div class="text-[11px] font-semibold text-slate-400">${esc(title)} (${(items || []).length})</div>
          ${list || '<div class="text-slate-600 italic">None</div>'}
        </div>
      `;
    }

    function renderCaseDetail() {
      const d = currentCaseData;
      if (!d) return;
      const s = d.summary || {};

      document.getElementById('detailCaseId').textContent = d.case_run_id;

      const badge = document.getElementById('detailOutcomeBadge');
      badge.textContent = s.outcome || 'UNKNOWN';
      badge.className = `text-xs px-2.5 py-0.5 rounded-full font-mono border ${getOutcomeBadgeClass(s.outcome)}`;

      const pbadge = document.getElementById('detailPassedBadge');
      pbadge.textContent = s.passed ? 'PASSED' : 'FAILED';
      pbadge.className = `text-xs px-2 py-0.5 rounded font-mono font-bold ${s.passed ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400 border border-rose-800'}`;

      document.getElementById('detailPatternBadge').textContent = `pattern: ${s.pattern || d.case_run_id}`;
      document.getElementById('detailGoalPrompt').textContent = d.goal || '(No goal prompt recorded)';

      document.getElementById('detailMetaPills').innerHTML = `
        <span class="px-2 py-0.5 rounded bg-slate-950 border border-slate-800">Attempts: <b class="text-white">${s.inference_attempts ?? d.inference_attempts?.length ?? 1}</b></span>
        <span class="px-2 py-0.5 rounded bg-slate-950 border border-slate-800">Repairs: <b class="text-white">${s.repairs ?? 0}</b></span>
        <span class="px-2 py-0.5 rounded bg-slate-950 border border-slate-800">Replay: <b class="${s.replay_match ? 'text-emerald-400' : 'text-slate-400'}">${s.replay_match ?? 'N/A'}</b></span>
        <span class="px-2 py-0.5 rounded bg-slate-950 border border-slate-800">6-Mode Paired: <b class="${s.six_mode_paired_consistent ? 'text-emerald-400' : 'text-slate-400'}">${s.six_mode_paired_consistent ?? 'N/A'}</b></span>
      `;

      // Oracles Bar
      const go = s.goal_oracle || {};
      const bo = s.business_oracle || {};
      const missStr = (go.missing_required && go.missing_required.length > 0) ? JSON.stringify(go.missing_required) : 'None';
      const forbStr = (go.forbidden_effects && go.forbidden_effects.length > 0) ? JSON.stringify(go.forbidden_effects) : 'None (0)';
      document.getElementById('detailOraclesBar').innerHTML = `
        <div class="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-col gap-1">
          <div class="font-bold text-sky-400 flex items-center justify-between">
            <span>Goal Oracle (System B Ground Truth)</span>
            <span class="${go.intent_correct ? 'text-emerald-400' : 'text-rose-400'}">intent_correct=${esc(go.intent_correct)}</span>
          </div>
          <div class="text-slate-400">Accepted Outcomes: <span class="text-slate-200">${esc((s.accepted_outcomes || [s.expected_outcome]).join(', '))}</span></div>
          <div class="text-slate-400">Missing Required Effects: <span class="${missStr === 'None' ? 'text-emerald-400' : 'text-amber-400'}">${esc(missStr)}</span></div>
          <div class="text-slate-400">Forbidden Effects: <span class="${forbStr.startsWith('None') ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}">${esc(forbStr)}</span></div>
        </div>
        <div class="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-col gap-1">
          <div class="font-bold text-indigo-400 flex items-center justify-between">
            <span>Phase 5 Invariant Monitor</span>
            <span class="${s.invariants_ok !== false ? 'text-emerald-400' : 'text-rose-400'}">invariants_ok=${esc(s.invariants_ok ?? true)}</span>
          </div>
          <div class="text-slate-400">Accepted Policy Violations: <span class="text-emerald-400 font-bold">${esc(bo.accepted_violation_count ?? 0)} / ${esc(bo.assessable_accepted_count ?? 0)}</span></div>
          <div class="text-slate-400">Delivered Effect Violations: <span class="text-emerald-400 font-bold">${esc(bo.delivered_violation_count ?? 0)} / ${esc(bo.assessable_delivered_count ?? 0)}</span></div>
          <div class="text-slate-400">Planner Digest: <span class="text-slate-500">${esc((s.planner_output_digest || '').slice(0, 24))}</span></div>
        </div>
      `;

      // Replan badge
      const rBadge = document.getElementById('replanBadge');
      if (d.proposal_preview_rev0) {
        rBadge.classList.remove('hidden');
      } else {
        rBadge.classList.add('hidden');
      }

      // Mermaid DAG
      const container = document.getElementById('mermaidContainer');
      container.innerHTML = `<div class="mermaid">${d.mermaid_dag}</div>`;
      try {
        mermaid.run({ nodes: container.querySelectorAll('.mermaid') });
      } catch (err) {}

      // Special Box (Clarify Questions / Permission Requests / Capability Requests)
      const sBox = document.getElementById('detailSpecialBox');
      const env = d.planner_envelope || {};
      const prop = d.proposal || {};
      const questions = prop.questions || [];
      const permReqs = env.permission_requests || prop.permission_requests || [];
      const capReqs = env.capability_requests || prop.capability_requests || [];
      let specialHtml = '';
      if (questions.length > 0) {
        specialHtml += `<div class="font-bold text-amber-400 uppercase text-xs">Clarification Questions (CLARIFY)</div>
          <ul class="list-disc pl-5 text-xs text-amber-200 font-mono">${questions.map(q => `<li>${esc(q)}</li>`).join('')}</ul>`;
      }
      if (permReqs.length > 0) {
        specialHtml += `<div class="font-bold text-sky-400 uppercase text-xs mt-1">Permission Request Bundle (New Destination / Resource)</div>
          <div class="flex flex-col gap-1 text-xs font-mono">${permReqs.map(pr => `<div class="p-2 rounded bg-slate-900 border border-sky-900 text-sky-200"><b>${esc(pr.kind)}</b>: ${esc(pr.reference)} — <span class="text-slate-400">${esc(pr.reason)}</span></div>`).join('')}</div>`;
      }
      if (capReqs.length > 0) {
        specialHtml += `<div class="font-bold text-blue-400 uppercase text-xs mt-1">Missing Capability Requests (NEEDS_CAPABILITY)</div>
          <div class="flex flex-col gap-1 text-xs font-mono">${capReqs.map(cr => `<div class="p-2 rounded bg-slate-900 border border-blue-900 text-blue-200"><b>${esc(cr.name || cr.kind)}</b>: ${esc(cr.reason || JSON.stringify(cr))}</div>`).join('')}</div>`;
      }
      if (specialHtml) {
        sBox.innerHTML = specialHtml;
        sBox.classList.remove('hidden');
      } else {
        sBox.classList.add('hidden');
      }

      // Agents & Delegated Capabilities
      const agents = prop.spec?.agents || [];
      const agContainer = document.getElementById('agentsContent');
      if (agents.length === 0) {
        agContainer.innerHTML = '<div class="text-slate-500 italic">No execution agents proposed (stopped prior to execution spec).</div>';
      } else {
        agContainer.innerHTML = agents.map(a => `
          <div class="p-3 rounded-lg bg-slate-900 border border-slate-800 flex flex-col gap-1.5">
            <div class="flex items-center justify-between">
              <span class="font-bold text-sky-300">${esc(a.id)}</span>
              <span class="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">role: ${esc(a.role)}</span>
            </div>
            <div class="flex flex-col gap-1 mt-1">
              ${(a.capabilities || []).map(c => `
                <div class="text-[11px] px-2 py-1 rounded bg-slate-950 border border-slate-800/80 text-slate-300">
                  <b class="text-emerald-400">${esc(c.tool)}</b> → res:<span class="text-sky-200">${esc(c.resource ?? 'null')}</span>, dest:<span class="text-amber-200">${esc(c.destination ?? 'null')}</span> (${esc(c.purpose)})
                </div>
              `).join('')}
            </div>
          </div>
        `).join('');
      }

      // Scope Breakdown
      const sb = d.scope_breakdown || {};
      document.getElementById('scopeBreakdownContent').innerHTML =
        renderScopeList(sb.selected_by_model, '1. Selected by Model', 'text-sky-300') +
        renderScopeList(sb.derived_by_host, '2. Derived by Host (Inference)', 'text-indigo-300') +
        renderScopeList(sb.host_context_egress, '3. Host Context Egress', 'text-purple-300');

      // Origin, Assumptions, Unsupported
      const origins = prop.origin || [];
      const assumptions = prop.assumptions || [];
      const unsupported = prop.unsupported || [];
      document.getElementById('originContent').innerHTML = `
        <div><b class="text-slate-400">Origin Mapping (${origins.length}):</b> ${origins.length ? origins.map(o => `<div class="p-2 mt-1 rounded bg-slate-900 border border-slate-800"><span class="text-sky-300">${esc((o.paths || []).join(', '))}</span> ← "${esc(o.requirement)}" <span class="text-slate-400">(${esc(o.reason)})</span></div>`).join('') : '<span class="text-slate-600">None</span>'}</div>
        <div><b class="text-slate-400">Assumptions (${assumptions.length}):</b> ${assumptions.length ? `<ul class="list-disc pl-5 text-slate-300">${assumptions.map(x => `<li>${esc(x)}</li>`).join('')}</ul>` : '<span class="text-slate-600">None</span>'}</div>
        <div><b class="text-slate-400">Unsupported (${unsupported.length}):</b> ${unsupported.length ? `<ul class="list-disc pl-5 text-rose-300">${unsupported.map(x => `<li>${esc(x)}</li>`).join('')}</ul>` : '<span class="text-slate-600">None</span>'}</div>
      `;

      document.getElementById('rawProposalJson').textContent = JSON.stringify(d.planner_envelope || d.proposal, null, 2);

      // TAB 2: Policies, Z3 Probe & Workspace Catalog
      const policies = prop.spec?.policies || [];
      const pBox = document.getElementById('detailPolicyContent');
      if (policies.length > 0) {
        pBox.innerHTML = policies.map((pol, i) => `
          <div class="p-3 rounded bg-slate-900 border border-slate-800 mb-2">
            <div class="flex items-center justify-between text-xs text-sky-400 font-bold mb-1">
              <span>Policy ID: ${esc(pol.policy_id || `policy-${i+1}`)} (scope=${esc(pol.scope)}, on_violation=${esc(pol.on_violation)})</span>
              <span class="text-slate-400">applies_to: ${esc((pol.applies_to || []).join(', '))}</span>
            </div>
            <pre class="text-[11px] text-slate-200 overflow-x-auto bg-slate-950 p-2 rounded border border-slate-800/80">${esc(JSON.stringify(pol.constraint, null, 2))}</pre>
          </div>
        `).join('');
      } else {
        pBox.innerHTML = '<span class="text-slate-500 italic">No custom dynamic policy synthesized for this goal (enforced by static contract scope & budget_limit=' + esc(prop.spec?.budget_limit ?? 0) + ').</span>';
      }

      const probe = s.z3_policy_probe;
      const z3Box = document.getElementById('detailZ3ProbeContent');
      if (probe && probe.checks) {
        z3Box.innerHTML = `
          <div class="mb-2">Overall Probe Status: <b class="${probe.ok ? 'text-emerald-400' : 'text-rose-400'}">${probe.ok ? 'PASSED (All boundary checks matched Z3)' : 'FAILED'}</b></div>
          <table class="w-full text-left text-xs font-mono border border-slate-800">
            <thead class="bg-slate-900 text-slate-400">
              <tr><th class="py-1.5 px-3">Test Args</th><th class="py-1.5 px-3">Expected</th><th class="py-1.5 px-3">Z3 Decision</th><th class="py-1.5 px-3">Match</th></tr>
            </thead>
            <tbody class="divide-y divide-slate-800">
              ${probe.checks.map(chk => `
                <tr>
                  <td class="py-1.5 px-3 text-slate-200">${esc(JSON.stringify(chk.args))}</td>
                  <td class="py-1.5 px-3">${esc(chk.expect)}</td>
                  <td class="py-1.5 px-3 font-bold ${chk.decision === 'ALLOW' ? 'text-emerald-400' : 'text-amber-400'}">${esc(chk.decision)}</td>
                  <td class="py-1.5 px-3 font-bold ${chk.expect === chk.decision ? 'text-emerald-400' : 'text-rose-400'}">${chk.expect === chk.decision ? '✓ OK' : '✗ MISMATCH'}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        `;
      } else {
        z3Box.innerHTML = '<span class="text-slate-500 italic">No Z3 policy boundary probe configured for this case.</span>';
      }

      const ws = d.workspace || d.environment_preview?.environment || {};
      const wsResources = ws.resources || [];
      const wsDests = ws.destinations || [];
      document.getElementById('workspaceCatalogContent').innerHTML = `
        <div class="flex flex-wrap gap-3 text-xs">
          <span class="px-2.5 py-1 rounded bg-slate-900 border border-slate-800">Budget Entitlement: <b class="text-emerald-400">${esc(ws.budget_limit ?? 'N/A')}</b></span>
          <span class="px-2.5 py-1 rounded bg-slate-900 border border-slate-800">Enabled Tools: <b class="text-sky-300">${esc((ws.enabled_tools || []).join(', '))}</b></span>
          <span class="px-2.5 py-1 rounded bg-slate-900 border border-slate-800">Allowed Destinations: <b class="text-amber-300">${esc(wsDests.map(x => x.id || x.destination || JSON.stringify(x)).join(', '))}</b></span>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-2.5">
          ${wsResources.map(r => {
            const lbl = r.label || 'PUBLIC';
            const lblCls = lbl === 'SENSITIVE' ? 'bg-rose-950 text-rose-400 border-rose-800' : (lbl === 'UNKNOWN' ? 'bg-amber-950 text-amber-400 border-amber-800' : 'bg-emerald-950 text-emerald-400 border-emerald-800');
            return `
              <div class="p-2.5 rounded bg-slate-900 border border-slate-800 flex flex-col gap-1">
                <div class="flex items-center justify-between">
                  <span class="font-bold text-slate-200">${esc(r.id || r.resource)}</span>
                  <span class="text-[10px] px-2 py-0.5 rounded border ${lblCls} font-bold">${esc(lbl)}</span>
                </div>
                <div class="text-[11px] text-slate-300 bg-slate-950 p-2 rounded border border-slate-800/60 whitespace-pre-wrap">${esc(r.content || '')}</div>
              </div>
            `;
          }).join('')}
        </div>
      `;

      // TAB 3: Guard Timeline & Reviews
      const revs = d.reviews || [];
      const decs = d.decisions || [];
      document.getElementById('reviewsContent').innerHTML = `
        <div class="flex flex-col gap-1.5">
          ${revs.map(r => `<div class="p-2 rounded bg-slate-900 border border-slate-800 flex items-center justify-between"><span><b>${esc(r.id)}</b> (kind=${esc(r.kind)}, approver=${esc(r.approver)})</span><span class="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 font-bold">${esc(r.status)}</span></div>`).join('')}
          ${decs.map(dc => `<div class="p-2 rounded bg-slate-900/60 border border-slate-800/60 text-slate-300"><b>${esc(dc.reviewer)} (${esc(dc.actor)}):</b> ${esc(dc.question)} → <span class="text-sky-300 font-bold">${esc(dc.answer)}</span></div>`).join('')}
        </div>
      `;

      document.getElementById('eventsCountBadge').textContent = d.events.length;
      const tbody = document.getElementById('timelineTableBody');
      tbody.innerHTML = '';
      d.events.forEach(ev => {
        const tr = document.createElement('tr');
        const stColor = ['ALLOW', 'COMMITTED', 'RELEASED', 'SATISFIED', 'ACCEPTANCE_SATISFIED', 'READS_DELIVERED'].includes(ev.status)
          ? 'text-emerald-400'
          : (['DENY', 'REFUSED', 'FAILED', 'PLANNING_FAILED', 'INVALID_PROPOSAL'].includes(ev.status) ? 'text-rose-400' : 'text-amber-300');
        tr.innerHTML = `
          <td class="py-1.5 px-3 text-slate-500">${esc(ev.sequence ?? '-')}</td>
          <td class="py-1.5 px-3 font-semibold text-slate-200">${esc(ev.event || '-')}</td>
          <td class="py-1.5 px-3 text-sky-400">${esc(ev.tool || '-')}</td>
          <td class="py-1.5 px-3 font-bold ${stColor}">${esc(ev.status || '-')}</td>
          <td class="py-1.5 px-3 text-slate-400">${esc(ev.error || ev.reason || '')}</td>
        `;
        tbody.appendChild(tr);
      });

      const sev = d.service_events || [];
      document.getElementById('serviceEventsContent').innerHTML = `
        <table class="w-full text-left text-[11px] font-mono">
          <thead class="bg-slate-900 text-slate-400"><tr><th class="p-1.5">Seq</th><th class="p-1.5">Kind</th><th class="p-1.5">Actor</th><th class="p-1.5">Data</th></tr></thead>
          <tbody class="divide-y divide-slate-800">${sev.map(e => `<tr><td class="p-1.5 text-slate-500">${e.seq}</td><td class="p-1.5 text-sky-300">${esc(e.kind)}</td><td class="p-1.5 text-slate-400">${esc(e.actor)}</td><td class="p-1.5 text-slate-300 truncate max-w-md">${esc(JSON.stringify(e.data))}</td></tr>`).join('')}</tbody>
        </table>
      `;

      // TAB 4: Tickets & Trace Store
      const tev = d.trace_events || [];
      const auths = d.authorizations || [];
      document.getElementById('ticketsCountBadge').textContent = auths.length;
      document.getElementById('traceEventsContent').innerHTML = tev.length === 0
        ? '<div class="text-slate-500 italic">No committed trace events in Trace Store.</div>'
        : `<table class="w-full text-left text-xs font-mono">
            <thead class="bg-slate-900 text-slate-400"><tr><th class="p-2">Seq</th><th class="p-2">Agent</th><th class="p-2">Tool</th><th class="p-2">Ticket ID</th><th class="p-2">Nonce</th><th class="p-2">Write Set</th></tr></thead>
            <tbody class="divide-y divide-slate-800">${tev.map(t => `
              <tr>
                <td class="p-2 text-slate-500">${t.seq}</td>
                <td class="p-2 text-sky-300">${esc(t.agent_id)}</td>
                <td class="p-2 text-emerald-400 font-bold">${esc(t.tool)}</td>
                <td class="p-2 text-slate-300">${esc(t.ticket_id)}</td>
                <td class="p-2 text-slate-400">${esc((t.nonce || '').slice(0, 12))}…</td>
                <td class="p-2 text-amber-300">${esc(JSON.stringify(t.write_set))}</td>
              </tr>`).join('')}
            </tbody>
          </table>`;

      document.getElementById('authorizationsContent').innerHTML = auths.length === 0
        ? '<div class="text-slate-500 italic">No tickets issued.</div>'
        : auths.map(a => `
          <details class="p-2.5 rounded bg-slate-900 border border-slate-800">
            <summary class="cursor-pointer flex items-center justify-between">
              <span class="font-bold text-sky-300">${esc(a.ticket)}</span>
              <span class="text-slate-400">op: ${esc(a.operation)}</span>
            </summary>
            <pre class="mt-2 text-[11px] text-slate-300 bg-slate-950 p-2 rounded overflow-x-auto">${esc(JSON.stringify(a.data, null, 2))}</pre>
          </details>
        `).join('');

      // TAB 5: Outbox, Receipts & Outputs
      document.getElementById('outboxCountBadge').textContent = d.outbox.length;
      const comp = d.result?.completion;
      document.getElementById('completionCriteriaContent').innerHTML = comp
        ? `<div class="mb-2">Completion Satisfied: <b class="${comp.satisfied ? 'text-emerald-400' : 'text-rose-400'}">${esc(comp.satisfied)}</b> (effects=${esc(comp.business_effects)})</div>
           <div class="flex flex-col gap-1.5">${(comp.criteria || []).map(cr => `
             <div class="p-2 rounded bg-slate-900 border border-slate-800 flex items-center justify-between">
               <span>Criterion: <b class="text-sky-300">${esc(JSON.stringify(cr.criterion))}</b> → Evidence: <span class="text-slate-300">${esc(JSON.stringify(cr.evidence))}</span></span>
               <span class="px-2 py-0.5 rounded font-bold ${cr.satisfied ? 'bg-emerald-950 text-emerald-400' : 'bg-rose-950 text-rose-400'}">${cr.satisfied ? 'SATISFIED' : 'UNSATISFIED'}</span>
             </div>`).join('')}</div>`
        : '<span class="text-slate-500 italic">No execution completion record (stopped before workflow completion).</span>';

      const obody = document.getElementById('outboxTableBody');
      obody.innerHTML = '';
      if (d.outbox.length === 0) {
        obody.innerHTML = '<tr><td colspan="6" class="py-3 px-3 text-slate-500 text-center">No outbox entries committed</td></tr>';
      } else {
        d.outbox.forEach(o => {
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td class="py-2 px-3 text-slate-300">${esc(o.operation)}</td>
            <td class="py-2 px-3 text-sky-300">${esc(o.agent)}</td>
            <td class="py-2 px-3 text-amber-300">${esc(o.amount ?? 0)}</td>
            <td class="py-2 px-3 text-slate-300"><pre class="whitespace-pre-wrap max-w-md text-[11px]">${esc(JSON.stringify(o.payload))}</pre></td>
            <td class="py-2 px-3 font-bold text-emerald-400">${esc(o.status)}</td>
            <td class="py-2 px-3 text-slate-400 text-[11px]">${esc(o.receipt ? JSON.stringify(o.receipt) : '-')}</td>
          `;
          obody.appendChild(tr);
        });
      }

      const outs = d.execution_outputs || [];
      document.getElementById('outputsContent').innerHTML = outs.length === 0
        ? '<span class="text-slate-500 italic">No authored outputs published for this task.</span>'
        : outs.map(o => `
          <div class="p-3 rounded bg-slate-900 border border-slate-800">
            <div class="flex items-center justify-between text-sky-300 font-bold mb-1">
              <span>Output ID: ${esc(o.id)}</span>
              <span class="text-[11px] text-slate-400">${esc(o.digest)}</span>
            </div>
            <div class="p-2 rounded bg-slate-950 text-slate-200 whitespace-pre-wrap">${esc(typeof o.data === 'object' ? JSON.stringify(o.data, null, 2) : o.data)}</div>
          </div>
        `).join('');

      // TAB 6: Conflict Keys
      document.getElementById('keysCountBadge').textContent = d.conflict_keys.length;
      filterConflictKeys();

      // TAB 7: LLM Memos, Attempts & Console Log
      document.getElementById('memosCountBadge').textContent = d.memos.length;
      const atts = d.inference_attempts || [];
      document.getElementById('attemptsContent').innerHTML = atts.length === 0
        ? '<span class="text-slate-500 italic">No inference attempt records.</span>'
        : `<table class="w-full text-left text-xs font-mono">
            <thead class="bg-slate-900 text-slate-400"><tr><th class="p-2">#</th><th class="p-2">Kind</th><th class="p-2">Model</th><th class="p-2">Status</th><th class="p-2">Token Usage</th><th class="p-2">Error</th></tr></thead>
            <tbody class="divide-y divide-slate-800">${atts.map((a, idx) => `
              <tr>
                <td class="p-2 text-slate-500">${idx + 1}</td>
                <td class="p-2 text-sky-300">${esc(a.kind)}</td>
                <td class="p-2 text-slate-300">${esc(a.model)}</td>
                <td class="p-2 font-bold ${a.status === 'SUCCEEDED' || a.status === 'COMPLETED' ? 'text-emerald-400' : 'text-amber-400'}">${esc(a.status)}</td>
                <td class="p-2 text-slate-300">${esc(a.usage ? JSON.stringify(a.usage) : '-')}</td>
                <td class="p-2 text-rose-400">${esc(a.error || '')}</td>
              </tr>`).join('')}
            </tbody>
          </table>`;

      const mContainer = document.getElementById('memosContainer');
      mContainer.innerHTML = d.memos.map((m, idx) => `
        <div class="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono">
          <div class="flex items-center justify-between text-sky-400 font-bold mb-2 border-b border-slate-800 pb-1.5">
            <span>Inference Memo #${idx + 1} (${esc(m.id)})</span>
            <span class="text-[10px] text-slate-500">${esc(m.binding)}</span>
          </div>
          <pre class="text-slate-200 overflow-x-auto max-h-72 p-2.5 bg-slate-900 rounded text-[11px]">${esc(JSON.stringify(m.output, null, 2))}</pre>
        </div>
      `).join('');

      document.getElementById('consoleLogContent').textContent = d.console_log || '(No console log file recorded for this case)';
    }

    function filterConflictKeys() {
      if (!currentCaseData) return;
      const q = (document.getElementById('keySearch').value || '').toLowerCase();
      const kbody = document.getElementById('keysTableBody');
      kbody.innerHTML = '';
      currentCaseData.conflict_keys
        .filter(k => k.key.toLowerCase().includes(q) || JSON.stringify(k.value).toLowerCase().includes(q))
        .forEach(k => {
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td class="py-1.5 px-3 text-sky-300 font-semibold">${esc(k.key)}</td>
            <td class="py-1.5 px-3 text-amber-400 font-bold">v${esc(k.version)}</td>
            <td class="py-1.5 px-3 text-slate-300"><div class="max-w-xl overflow-x-auto">${esc(typeof k.value === 'object' ? JSON.stringify(k.value) : k.value)}</div></td>
          `;
          kbody.appendChild(tr);
        });
    }

    function renderWhitebox(data) {
      const results = data.results || [];
      const b = data.blocked || { numerator: results.length, denominator: results.length };
      document.getElementById('wbCountBadge').textContent = `${b.numerator}/${b.denominator} BLOCKED`;

      const tbody = document.getElementById('whiteboxTableBody');
      tbody.innerHTML = '';
      results.forEach(r => {
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-slate-900 cursor-pointer transition-colors';
        tr.onclick = () => selectWhiteboxAttack(r.attack);
        tr.innerHTML = `
          <td class="py-2 px-3 font-bold text-sky-300">${esc(r.attack)}</td>
          <td class="py-2 px-3 text-slate-400 max-w-[200px] truncate" title="${esc(r.surface)}">${esc(r.surface)}</td>
          <td class="py-2 px-3 text-amber-400 font-semibold">${esc((r.blocked_by || []).join(', '))}</td>
          <td class="py-2 px-3 text-purple-300">${esc(r.outcome)}</td>
          <td class="py-2 px-3 text-center">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${r.blocked ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400 border border-rose-800'}">
              ${r.blocked ? 'BLOCKED' : 'LEAKED'}
            </span>
          </td>
        `;
        tbody.appendChild(tr);
      });

      if (results.length > 0) {
        selectWhiteboxAttack(results[0].attack);
      }
    }

    async function selectWhiteboxAttack(attackId) {
      document.getElementById('wbEmptyState').classList.add('hidden');
      const box = document.getElementById('wbDetailContent');
      box.classList.remove('hidden');
      box.classList.add('flex');
      box.innerHTML = '<div class="text-xs text-slate-400 font-mono">Loading attack trace...</div>';

      try {
        const res = await fetch(`/api/run/${encodeURIComponent(currentRunData.id)}/whitebox/${encodeURIComponent(attackId)}`);
        const d = await res.json();
        const a = d.attack;
        box.innerHTML = `
          <div class="border-b border-slate-800 pb-3">
            <div class="flex items-center justify-between">
              <h4 class="text-base font-bold text-white font-mono">${esc(a.attack)}</h4>
              <span class="px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-emerald-950 border border-emerald-800 text-emerald-400">BLOCKED BY: ${esc((a.blocked_by || []).join(', '))}</span>
            </div>
            <div class="text-xs text-slate-400 font-mono mt-1"><b>Surface:</b> ${esc(a.surface)}</div>
            <div class="text-xs text-amber-300 bg-amber-950/30 border border-amber-900/60 p-2.5 rounded mt-2 font-mono"><b>Adversarial Claim / Goal:</b> ${esc(a.claim)}</div>
          </div>

          <div class="grid grid-cols-2 gap-2 text-xs font-mono">
            <div class="p-2 rounded bg-slate-950 border border-slate-800">Plan Status: <b class="text-sky-300">${esc(a.plan_status)}</b></div>
            <div class="p-2 rounded bg-slate-950 border border-slate-800">Exec Status: <b class="text-purple-300">${esc(a.execution_status)}</b></div>
            <div class="p-2 rounded bg-slate-950 border border-slate-800">Forbidden Accepted: <b class="text-emerald-400">${esc(a.forbidden_accepted)}</b></div>
            <div class="p-2 rounded bg-slate-950 border border-slate-800">Forbidden Delivered: <b class="text-emerald-400">${esc(a.forbidden_delivered)}</b></div>
          </div>

          <div class="bg-slate-950 border border-slate-800 rounded-lg p-3 flex flex-col gap-2">
            <div class="text-xs font-bold text-sky-400 font-mono uppercase">Authorization Decisions</div>
            ${(a.authorizations || []).length === 0
              ? '<div class="text-xs text-slate-500 font-mono">Blocked at planning / resolver / review stage before tool authorization.</div>'
              : (a.authorizations || []).map(au => `
                <div class="p-2 rounded bg-slate-900 border border-slate-800 text-xs font-mono">
                  <div class="flex items-center justify-between">
                    <span class="font-bold text-slate-200">${esc(au.tool)}</span>
                    <span class="px-2 py-0.5 rounded font-bold ${au.decision === 'ALLOW' ? 'bg-emerald-950 text-emerald-400' : 'bg-rose-950 text-rose-400'}">${esc(au.decision)} ${au.policy ? `(${esc(au.policy)})` : ''}</span>
                  </div>
                  ${au.explanation ? `<div class="text-[11px] text-rose-300 mt-1">${esc(au.explanation)}</div>` : ''}
                </div>
              `).join('')}
          </div>

          <div class="bg-slate-950 border border-slate-800 rounded-lg p-3 flex flex-col gap-2">
            <div class="text-xs font-bold text-indigo-400 font-mono uppercase">Observed Business Effects & Resource Snapshots</div>
            ${(a.business_effects || []).length === 0
              ? '<div class="text-xs text-slate-500 font-mono">0 business effects executed.</div>'
              : (a.business_effects || []).map(be => `
                <div class="p-2 rounded bg-slate-900 border border-slate-800 text-xs font-mono flex flex-col gap-1">
                  <div class="flex items-center justify-between">
                    <span class="text-emerald-400 font-bold">${esc(be.tool)} (${esc(be.status)})</span>
                    <span class="text-slate-400">label=${esc(be.resolved_label || 'N/A')}</span>
                  </div>
                  ${be.resource_snapshot ? `<div class="p-2 rounded bg-slate-950 text-[11px] text-slate-300 whitespace-pre-wrap">${esc(be.resource_snapshot.content)}</div>` : ''}
                </div>
              `).join('')}
          </div>
        `;
      } catch (e) {
        box.innerHTML = '<div class="text-xs text-rose-400">Failed to load whitebox attack details.</div>';
      }
    }

    function switchTab(tabId) {
      document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('border-sky-500', 'text-sky-400');
        btn.classList.add('border-transparent', 'text-slate-400');
      });
      document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));

      document.getElementById(tabId).classList.remove('hidden');
      const btn = document.getElementById('btn' + tabId.charAt(0).toUpperCase() + tabId.slice(1));
      if (btn) {
        btn.classList.add('border-sky-500', 'text-sky-400');
        btn.classList.remove('border-transparent', 'text-slate-400');
      }

      if (tabId === 'tabDag' && currentCaseData) {
        try {
          mermaid.run({ nodes: document.querySelectorAll('#mermaidContainer .mermaid') });
        } catch(e) {}
      }
    }

    window.onload = init;
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def index_html():
    return DASHBOARD_HTML


def main():
    parser = argparse.ArgumentParser(description="AtomicRoot Runtime Authorization Dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    parser.add_argument("--open", action="store_true", help="Automatically open dashboard in browser")
    args = parser.parse_args()

    url = f"http://{args.host}:{args.port}"
    print("\n=======================================================")
    print("  AtomicRoot Runtime Authorization Dashboard")
    print(f"  Running on: {url}")
    print("  Inspecting .runs/ directory read-only (?mode=ro&immutable=1)")
    print("  Press Ctrl+C to stop.")
    print("=======================================================\n")

    if args.open:
        webbrowser.open(url)

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
