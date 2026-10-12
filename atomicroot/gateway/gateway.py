"""
Tool Gateway — the sole execution path for tool effects.

Three-step protocol (Section 5 of the design brief):

1. Verify the ticket's Ed25519 signature.
2. Verify args_hash matches the actual arguments presented.
3. Ask the Trace Store to perform a CAS commit:
   - If Fresh(τ, S): commit atomically, then execute the (simulated)
     tool effect.  Return COMMITTED.
   - If stale: return STALE_TICKET.  No effect is executed.

In Phase 1 tool effects are simulated: they write to an in-memory log
rather than calling real external services.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from nacl.signing import VerifyKey

from atomicroot.authority.ticket import Ticket, freeze_json, args_hash as compute_args_hash
from atomicroot.store.trace_store import TraceStore, CommitResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Simulated tool effects (Phase 1)
# ---------------------------------------------------------------------------

class ToolEffectLog:
    """
    In-memory log of simulated tool effects.
    Allows tests to verify which tools actually fired.
    """

    def __init__(self) -> None:
        self.effects: list[dict[str, Any]] = []

    def record(self, ticket_id: str, tool: str, args: dict[str, Any]) -> str:
        """Record a simulated tool execution.  Returns a result reference."""
        entry = {
            "ticket_id": ticket_id,
            "tool": tool,
            "args": args,
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }
        self.effects.append(entry)
        return f"effect-{len(self.effects)}"

    def was_executed(self, ticket_id: str) -> bool:
        return any(e["ticket_id"] == ticket_id for e in self.effects)


# ---------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------

class ToolGateway:
    """
    Trusted gateway that mediates all tool executions.

    Holds the Policy Authority's verification key (to check ticket
    signatures) and a reference to the Trace Store (for CAS commits).
    """

    def __init__(
        self,
        store: TraceStore,
        verify_key: VerifyKey,
        effect_log: ToolEffectLog | None = None,
        *, allow_baseline: bool = False, harness=None,
    ) -> None:
        self.store = store
        self.verify_key = verify_key
        self.effect_log = effect_log or ToolEffectLog()
        self.allow_baseline = allow_baseline
        self.harness = harness

    def commit(
        self,
        ticket_dict: dict[str, Any],
        args: dict[str, Any],
        *,
        skip_freshness_check: bool = False,
        caller_agent_id: str | None = None,
        action_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Execute the three-step commit protocol.

        Parameters
        ----------
        ticket_dict : dict
            Signed ticket as returned by PolicyAuthority.authorize().
        args : dict
            Concrete tool arguments (must hash-match the ticket).
        skip_freshness_check : bool
            **Baseline mode only.** Bypass the CAS freshness check to
            demonstrate the vulnerability that AtomicRoot prevents.

        Returns
        -------
        dict
            ``{"status": "COMMITTED", ...}`` or
            ``{"status": "STALE_TICKET", ...}`` or
            ``{"status": "REJECTED", "reason": ...}``
        """
        try:
            # Freeze caller-owned containers before signature verification. A
            # concurrent worker must not mutate them between verify and CAS.
            frozen_ticket = freeze_json(ticket_dict)
            frozen_args = freeze_json(args)
            ticket = Ticket.from_dict(frozen_ticket)
        except (TypeError, ValueError, KeyError, RecursionError):
            return {"status": "REJECTED", "reason": "malformed_ticket"}

        # Step 1: Verify signature.
        try:
            signature_ok = ticket.verify(self.verify_key)
        except (TypeError, ValueError, AttributeError):
            signature_ok = False
        if not signature_ok:
            logger.warning("Ticket %s: invalid signature", ticket.ticket_id)
            return {
                "status": "REJECTED",
                "reason": "invalid_signature",
                "ticket_id": ticket.ticket_id,
            }

        if caller_agent_id != ticket.agent_id:
            return {"status": "REJECTED", "reason": "caller_identity_mismatch"}
        try:
            start = datetime.fromisoformat(ticket.not_before.replace("Z", "+00:00"))
            end = datetime.fromisoformat(ticket.not_after.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            if start.tzinfo is None or end.tzinfo is None or not (start <= now <= end):
                return {"status": "REJECTED", "reason": "ticket_expired_or_not_yet_valid"}
        except (TypeError, ValueError):
            return {"status": "REJECTED", "reason": "invalid_ticket_time"}
        if skip_freshness_check and not self.allow_baseline:
            return {"status": "REJECTED", "reason": "baseline_disabled"}

        # Step 2: Verify args_hash.
        try:
            expected_hash = compute_args_hash(frozen_args)
        except (TypeError, ValueError):
            return {"status": "REJECTED", "reason": "invalid_args"}
        if ticket.args_hash != expected_hash:
            logger.warning(
                "Ticket %s: args_hash mismatch (ticket=%s, actual=%s)",
                ticket.ticket_id, ticket.args_hash, expected_hash,
            )
            return {
                "status": "REJECTED",
                "reason": "args_hash_mismatch",
                "ticket_id": ticket.ticket_id,
            }

        # Step 3: CAS commit via Trace Store.
        event_data = {
            "task_id": ticket.task_id,
            "agent_id": ticket.agent_id,
            "tool": ticket.tool,
            "args_hash": ticket.args_hash,
            "ticket_id": ticket.ticket_id,
            "nonce": ticket.nonce,
            "not_before": ticket.not_before,
            "not_after": ticket.not_after,
            "write_set": ticket.write_set,
            "args": frozen_args,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if self.harness:
            self.harness.checkpoint("before_cas", action_id)
        try:
            result: CommitResult = self.store.commit(
                footprint=ticket.footprint,
                write_set=ticket.write_set,
                event_data=event_data,
                skip_freshness_check=skip_freshness_check,
            )
        except (ValueError, TypeError) as exc:
            return {"status": "REJECTED", "reason": str(exc)}

        if result.status == "COMMITTED":
            if self.harness:
                self.harness.checkpoint("after_commit", action_id)
            # Execute simulated tool effect.
            self.effect_log.record(ticket.ticket_id, ticket.tool, frozen_args)
            return {
                "status": "COMMITTED",
                "version_before": result.version_before,
                "version_after": result.version_after,
                "result_ref": result.result_ref,
                "ticket_id": ticket.ticket_id,
            }

        # STALE_TICKET — effect NOT executed.
        if result.status == "EXPIRED":
            return {"status": "REJECTED", "reason": "ticket_expired_or_not_yet_valid",
                    "ticket_id": ticket.ticket_id}
        if result.status == "REPLAY":
            return {"status": "REJECTED", "reason": "replay", "ticket_id": ticket.ticket_id}
        assert result.status == "STALE_TICKET"
        return {
            "status": "STALE_TICKET",
            "stale_keys": result.stale_keys,
            "expected": result.expected,
            "actual": result.actual,
            "ticket_id": ticket.ticket_id,
        }
