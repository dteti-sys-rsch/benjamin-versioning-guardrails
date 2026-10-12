"""
Worker — simulated agent for test scenarios.

Not an LLM.  A simple Python helper that encapsulates the two-step
"request authorisation → present ticket to gateway" flow so that test
code can script deterministic interleavings.
"""

from __future__ import annotations

from typing import Any

from atomicroot.authority.authority import PolicyAuthority
from atomicroot.gateway.gateway import ToolGateway


class SimulatedWorker:
    """
    A simulated agent that follows the AtomicRoot protocol:

    1. Ask the Policy Authority for authorisation (obtain a ticket).
    2. Present the ticket + concrete args to the Gateway for execution.

    Tests use this to build deterministic scenarios where the ordering
    of steps 1 and 2 across multiple workers is explicitly controlled.
    """

    def __init__(
        self,
        agent_id: str,
        authority: PolicyAuthority,
        gateway: ToolGateway,
    ) -> None:
        self.agent_id = agent_id
        self.authority = authority
        self.gateway = gateway

    def request_authorization(
        self,
        task_id: str,
        tool: str,
        args: dict[str, Any],
        *, action_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Step 1: ask the Policy Authority for a ticket.

        Returns the raw response — either a signed ticket dict
        (containing ``ticket_id``) or a denial dict (``decision: DENY``).
        """
        request = {
            "task_id": task_id,
            "agent_id": self.agent_id,
            "tool": tool,
            "args": args,
        }
        return self.authority.authorize(request, caller_agent_id=self.agent_id,
                                        action_id=action_id)

    def execute(
        self,
        ticket_dict: dict[str, Any],
        args: dict[str, Any],
        *,
        skip_freshness_check: bool = False,
        action_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Step 2: present the ticket to the Gateway.

        Returns the commit result dict (COMMITTED / STALE_TICKET / REJECTED).
        """
        return self.gateway.commit(
            ticket_dict, args, skip_freshness_check=skip_freshness_check,
            caller_agent_id=self.agent_id, action_id=action_id,
        )

    def authorize_and_execute(
        self,
        task_id: str,
        tool: str,
        args: dict[str, Any],
        *,
        skip_freshness_check: bool = False,
    ) -> dict[str, Any]:
        """
        Convenience: run both steps in sequence (no interleaving).
        Useful for simple, non-concurrent tests.
        """
        auth_result = self.request_authorization(task_id, tool, args)
        if "ticket_id" not in auth_result:
            return auth_result
        return self.execute(
            auth_result, args, skip_freshness_check=skip_freshness_check,
        )
