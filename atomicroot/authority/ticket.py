"""
Ticket — Ed25519-signed, single-use authorisation ticket.

A ticket binds a policy decision (ALLOW) to a specific footprint snapshot.
It is only valid while Fresh(τ, S) holds, i.e. while every conflict key in
the footprint still has the version recorded at evaluation time.

Structure matches Section 6 of the design brief exactly.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError


# ---------------------------------------------------------------------------
# Key management (in-process for Phase 1)
# ---------------------------------------------------------------------------

def generate_keypair() -> tuple[SigningKey, VerifyKey]:
    """Generate a fresh Ed25519 signing/verification keypair."""
    sk = SigningKey.generate()
    return sk, sk.verify_key


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MAX_REQUEST_BYTES = 65_536


def canonical_json_bytes(value) -> bytes:
    """One JSON rule for requests, argument hashes and signed payloads."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False, ensure_ascii=False).encode("utf-8")


def freeze_json(value, *, max_bytes: int = MAX_REQUEST_BYTES):
    encoded = canonical_json_bytes(value)
    if len(encoded) > max_bytes:
        raise ValueError("JSON input exceeds size limit")
    return json.loads(encoded)


def args_hash(args: dict) -> str:
    """Deterministic full SHA-256 hash of the canonical argument dict."""
    digest = hashlib.sha256(canonical_json_bytes(args)).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Ticket data class
# ---------------------------------------------------------------------------

@dataclass
class Ticket:
    ticket_id: str
    task_id: str
    agent_id: str
    tool: str
    args_hash: str
    footprint: dict[str, int]       # conflict_key → version observed
    write_set: list[str]
    nonce: str
    not_before: str                  # ISO-8601
    not_after: str                   # ISO-8601
    signature: str = ""              # "ed25519:<hex>"

    def canonical_bytes(self) -> bytes:
        """
        Deterministic byte representation used for signing/verification.
        Excludes the signature field itself.
        """
        payload = {
            "ticket_id": self.ticket_id,
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "tool": self.tool,
            "args_hash": self.args_hash,
            "footprint": dict(sorted(self.footprint.items())),
            "write_set": self.write_set,
            "nonce": self.nonce,
            "not_before": self.not_before,
            "not_after": self.not_after,
        }
        return canonical_json_bytes(payload)

    def sign(self, signing_key: SigningKey) -> None:
        """Sign this ticket in-place."""
        signed = signing_key.sign(self.canonical_bytes())
        self.signature = f"ed25519:{signed.signature.hex()}"

    def verify(self, verify_key: VerifyKey) -> bool:
        """
        Verify the Ed25519 signature.
        Returns True if valid, False if the signature is missing or invalid.
        """
        if not isinstance(self.signature, str) or not self.signature.startswith("ed25519:"):
            return False
        try:
            sig_bytes = bytes.fromhex(self.signature[len("ed25519:"):])
            verify_key.verify(self.canonical_bytes(), sig_bytes)
            return True
        except (BadSignatureError, ValueError, TypeError):
            return False

    def to_dict(self) -> dict:
        return {
            "ticket_id": self.ticket_id,
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "tool": self.tool,
            "args_hash": self.args_hash,
            "footprint": self.footprint,
            "write_set": self.write_set,
            "nonce": self.nonce,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Ticket:
        return cls(**d)


# ---------------------------------------------------------------------------
# Ticket factory
# ---------------------------------------------------------------------------

def create_ticket(
    task_id: str,
    agent_id: str,
    tool: str,
    args: dict,
    footprint: dict[str, int],
    write_set: list[str],
    signing_key: SigningKey,
    ttl_seconds: int = 30,
) -> Ticket:
    """
    Build and sign a new ticket.

    Parameters
    ----------
    ttl_seconds : int
        Validity window.  Default 30 s (matches the brief's example).
    """
    now = datetime.now(timezone.utc)
    ticket = Ticket(
        ticket_id=f"tk-{uuid.uuid4().hex[:8]}",
        task_id=task_id,
        agent_id=agent_id,
        tool=tool,
        args_hash=args_hash(args),
        footprint=footprint,
        write_set=write_set,
        nonce=f"n-{uuid.uuid4().hex[:12]}",
        not_before=now.isoformat(timespec="seconds"),
        not_after=(now + timedelta(seconds=ttl_seconds)).isoformat(timespec="seconds"),
    )
    ticket.sign(signing_key)
    return ticket
