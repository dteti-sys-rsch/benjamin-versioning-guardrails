"""Trusted authentication fixture. Never deserialize a Principal from a body."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: frozenset[str]
    tasks: frozenset[str] = frozenset()
    resources: frozenset[str] = frozenset()

    def require(self, role, *, task=None, resource=None):
        if role not in self.roles:
            raise PermissionError(f"{role} role required")
        if task is not None and task not in self.tasks:
            raise PermissionError("task outside authenticated scope")
        if resource is not None and resource not in self.resources:
            raise PermissionError("resource outside authenticated scope")
