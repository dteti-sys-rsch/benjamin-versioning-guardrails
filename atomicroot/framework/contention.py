"""Bounded process-local writer admission, shared by connections to one database.

The exclusive fallback is deliberately database-wide. Concrete keys describe its
reauthorization scope, not parallel SQLite writers or distributed exclusion.
"""
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from threading import Condition, RLock, get_ident
from time import monotonic
import math


class ContentionTimeout(TimeoutError): pass
class ContentionCancelled(RuntimeError): pass


@dataclass(frozen=True)
class FallbackConfig:
    stale_threshold: int = 2
    max_attempts: int = 4
    max_restarts: int = 2
    timeout: float = 5.0

    def __post_init__(self):
        if (type(self.stale_threshold) is not int or type(self.max_attempts) is not int or
                not 1 <= self.stale_threshold < self.max_attempts <= 16 or
                type(self.max_restarts) is not int or not 0 <= self.max_restarts <= 8 or
                type(self.timeout) not in (int, float) or not math.isfinite(self.timeout) or not 0 < self.timeout <= 30):
            raise ValueError("invalid fallback bounds")


class WriterCoordinator:
    def __init__(self):
        self.condition = Condition(RLock())
        self.queue = deque()
        self.active = 0
        self.owner = None
        self.keys = ()
        self.key_owners = {}

    @contextmanager
    def acquire(self, *, exclusive=False, keys=(), timeout=5.0, cancelled=None):
        concrete = tuple(keys)
        if any(type(k) is not str or not k or "*" in k for k in concrete):
            raise ValueError("concrete conflict keys required")
        ordered = tuple(sorted(set(concrete)))
        thread = get_ident()
        with self.condition:
            nested = self.owner == thread
            if nested and exclusive and not set(ordered) <= set(self.keys):
                raise ValueError("release before expanding concrete key reservation")
            if not nested:
                token = object()
                self.queue.append(token)
                self.condition.notify_all()
                deadline = monotonic() + timeout
                try:
                    while True:
                        if cancelled is not None and cancelled.is_set():
                            raise ContentionCancelled("cancelled before writer admission")
                        if self.queue[0] is token and self.owner is None and (not exclusive or self.active == 0):
                            self.queue.popleft()
                            if exclusive:
                                self.owner, self.keys = thread, ordered
                                for key in ordered: self.key_owners[key] = thread
                            else: self.active += 1
                            self.condition.notify_all()
                            break
                        remaining = deadline - monotonic()
                        if remaining <= 0: raise ContentionTimeout("writer admission timeout")
                        # Poll only cancellation; this is not a race/interleaving scheduler.
                        self.condition.wait(min(remaining, .05) if cancelled is not None else remaining)
                except BaseException:
                    self.queue.remove(token)
                    self.condition.notify_all()
                    raise
        try:
            yield ordered
        finally:
            if not nested:
                with self.condition:
                    if exclusive:
                        for key in reversed(self.keys): del self.key_owners[key]
                        self.owner, self.keys = None, ()
                    else: self.active -= 1
                    self.condition.notify_all()

    def held_exclusively(self):
        with self.condition: return self.owner == get_ident()


_coordinators = {}
_registry_lock = RLock()


def coordinator_for(path):
    # Independent in-memory databases must never share exclusion accidentally.
    if str(path) == ":memory:": return WriterCoordinator()
    identity = str(Path(path).resolve()).casefold()
    with _registry_lock:
        return _coordinators.setdefault(identity, WriterCoordinator())
