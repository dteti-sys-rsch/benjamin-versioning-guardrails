"""Small deterministic phase-2 checkpoint harness; not a scheduler explorer."""
from __future__ import annotations

import threading


class ControlledHarness:
    def __init__(self, replay: list[tuple[str | None, str]] | None = None):
        self._cv = threading.Condition()
        self._paused: set[tuple[str, str | None]] = set()
        self.steps: list[tuple[int, str | None, str]] = []
        self.replay = replay

    def pause(self, stage: str, action_id: str | None):
        with self._cv:
            self._paused.add((stage, action_id))

    def checkpoint(self, stage: str, action_id: str | None):
        with self._cv:
            if self.replay is not None:
                expected = (action_id, stage)
                ready = self._cv.wait_for(
                    lambda: len(self.steps) < len(self.replay) and
                    self.replay[len(self.steps)] == expected,
                    timeout=5)
                if not ready:
                    raise TimeoutError(f"replay did not reach {expected}")
            self.steps.append((len(self.steps) + 1, action_id, stage))
            self._cv.notify_all()
            while (stage, action_id) in self._paused:
                self._cv.wait()

    def wait_reached(self, stage: str, action_id: str | None, timeout: float = 5):
        with self._cv:
            reached = self._cv.wait_for(
                lambda: any(a == action_id and s == stage for _, a, s in self.steps),
                timeout=timeout)
            if not reached:
                raise TimeoutError(f"checkpoint {stage}/{action_id} not reached")

    def release(self, stage: str, action_id: str | None):
        with self._cv:
            self._paused.discard((stage, action_id))
            self._cv.notify_all()

    def recorded_schedule(self) -> list[tuple[str | None, str]]:
        with self._cv:
            return [(action_id, stage) for _, action_id, stage in self.steps]
