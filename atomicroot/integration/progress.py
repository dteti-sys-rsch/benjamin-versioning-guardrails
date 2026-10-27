"""Local, bounded progress metadata; never prompts, arguments, tickets or keys."""
import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from time import monotonic


FIELDS = frozenset({"role", "model", "provider", "tool", "status", "delivery", "operation",
                    "review", "attempt", "observations", "tools", "budget", "step", "input_tokens",
                    "output_tokens", "elapsed_ms", "error", "repairs"})


def emit(progress, event, **fields):
    if progress is not None:
        try: progress(event, **fields)
        except Exception: pass  # Observability must not grant/deny or alter commit.


class Progress:
    def __init__(self, path, *, quiet=False):
        self.path, self.quiet = Path(path), quiet
        self._lock = Lock()
        self.sequence = 0
        if self.path.exists():
            with self.path.open(encoding="utf-8") as stream: self.sequence = sum(1 for _ in stream)
        self._started = self._previous = monotonic()

    def __call__(self, event, **fields):
        with self._lock: self._write(event, **fields)

    def _write(self, event, **fields):
        if not set(fields) <= FIELDS: raise ValueError("unsupported progress field")
        clean = {k: (str(v).replace("\n", " ").replace("\r", " ")[:128] if isinstance(v, str) else v)
                 for k, v in fields.items() if v is not None}
        if any(type(v) not in (str, int, float, bool) for v in clean.values()): raise ValueError("scalar progress metadata only")
        now = monotonic()
        # Wall-clock timestamps can jump; durations use a monotonic clock per invocation.
        elapsed = (now - self._started) * 1000
        delta = (now - self._previous) * 1000
        self.sequence += 1
        record = {"sequence": self.sequence, "time": datetime.now(timezone.utc).isoformat(),
                  "session_elapsed_ms": round(elapsed, 3), "since_previous_ms": round(delta, 3),
                  "event": event, **clean}
        with self.path.open("a", encoding="utf-8") as stream: stream.write(json.dumps(record) + "\n")
        self._previous = now
        if not self.quiet:
            display = {k: v[:16] if k in {"operation", "review"} and isinstance(v, str) else v for k, v in clean.items()}
            print(f"[{self.sequence:03d}] [{record['time']}] [total={elapsed / 1000:.3f}s delta={delta / 1000:.3f}s] {event}"
                  + "".join(f" {k}={v}" for k, v in display.items()), flush=True)
