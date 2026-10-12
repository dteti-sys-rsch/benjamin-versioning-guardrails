"""Local, bounded progress metadata; never prompts, arguments, tickets or keys."""
import json
from datetime import datetime, timezone
from pathlib import Path


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
        self.sequence = 0
        if self.path.exists():
            with self.path.open(encoding="utf-8") as stream: self.sequence = sum(1 for _ in stream)

    def __call__(self, event, **fields):
        if not set(fields) <= FIELDS: raise ValueError("unsupported progress field")
        clean = {k: (str(v).replace("\n", " ").replace("\r", " ")[:128] if isinstance(v, str) else v)
                 for k, v in fields.items() if v is not None}
        if any(type(v) not in (str, int, float, bool) for v in clean.values()): raise ValueError("scalar progress metadata only")
        self.sequence += 1
        record = {"sequence": self.sequence, "time": datetime.now(timezone.utc).isoformat(), "event": event, **clean}
        with self.path.open("a", encoding="utf-8") as stream: stream.write(json.dumps(record) + "\n")
        if not self.quiet:
            display = {k: v[:16] if k in {"operation", "review"} and isinstance(v, str) else v for k, v in clean.items()}
            print(f"[{self.sequence:03d}] {event}" + "".join(f" {k}={v}" for k, v in display.items()), flush=True)
