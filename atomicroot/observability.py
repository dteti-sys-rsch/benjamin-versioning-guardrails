"""Real recording time only; never an authorization clock or replay input."""
from datetime import datetime, timezone
import os
from time import perf_counter_ns


def point():
    return {"observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
            "monotonic_ns": perf_counter_ns(), "process_id": os.getpid()}


class Stopwatch:
    def __init__(self):
        self.start = point()
        self.end = None

    def finish(self):
        if self.end is None: self.end = point()
        return {"started_at_utc": self.start["observed_at_utc"], "finished_at_utc": self.end["observed_at_utc"],
                "duration_ns": self.end["monotonic_ns"] - self.start["monotonic_ns"], "process_id": self.start["process_id"]}


def protocol_run(run):
    # Only this trusted scheduler-root sidecar is observational. Never remove
    # fields recursively from worker data, signed tickets, facts or receipts.
    return {k: v for k, v in run.items() if k != "observed_timing"}


def event_times(events, hooks, ledger):
    """Link oracle events to recorded post-transaction observer points.

    Export time is not fabricated as effect time when a source hook is absent.
    Deferred hooks explicitly describe observation after the fallback release.
    """
    exported = point()
    protocol_times = {(e["task"], e["args"]["operation_id"]): e["time"] for e in ledger["events"]}
    result = []
    for index, event in enumerate(events):
        task, operation = event["task"], event["operation"]
        if event["kind"] == "INTENT":
            matches = [(i, h) for i, h in enumerate(hooks) if h["stage"] == "mutation:operation" and h["action"] == f"operation:{task}:{operation}"]
        else:
            matches = [(i, h) for i, h in enumerate(hooks) if h["stage"] == "receiver_apply" and h["action"] == operation and h.get("task") == task]
        entry = {"event": index, "kind": event["kind"], "task": task, "operation": operation,
                 "protocol_commit_time": protocol_times.get((task, operation)), "exported_at_utc": exported["observed_at_utc"]}
        if matches:
            hook_index, hook = matches[-1]
            entry.update(hook_index=hook_index, source="post-transaction hook", observed=hook["observed"],
                         deferred=hook.get("deferred", False))
        else: entry.update(source="source timing unavailable", observed=None)
        result.append(entry)
    return result
