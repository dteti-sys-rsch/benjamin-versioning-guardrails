"""Invocation reports must not erase previously recorded run evidence."""
from pathlib import Path
import json
from atomicroot.framework.storage import uid


def write_invocation_report(directory, report, transcript):
    directory = Path(directory)
    history = directory / "invocations"
    history.mkdir(exist_ok=True)
    (history / (uid("invocation") + ".json")).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    # A failed fresh start has no new workflow result. Preserve the previous
    # status/transcript; the invocation error remains in its own immutable file.
    if "workflow_status" not in report and (directory / "status.json").exists(): return
    (directory / "status.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    (directory / "transcript.json").write_text(json.dumps(transcript, indent=2, ensure_ascii=False), encoding="utf-8")
