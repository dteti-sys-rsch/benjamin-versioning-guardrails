"""One-command offline tests and timestamped evidence. Run with the project venv."""
import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import os
import platform
from pathlib import Path
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET

from atomicroot.observability import Stopwatch, point

ROOT = Path(__file__).resolve().parent
PHASE4 = ("atomicroot/tests/test_phase4_replay.py", "atomicroot/tests/test_phase4_fallback.py")
PHASE5 = ("atomicroot/tests/test_phase5_policies.py", "atomicroot/tests/test_phase5_modes.py", "atomicroot/tests/test_phase5_oracle.py")
OBSERVABILITY = ("atomicroot/tests/test_timestamps.py", "atomicroot/tests/test_test_runner.py")
PHASE55 = ("atomicroot/tests/test_phase55_goals.py",)
PROFILES = ("quick", "phase4", "phase5", "phase55", "regression", "scenarios", "all")


@dataclass(frozen=True)
class Command:
    name: str
    args: tuple[str, ...]
    dependency: str | None = None


def plan(profile, directory, *, scenario=None, mode=None):
    from atomicroot.evaluation.modes import MODES
    from atomicroot.evaluation.scenarios import SCENARIOS
    if profile not in PROFILES: raise ValueError("unknown test profile")
    if (scenario or mode) and profile != "scenarios": raise ValueError("--scenario/--mode require the scenarios profile")
    if scenario is not None and scenario not in SCENARIOS: raise ValueError("unknown scenario")
    if mode is not None and (mode not in MODES or scenario is None): raise ValueError("--mode requires a valid --scenario")
    commands = []
    def pytest(name, paths):
        commands.append(Command(name, (sys.executable, "-m", "pytest", *paths, "-q", "--junitxml", str(directory / (name + ".xml")))))
    if profile == "quick": pytest("quick", (*OBSERVABILITY, PHASE5[0], PHASE5[2]))
    elif profile == "phase4": pytest("phase4", (*PHASE4, OBSERVABILITY[0]))
    elif profile == "phase5": pytest("phase5", (*PHASE5, OBSERVABILITY[0]))
    elif profile == "phase55": pytest("phase55", (*PHASE55, OBSERVABILITY[0]))
    elif profile in {"regression", "all"}: pytest("regression", ("atomicroot/tests",))
    if profile == "all":
        commands.append(Command("phase4-artifacts", (sys.executable, str(ROOT / "examples/phase4/generate.py"), "--output", str(directory / "phase4"))))
    if profile in {"scenarios", "all"}:
        if scenario is None:
            commands.append(Command("phase5-artifacts", (sys.executable, str(ROOT / "examples/phase5/generate.py"), "--output", str(directory / "phase5"))))
        else:
            cli = str(ROOT / "phase5_cli.py")
            target = directory / scenario
            if mode:
                commands.append(Command("scenario-record", (sys.executable, cli, "record", scenario, str(target / (mode + ".json")), "--mode", mode)))
            else:
                commands.append(Command("scenario-record", (sys.executable, cli, "compare", scenario, str(target))))
            for selected in (mode,) if mode else MODES:
                commands.append(Command("replay-" + selected, (sys.executable, cli, "replay", str(target / (selected + ".json"))), "scenario-record"))
    if profile == "all":
        commands.append(Command("phase55-artifacts", (sys.executable, str(ROOT / "examples/phase55/generate.py"), "--output", str(directory / "phase55"))))
    return commands


def write_json(path, data):
    # Preserve an earlier valid summary if writing the new snapshot is interrupted.
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def progress(directory, event, **fields):
    record = {"event": event, **point(), **fields}
    with (directory / "progress.jsonl").open("a", encoding="utf-8") as stream: stream.write(json.dumps(record) + "\n")
    print(f"[{record['observed_at_utc']}] {event} " + " ".join(f"{k}={v}" for k, v in fields.items()), flush=True)


def execute(command, directory, timeout):
    timer = Stopwatch()
    log = directory / (command.name + ".log")
    result = {"name": command.name, "args": list(command.args), "cwd": str(ROOT), "log": str(log), "status": "RUNNING"}
    progress(directory, "COMMAND_STARTED", name=command.name, log=str(log))
    child = None
    try:
        with log.open("w", encoding="utf-8") as output:
            environment = {**os.environ, "PYTHONIOENCODING": "utf-8"}
            child = subprocess.Popen(command.args, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
            remaining = timeout
            while True:
                interval = min(30, remaining)
                try:
                    child.wait(timeout=interval)
                    result.update(status="PASSED" if child.returncode == 0 else "FAILED", exit_code=child.returncode)
                    break
                except subprocess.TimeoutExpired:
                    remaining -= interval
                    if remaining <= 0:
                        child.kill(); child.wait(timeout=10)
                        result.update(status="TIMEOUT", exit_code=124, process_exit_code=child.returncode)
                        break
                    progress(directory, "COMMAND_RUNNING", name=command.name, timeout_remaining_seconds=remaining)
    except KeyboardInterrupt:
        if child is not None and child.poll() is None: child.kill(); child.wait(timeout=10)
        result.update(status="INTERRUPTED", exit_code=130)
    except OSError as exc:
        result.update(status="FAILED", exit_code=1, error=type(exc).__name__ + ": " + str(exc))
    except subprocess.TimeoutExpired:
        result.update(status="FAILED", exit_code=1, error="child did not terminate within cleanup deadline")
    result["observed_timing"] = timer.finish()
    progress(directory, "COMMAND_FINISHED", name=command.name, status=result["status"], exit_code=result["exit_code"])
    return result


def junit(path):
    suites = list(ET.parse(path).getroot().iter("testsuite"))
    return {"tests": sum(int(s.get("tests", 0)) for s in suites), "failures": sum(int(s.get("failures", 0)) for s in suites),
            "errors": sum(int(s.get("errors", 0)) for s in suites), "skipped": sum(int(s.get("skipped", 0)) for s in suites),
            "suite_timestamps": [s.get("timestamp") for s in suites], "seconds": sum(float(s.get("time", 0)) for s in suites)}


def file_index(directory):
    files = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.name in {"files.json", "summary.json"} or path.suffix == ".tmp": continue
        stat = path.stat()
        files.append({"path": str(path.relative_to(directory)), "size": stat.st_size,
            "file_modified_at_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return {"generated_at_utc": point()["observed_at_utc"], "files": files}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=PROFILES, nargs="?", default="quick")
    parser.add_argument("--scenario")
    parser.add_argument("--mode")
    parser.add_argument("--output", type=Path, help="new result directory; existing directories are rejected")
    parser.add_argument("--timeout", type=float, default=300, help="maximum seconds per command (default 300)")
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 3600: parser.error("timeout must be in (0, 3600]")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = (args.output or ROOT / ".runs" / "testing" / (stamp + "-" + uuid.uuid4().hex[:8])).resolve()
    try: commands = plan(args.profile, directory, scenario=args.scenario, mode=args.mode)
    except ValueError as exc: parser.error(str(exc))
    try: directory.mkdir(parents=True, exist_ok=False)
    except FileExistsError: parser.error("result directory exists; choose a new path to preserve previous evidence")
    timer = Stopwatch()
    summary = {"schema_version": 1, "profile": args.profile, "directory": str(directory), "python": sys.executable,
               "python_version": platform.python_version(), "platform": platform.platform(),
               "effects": "SIMULATED", "live_validation": "NOT RUN", "status": "RUNNING", "commands": []}
    write_json(directory / "plan.json", {"profile": args.profile, "generated_at_utc": point()["observed_at_utc"], "commands": [{"name": c.name, "args": c.args, "dependency": c.dependency} for c in commands]})
    write_json(directory / "summary.json", summary)
    completed, interrupted = {}, False
    progress(directory, "RUN_STARTED", profile=args.profile, output_directory=str(directory))
    for command in commands:
        if interrupted or command.dependency and completed[command.dependency]["status"] != "PASSED":
            result = {"name": command.name, "status": "SKIPPED", "reason": "interrupted" if interrupted else "dependency failed", **point()}
        else:
            result = execute(command, directory, args.timeout)
            interrupted = result["status"] == "INTERRUPTED"
            report = directory / (command.name + ".xml")
            if report.exists():
                try: result["junit"] = junit(report)
                except (ValueError, ET.ParseError): result.update(status="FAILED", error="invalid JUnit report")
        completed[command.name] = result
        summary["commands"].append(result)
        write_json(directory / "summary.json", summary)
    summary["status"] = "INTERRUPTED" if interrupted else "PASSED" if all(r["status"] == "PASSED" for r in summary["commands"]) else "FAILED"
    progress(directory, "RUN_FINISHED", status=summary["status"])
    write_json(directory / "files.json", file_index(directory))
    summary["observed_timing"] = timer.finish()
    write_json(directory / "summary.json", summary)
    print("Results: " + str(directory / "summary.json"), flush=True)
    return 130 if interrupted else 0 if summary["status"] == "PASSED" else 1


if __name__ == "__main__": raise SystemExit(main())
