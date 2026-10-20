"""Host side of the sandbox: build and run the unprivileged namespace.

The namespace is created with ``unshare -r -n -m``: a user namespace (so we get
CAP_NET_ADMIN without real root), a network namespace (so the aliased addresses
and port 53 exist only here), and a mount namespace (so /etc/resolv.conf can be
pointed at the testbed resolver without touching the host file).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


class SandboxUnavailable(RuntimeError):
    pass


def check_support() -> dict[str, str]:
    """Verify the host can create the namespace, with the reason if it cannot."""
    missing = [tool for tool in ("unshare", "ip", "mount") if not shutil.which(tool)]
    if missing:
        raise SandboxUnavailable(f"missing tools: {', '.join(missing)}")
    probe = subprocess.run(
        ["unshare", "-r", "-n", "-m", "--", "ip", "link", "set", "lo", "up"],
        capture_output=True, text=True, timeout=30,
    )
    if probe.returncode != 0:
        raise SandboxUnavailable(
            "cannot create user+net namespace: "
            f"{(probe.stderr or probe.stdout).strip()[:200]}"
        )
    return {"unshare": shutil.which("unshare") or "", "status": "ok"}


def run_in_sandbox(plan: dict, run_dir: str | os.PathLike, timeout: float = 300.0) -> dict:
    """Run one job inside the sandbox and return the result it wrote.

    Communication is by file, never by pipe: the job starts lab servers as child
    processes, and a child that inherits the pipe keeps it open, so a reader
    waiting for EOF would hang rather than finish.
    """
    check_support()
    run_path = Path(run_dir)
    run_path.mkdir(parents=True, exist_ok=True)
    plan = dict(plan)
    plan.setdefault("result_path", str(run_path / "result.json"))
    plan.setdefault("access_log", str(run_path / "access.jsonl"))
    plan_path = run_path / "plan.json"
    plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True))

    result_path = Path(plan["result_path"])
    if result_path.exists():
        result_path.unlink()
    stdio_path = run_path / f"inside-{time.strftime('%Y%m%d-%H%M%S')}.log"

    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT), PYTHONUNBUFFERED="1")
    import sys
    with open(stdio_path, "w") as fh:
        proc = subprocess.run(
            ["unshare", "-r", "-n", "-m", "--",
             sys.executable, "-m", "ssrefuse.harness.inside", "--plan", str(plan_path)],
            cwd=str(REPO_ROOT), env=env, stdout=fh, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, timeout=timeout,
        )
    if not result_path.exists():
        tail = stdio_path.read_text()[-2000:]
        raise RuntimeError(
            f"sandbox job produced no result file (exit {proc.returncode})\n--- log tail ---\n{tail}"
        )
    result = json.loads(result_path.read_text())
    result["_exit_code"] = proc.returncode
    result["_stdio_log"] = str(stdio_path)
    result["_plan"] = str(plan_path)
    return result
