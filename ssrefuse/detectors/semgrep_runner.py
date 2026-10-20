"""Semgrep detector.

The positive control is scanned in the same invocation as the corpus, not in a
separate one: a rule file that fails to load, a semgrep upgrade that changes
pattern semantics, or a typo in a metavariable all produce an empty result set,
and the only cheap way to tell that apart from a clean corpus is to include a
file whose answer is known.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

from ssrefuse.corpus import REPO_ROOT
from ssrefuse.detectors.base import Candidate, DetectorRun

CONTROL_FILE = REPO_ROOT / "tests" / "fixtures" / "positive_control_python.py"
DEFAULT_CONFIGS = {
    "inventory": REPO_ROOT / "rules" / "semgrep" / "python-inventory.yaml",
    "taint-nosan": REPO_ROOT / "rules" / "semgrep" / "python-taint-nosan.yaml",
    "taint-naive": REPO_ROOT / "rules" / "semgrep" / "python-taint-naive.yaml",
}


def semgrep_binary() -> str:
    for candidate in (REPO_ROOT / ".venv" / "bin" / "semgrep", Path("semgrep")):
        found = shutil.which(str(candidate))
        if found:
            return found
    raise FileNotFoundError(
        "semgrep not found. Install it into the project venv with "
        "`.venv/bin/pip install semgrep`, or put it on PATH.")


def run_semgrep(detector: str, config: Path, targets: list[Path],
                timeout: float = 600.0) -> DetectorRun:
    binary = semgrep_binary()
    scan_targets = [str(t) for t in targets] + [str(CONTROL_FILE)]
    cmd = [binary, "scan", "--config", str(config), "--json", "--quiet",
           "--metrics", "off", "--no-git-ignore", "--disable-version-check",
           *scan_targets]
    started = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          cwd=str(REPO_ROOT))
    duration = time.time() - started

    run = DetectorRun(detector=detector, config=str(config.relative_to(REPO_ROOT)),
                      duration_s=duration, control_file=str(CONTROL_FILE))
    try:
        report = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        run.errors.append(f"semgrep produced unparsable output (exit {proc.returncode}): "
                          f"{(proc.stderr or proc.stdout)[:400]}")
        return run

    for error in report.get("errors", []):
        run.errors.append(f"{error.get('type', 'error')}: {error.get('message', '')[:200]}")
    run.scanned_files = len(report.get("paths", {}).get("scanned", []))

    control_name = CONTROL_FILE.name
    for finding in report.get("results", []):
        path = finding.get("path", "")
        if Path(path).name == control_name:
            run.control_findings += 1
            continue
        extra = finding.get("extra", {})
        run.candidates.append(Candidate(
            detector=detector,
            rule_id=finding.get("check_id", ""),
            file=path,
            line=finding.get("start", {}).get("line", 0),
            message=(extra.get("message", "") or "").strip()[:300],
            sink=(extra.get("lines", "") or "").strip()[:160],
            confidence=extra.get("metadata", {}).get("confidence", ""),
            extra={"severity": extra.get("severity", "")},
        ))
    return run


def run_all(targets: list[Path] | None = None,
            configs: dict[str, Path] | None = None) -> list[DetectorRun]:
    targets = targets or [REPO_ROOT / "corpus" / "labs"]
    configs = configs or DEFAULT_CONFIGS
    return [run_semgrep(name, path, targets) for name, path in configs.items()]
