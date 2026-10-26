"""Semgrep detector.

A detector here is a *tier* -- sink inventory, taint without sanitizers, taint
with the sanitizers a reviewer would reach for -- and a tier spans every
language in the corpus. One semgrep invocation per tier runs that tier's rule
files for all languages together, so the numbers in the report compare tiers
rather than rule files.

The positive controls are scanned in the same invocation as the corpus, not in
a separate one, and there is one per language. A rule file that fails to load,
a semgrep upgrade that changes pattern semantics, or a typo in a metavariable
all produce an empty result set, and the only cheap way to tell that apart from
a clean codebase is to include files whose answer is known. Per language,
because a tier whose Python rules work and whose JavaScript rules load nothing
would still show a healthy total.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

from ssrefuse.corpus import REPO_ROOT
from ssrefuse.detectors.base import Candidate, DetectorRun

RULES = REPO_ROOT / "rules" / "semgrep"
FIXTURES = REPO_ROOT / "tests" / "fixtures"

# One control per language whose rules are loaded, and the check is per file:
# a tier whose Python rules run and whose PHP rules fail to load still returns
# a healthy-looking total.
CONTROL_FILES = [
    FIXTURES / "positive_control_python.py",
    FIXTURES / "positive_control_javascript.js",
    FIXTURES / "positive_control_php.php",
]

DEFAULT_CONFIGS: dict[str, list[Path]] = {
    "inventory": [RULES / "python-inventory.yaml", RULES / "js-inventory.yaml",
                  RULES / "php-inventory.yaml"],
    "taint-nosan": [RULES / "python-taint-nosan.yaml", RULES / "js-taint-nosan.yaml",
                    RULES / "php-taint-nosan.yaml"],
    "taint-naive": [RULES / "python-taint-naive.yaml", RULES / "js-taint-naive.yaml",
                    RULES / "php-taint-naive.yaml"],
}

# The sink-inventory pass over the static-only corpus is a separate run, with
# separate targets and separate controls, because what it produces is a
# different measurement. The labelled corpus is scored for precision and
# recall against labels the prober reproduced. What the static-only files can
# answer without running is "which sinks does the rule see", and that is all
# this run is for.
#
# Java is still in that position: no runnable lab, so no label a prober
# reproduced, so its findings must not enter the scored table. PHP left it on
# 2026-10-25 -- `corpus/labs/php_ssrf` runs and is labelled, so the PHP rules
# are in DEFAULT_CONFIGS above and the PHP lab is scored like the other two.
# The PHP files under static_only stay here as well, which is not a
# duplication: one asks what the rule sees, the other asks whether what it saw
# was true.
SINK_CONFIGS: list[Path] = [
    RULES / "python-inventory.yaml", RULES / "js-inventory.yaml",
    RULES / "php-inventory.yaml", RULES / "java-inventory.yaml",
]
SINK_CONTROLS: list[Path] = [
    FIXTURES / "positive_control_python.py",
    FIXTURES / "positive_control_javascript.js",
    FIXTURES / "positive_control_php.php",
    FIXTURES / "PositiveControlJava.java",
]
STATIC_ONLY = REPO_ROOT / "corpus" / "static_only"


def semgrep_binary() -> str:
    for candidate in (REPO_ROOT / ".venv" / "bin" / "semgrep", Path("semgrep")):
        found = shutil.which(str(candidate))
        if found:
            return found
    raise FileNotFoundError(
        "semgrep not found. Install it into the project venv with "
        "`.venv/bin/pip install semgrep`, or put it on PATH.")


def run_semgrep(detector: str, configs: list[Path], targets: list[Path],
                controls: list[Path] | None = None,
                timeout: float = 600.0) -> DetectorRun:
    binary = semgrep_binary()
    controls = list(controls if controls is not None else CONTROL_FILES)
    scan_targets = [str(t) for t in targets] + [str(c) for c in controls]
    config_args: list[str] = []
    for config in configs:
        config_args += ["--config", str(config)]
    cmd = [binary, "scan", *config_args, "--json", "--quiet",
           "--metrics", "off", "--no-git-ignore", "--disable-version-check",
           *scan_targets]
    started = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          cwd=str(REPO_ROOT))
    duration = time.time() - started

    run = DetectorRun(
        detector=detector,
        config=", ".join(str(c.relative_to(REPO_ROOT)) for c in configs),
        duration_s=duration,
        # Seeded at zero so a control file that produced nothing is reported as
        # a silent control rather than simply being absent from the mapping.
        control_by_file={c.name: 0 for c in controls},
    )
    try:
        report = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        run.errors.append(f"semgrep produced unparsable output (exit {proc.returncode}): "
                          f"{(proc.stderr or proc.stdout)[:400]}")
        return run

    for error in report.get("errors", []):
        run.errors.append(f"{error.get('type', 'error')}: {error.get('message', '')[:200]}")
    run.scanned_files = len(report.get("paths", {}).get("scanned", []))

    control_names = {c.name for c in controls}
    for finding in report.get("results", []):
        path = finding.get("path", "")
        name = Path(path).name
        if name in control_names:
            run.control_by_file[name] += 1
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
            extra={"severity": extra.get("severity", ""),
                   "lang": extra.get("metadata", {}).get("ssrefuse-lang", "")},
        ))
    return run


def run_all(targets: list[Path] | None = None,
            configs: dict[str, list[Path]] | None = None) -> list[DetectorRun]:
    targets = targets or [REPO_ROOT / "corpus" / "labs"]
    configs = configs or DEFAULT_CONFIGS
    return [run_semgrep(name, paths, targets) for name, paths in configs.items()]


def run_sink_inventory(targets: list[Path] | None = None) -> DetectorRun:
    """Sink inventory across all four languages, over the static-only corpus."""
    return run_semgrep("sink-inventory", SINK_CONFIGS,
                       targets or [STATIC_ONLY], controls=SINK_CONTROLS)
