"""Entry point that runs *inside* the sandbox namespace.

Order matters and is enforced: build the namespace, start the testbed, assert
every service answers with its marker, prove the namespace is hermetic, and only
then run the measurement job. A job that runs on a half-built testbed yields
negative results indistinguishable from real ones, so every failure above raises
instead of degrading.
"""
from __future__ import annotations

import argparse
import json
import socket
import subprocess
import time
import traceback
from pathlib import Path

from ssrefuse import testbed_spec as spec
from ssrefuse.harness.services import AccessLog, assert_ready, start_all


def _run(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {(proc.stderr or proc.stdout).strip()}")
    return proc.stdout


def setup_namespace() -> dict:
    """Bring up loopback, alias the testbed addresses, and redirect DNS."""
    _run(["ip", "link", "set", "lo", "up"])
    for cidr in spec.ALIAS_IPS:
        _run(["ip", "addr", "add", cidr, "dev", "lo"])

    root = Path(spec.SANDBOX_ROOT)
    root.mkdir(parents=True, exist_ok=True)
    Path(spec.SECRET_FILE).write_text(
        f"{spec.MARKER_LOCALFILE}\nssrefuse local file read canary\n")

    resolv = root / "resolv.conf"
    resolv.write_text(f"nameserver {spec.IP_INTERNAL}\noptions timeout:1 attempts:1\n")
    _run(["mount", "--bind", str(resolv), "/etc/resolv.conf"])

    return {
        "addresses": [line.strip() for line in
                      _run(["ip", "-4", "-o", "addr", "show", "dev", "lo"]).splitlines()],
        "resolv_conf": Path("/etc/resolv.conf").read_text().strip(),
        "secret_file": spec.SECRET_FILE,
    }


def isolation_controls() -> dict:
    """Prove the namespace cannot reach anything real.

    Both checks must fail for the run to be allowed to continue. They are the
    negative control for the whole testbed: if either one succeeds, the lab is
    talking to the outside world and no result from this run means anything.
    """
    out: dict[str, str] = {}

    try:
        sock = socket.create_connection(("1.1.1.1", 443), timeout=3)
        sock.close()
        out["tcp_1.1.1.1:443"] = "CONNECTED"
    except OSError as exc:
        out["tcp_1.1.1.1:443"] = f"blocked ({type(exc).__name__})"

    for name in ("example.com", f"nonexistent.{spec.ZONE}"):
        try:
            out[f"dns:{name}"] = f"RESOLVED {socket.gethostbyname(name)}"
        except OSError:
            out[f"dns:{name}"] = "NXDOMAIN/unresolvable"

    leaks = [key for key, value in out.items()
             if value.startswith("CONNECTED") or value.startswith("RESOLVED")]
    out["hermetic"] = not leaks
    if leaks:
        raise AssertionError(f"sandbox is not hermetic, refusing to measure: {leaks}")
    return out


def job_selftest(plan: dict, log: AccessLog) -> dict:
    """Smoke job: fetch each target from inside and report what came back."""
    import http.client

    probes = [
        ("internal-by-ip", spec.IP_INTERNAL, spec.PORT_INTERNAL_ADMIN, "/admin"),
        ("internal-by-name", f"internal.{spec.ZONE}", spec.PORT_INTERNAL_ADMIN, "/admin"),
        ("metadata-by-ip", spec.IP_METADATA, spec.PORT_HTTP, "/latest/meta-data/iam/security-credentials/"),
        ("metadata-by-name", f"metadata.{spec.ZONE}", spec.PORT_HTTP, "/latest/meta-data/"),
        ("public-allowed", spec.ALLOWED_HOST, spec.PORT_HTTP, "/"),
        ("cgnat", f"cgnat.{spec.ZONE}", spec.PORT_HTTP, "/"),
        ("oob-http", f"probe-selftest.oob.{spec.ZONE}", spec.PORT_HTTP, "/"),
    ]
    results = {}
    for name, host, port, path in probes:
        try:
            conn = http.client.HTTPConnection(host, port, timeout=3)
            conn.request("GET", path)
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", "replace")
            conn.close()
            marker = next((m for m in spec.INTERNAL_MARKERS + (spec.MARKER_BENIGN, spec.MARKER_OOB)
                           if m in body), None)
            results[name] = {"status": resp.status, "marker": marker,
                             "body_head": body[:60].replace("\n", " ")}
        except Exception as exc:
            results[name] = {"error": f"{type(exc).__name__}: {exc}"}

    rebind = []
    for _ in range(4):
        try:
            rebind.append(socket.gethostbyname(f"rebind.{spec.ZONE}"))
        except OSError as exc:
            rebind.append(f"FAIL {type(exc).__name__}")
    results["rebind_sequence"] = rebind
    return {"probes": results}


def job_probe(plan: dict, log: AccessLog) -> dict:
    """Measurement job: start each lab and fire the payload catalog at it."""
    from ssrefuse.corpus import Corpus
    from ssrefuse.harness.payloads import FAMILY_BY_ID, summary
    from ssrefuse.harness.probe import Prober

    corpus = Corpus(plan["ground_truth"]) if plan.get("ground_truth") else Corpus()
    validation = corpus.validate(set(FAMILY_BY_ID))
    if validation.problems:
        raise AssertionError("corpus does not validate, refusing to measure:\n  "
                             + "\n  ".join(validation.problems))

    prober = Prober(corpus, plan["access_log"], Path(plan["result_path"]).parent)
    apps = plan.get("apps") or sorted(corpus.apps)
    runs = []
    for app_name in apps:
        port = spec.LAB_PORTS[corpus.apps[app_name].lang]
        runs.append(prober.run_app(app_name, port, python=plan.get("python")))
    return {"corpus": corpus.counts(), "catalog": summary(), "runs": runs}


JOBS = {"selftest": job_selftest, "probe": job_probe}


def main() -> None:
    parser = argparse.ArgumentParser(description="run a job inside the ssrefuse sandbox")
    parser.add_argument("--plan", required=True)
    args = parser.parse_args()

    plan = json.loads(Path(args.plan).read_text())
    result: dict = {"job": plan.get("job"), "started_at": time.time(), "ok": False}
    try:
        result["setup"] = setup_namespace()
        log = AccessLog(plan["access_log"])
        start_all(log)
        result["testbed"] = assert_ready()
        result["isolation"] = isolation_controls()
        job = JOBS.get(plan.get("job", ""))
        if job is None:
            raise KeyError(f"unknown job {plan.get('job')!r}; known: {sorted(JOBS)}")
        result.update(job(plan, log))
        result["ok"] = True
    except BaseException as exc:  # noqa: BLE001 - recorded, then re-reported in the file
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["traceback"] = traceback.format_exc()
    finally:
        result["finished_at"] = time.time()
        Path(plan["result_path"]).write_text(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
