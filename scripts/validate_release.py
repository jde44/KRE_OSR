#!/usr/bin/env python3
"""One-command offline release-candidate validation.

Default mode verifies the COMMITTED evidence (benchmark result, SBOM, manifest) against freshly computed
values before anything else, and never rewrites it, so source or evidence drift fails the run.
`--regenerate` rewrites the evidence first; use it only for an intentional, reviewed evidence update.
"""

import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
if not sys.pycache_prefix:  # never write bytecode caches into the candidate tree
    import tempfile
    sys.pycache_prefix = tempfile.mkdtemp(prefix="osr-pycache-")
sys.path.insert(0, str(ROOT / "scripts"))
import hashlib

import release_evidence
import run_routing_benchmark

ADVERSARIAL_CATALOG = Path("evals") / "adversarial_catalog.json"
ADVERSARIAL_RESULTS = (Path("evals") / "results" / "adversarial-full.json", Path("evals") / "results" / "adversarial-sandbox.json")


def adversarial_source_sha256(root):
    """Same digest as scripts/run_adversarial_eval.py, computed for an arbitrary tree."""
    root = Path(root)
    digest = hashlib.sha256()
    files = sorted([*root.glob("src/**/*.py"), *root.glob("tests/test_*.py"), root / "scripts/run_adversarial_eval.py"])
    for path in files:
        digest.update(path.relative_to(root).as_posix().encode()); digest.update(b"\0"); digest.update(path.read_bytes()); digest.update(b"\0")
    return digest.hexdigest()


def adversarial_freshness(root):
    """The adversarial results must have been produced from exactly the current source, tests and catalog."""
    root = Path(root)
    errors = []
    source = adversarial_source_sha256(root)
    catalog = hashlib.sha256((root / ADVERSARIAL_CATALOG).read_bytes()).hexdigest()
    for relative in ADVERSARIAL_RESULTS:
        try:
            result = json.loads((root / relative).read_text())
        except (OSError, ValueError):
            errors.append("adversarial result missing or unreadable: " + relative.as_posix())
            continue
        if result.get("source_sha256") != source:
            errors.append("adversarial result predates current source/tests: " + relative.as_posix())
        if result.get("catalog_sha256") != catalog:
            errors.append("adversarial result predates current catalog: " + relative.as_posix())
        errors += _adversarial_consistency(root, relative, result)
    return errors


def _adversarial_consistency(root, relative, result):
    """Recomputes counts, mappings and dispositions from the raw outcomes, so a hand-edited result cannot pass."""
    import run_adversarial_eval
    try:
        catalog = json.loads((root / ADVERSARIAL_CATALOG).read_text())
        raw = result["raw_outcomes"]
        sandbox = bool(result["environment"]["sandbox_safe"])
        assessed = run_adversarial_eval.assess(raw, catalog, sandbox)
        counts = {s: sum(1 for x in raw if x["status"] == s) for s in ("pass", "fail", "error", "skip")}
        summary = result["summary"]
        expected_disposition = run_adversarial_eval.disposition(assessed)
        consistent = (
            all(summary[k] == v for k, v in counts.items()) and summary["total"] == len(raw)
            and summary["disposition"] == expected_disposition
            and [e["disposition"] for e in result["evaluations"]] == [e["disposition"] for e in assessed["evaluations"]]
            and all(result["mapping"][k] == assessed[k] for k in ("metadata_gaps", "allowed_skips", "unallowed_skips", "mapped_outcome_count", "total_outcome_count"))
        )
    except (KeyError, TypeError, ValueError):
        consistent = False
    return [] if consistent else ["adversarial result inconsistent with its raw outcomes: " + relative.as_posix()]

BENCHMARK_RESULT = Path("evals") / "results" / "routing-benchmark.json"
BENCHMARK_FIXTURE = Path("evals") / "benchmark_tasks.json"
SBOM = Path("release") / "sbom.spdx.json"


def render(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def check_evidence(root):
    """Returns a list of drift errors; reads only, never writes."""
    root = Path(root)
    errors = []
    expected_benchmark = render(run_routing_benchmark.evaluate(root / BENCHMARK_FIXTURE))
    result_path = root / BENCHMARK_RESULT
    if not result_path.is_file() or result_path.read_text() != expected_benchmark:
        errors.append("benchmark result is stale or altered: " + BENCHMARK_RESULT.as_posix())
    sbom_path = root / SBOM
    if not sbom_path.is_file() or sbom_path.read_text() != render(release_evidence.sbom_for(root)):
        errors.append("SBOM is stale or altered: " + SBOM.as_posix())
    manifest_path = root / release_evidence.MANIFEST_PATH
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, ValueError):
        return errors + ["manifest is missing or unreadable"]
    errors += ["manifest: " + e for e in release_evidence.verify_manifest(root, manifest)]
    errors += adversarial_freshness(root)
    return errors


def regenerate(root):
    root = Path(root)
    result = run_routing_benchmark.evaluate(root / BENCHMARK_FIXTURE)
    (root / BENCHMARK_RESULT).write_text(render(result))
    release_evidence.write_evidence(root)
    return result


def run(command, env=None):
    print("+", " ".join(map(str, command)))
    subprocess.run(command, cwd=ROOT, env=env, check=True)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--regenerate", action="store_true", help="rewrite benchmark, SBOM and manifest before validating")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if sys.version_info < (3, 10):
        raise SystemExit("Python 3.10+ required")
    if args.regenerate:
        regenerate(ROOT)
        print("evidence regenerated (review the diff before relying on it)")
    drift = check_evidence(ROOT)
    if drift:
        print(json.dumps({"status": "fail", "evidence_drift": drift}, indent=2))
        return 1
    benchmark = json.loads((ROOT / BENCHMARK_RESULT).read_text())
    if benchmark["disposition"] != "pass":
        print(json.dumps({"status": "fail", "benchmark": benchmark["checks"]}, indent=2))
        return 1
    external_cache = tempfile.mkdtemp(prefix="osr-pycache-")
    env = dict(os.environ, PYTHONPYCACHEPREFIX=external_cache, PYTHONHASHSEED="0")
    run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], env)
    run([sys.executable, "-m", "compileall", "-q", "src", "tests", "scripts"], env)
    findings = release_evidence.scan_tree(ROOT)
    if findings:
        print(json.dumps({"status": "fail", "scan_findings": findings}, indent=2))
        return 1
    print(json.dumps({
        "status": "pass", "mode": "regenerate" if args.regenerate else "check-committed",
        "tests": "pass", "compile": "pass", "benchmark": "pass", "manifest": "exact", "sbom": "SPDX-2.3", "scan_findings": 0,
        "python": platform.python_version(), "platform": platform.platform(terse=True),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
