#!/usr/bin/env python3
"""Run the deterministic adversarial tests and emit machine-readable raw outcomes and a summary."""
import argparse
import hashlib
import json
import os
import platform
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if not sys.pycache_prefix:  # never write bytecode caches into the candidate tree
    import tempfile
    sys.pycache_prefix = tempfile.mkdtemp(prefix="osr-pycache-")

class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs); self.raw = []
    def startTest(self, test):
        self._started = time.monotonic(); super().startTest(test)
    def _record(self, test, status, detail=""):
        self.raw.append({"test_id": test.id(), "status": status, "seconds": round(time.monotonic()-self._started, 6), "detail": detail[-2000:]})
    def addSuccess(self, test): super().addSuccess(test); self._record(test, "pass")
    def addSkip(self, test, reason): super().addSkip(test, reason); self._record(test, "skip", reason)
    def addFailure(self, test, err): super().addFailure(test, err); self._record(test, "fail", self._exc_info_to_string(err, test))
    def addError(self, test, err): super().addError(test, err); self._record(test, "error", self._exc_info_to_string(err, test))

def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite): yield from flatten(item)
        else: yield item

# Release-evidence tests check committed evidence files (including this runner's own output), not security
# behaviour, so they are excluded from adversarial runs and validated by scripts/test.sh instead.
EVIDENCE_STATE_MODULES = ("test_release_evidence",)

REQUIRED_EVAL_FIELDS = {"id", "purpose", "threshold", "owner", "due_point", "evidence", "remediation", "tests"}

def assess(raw, catalog, sandbox_safe):
    allowed = set(catalog.get("allowed_capability_skips", ()))
    metadata_gaps, evaluation_results, mapped_ids = [], [], set()
    for evaluation in catalog.get("evaluations", ()):
        missing_fields = sorted(REQUIRED_EVAL_FIELDS - set(evaluation))
        if missing_fields:
            metadata_gaps.append({"id": evaluation.get("id"), "missing_fields": missing_fields})
        expected = set(evaluation.get("tests", ()))
        matched = [item for item in raw if item["test_id"].rsplit(".", 1)[-1] in expected]
        mapped_ids.update(item["test_id"] for item in matched)
        observed = {item["test_id"].rsplit(".", 1)[-1] for item in matched}
        absent = sorted(expected - observed)
        bad = [item for item in matched if item["status"] in {"fail", "error"} or (item["status"] == "skip" and item["test_id"].rsplit(".", 1)[-1] not in allowed)]
        disposition = "pass" if matched and not absent and not bad else ("not_run" if absent else "fail")
        evaluation_results.append({**evaluation, "raw_outcomes": matched, "absent_tests": absent, "disposition": disposition})
    allowed_skips = sorted(item["test_id"] for item in raw if item["status"] == "skip" and item["test_id"].rsplit(".", 1)[-1] in allowed)
    unallowed_skips = sorted(item["test_id"] for item in raw if item["status"] == "skip" and item["test_id"].rsplit(".", 1)[-1] not in allowed)
    gaps = any(e["disposition"] != "pass" for e in evaluation_results)
    hard_failure = bool(metadata_gaps or unallowed_skips or any(item["status"] in {"fail", "error"} for item in raw))
    gate_passed = not hard_failure and (sandbox_safe or not gaps)
    return {"gate_passed": gate_passed, "evaluations": evaluation_results, "metadata_gaps": metadata_gaps,
            "allowed_skips": allowed_skips, "unallowed_skips": unallowed_skips,
            "mapped_outcome_count": len(mapped_ids), "total_outcome_count": len(raw)}

def disposition(assessment):
    if not assessment["gate_passed"]:
        return "fail"
    if any(e["disposition"] == "not_run" for e in assessment["evaluations"]):
        return "pass_with_environment_gaps"
    return "pass"

def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def source_sha256():
    digest = hashlib.sha256()
    files = sorted([*ROOT.glob("src/**/*.py"), *ROOT.glob("tests/test_*.py"), ROOT / "scripts/run_adversarial_eval.py"])
    for path in files:
        digest.update(path.relative_to(ROOT).as_posix().encode()); digest.update(b"\0"); digest.update(path.read_bytes()); digest.update(b"\0")
    return digest.hexdigest()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="evals/results/adversarial-results.json")
    parser.add_argument("--sandbox-safe", action="store_true", help="Exclude tests whose class name contains Socket")
    args = parser.parse_args()
    catalog = json.loads((ROOT / "evals/adversarial_catalog.json").read_text())
    discovered = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern="test_*.py")
    tests = [t for t in flatten(discovered) if t.id().split(".", 1)[0] not in EVIDENCE_STATE_MODULES]
    if args.sandbox_safe:
        tests = [t for t in tests if "Socket" not in t.id() and "TransportIntegrationTests" not in t.id()]
    suite = unittest.TestSuite(tests)
    runner = unittest.TextTestRunner(stream=sys.stderr, verbosity=1, resultclass=RecordingResult)
    started = time.time(); result = runner.run(suite)
    counts = {s: sum(1 for x in result.raw if x["status"] == s) for s in ("pass", "fail", "error", "skip")}
    assessment = assess(result.raw, catalog, args.sandbox_safe)
    payload = {
        "schema_version": 1,
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "environment": {"python": platform.python_version(), "implementation": platform.python_implementation(), "os": platform.system(), "machine": platform.machine(), "sandbox_safe": args.sandbox_safe},
        "catalog_schema_version": catalog["schema_version"],
        "excluded_test_modules": list(EVIDENCE_STATE_MODULES),
        "catalog_sha256": sha256(ROOT / "evals/adversarial_catalog.json"),
        "source_sha256": source_sha256(),
        "threshold": catalog["threshold"],
        "raw_outcomes": result.raw,
        "evaluations": assessment["evaluations"],
        "mapping": {key: assessment[key] for key in ("metadata_gaps", "allowed_skips", "unallowed_skips", "mapped_outcome_count", "total_outcome_count")},
        "summary": {**counts, "total": len(result.raw), "seconds": round(time.time()-started, 6), "disposition": disposition(assessment)},
    }
    destination = ROOT / args.output
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(destination)
    return 0 if result.wasSuccessful() and assessment["gate_passed"] else 1

if __name__ == "__main__": raise SystemExit(main())
