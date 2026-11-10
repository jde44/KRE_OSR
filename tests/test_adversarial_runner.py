import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("adversarial_runner", ROOT / "scripts/run_adversarial_eval.py")
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


def catalog(tests=("test_one",), allowed=()):
    return {
        "allowed_capability_skips": list(allowed),
        "evaluations": [{"id":"E1","purpose":"p","threshold":"t","owner":"o","due_point":"d","evidence":"e","remediation":"r","tests":list(tests)}],
    }


class RunnerGateTests(unittest.TestCase):
    def test_full_gate_rejects_absent_mapping(self):
        assessment = runner.assess([], catalog(), sandbox_safe=False)
        self.assertFalse(assessment["gate_passed"])

    def test_full_gate_rejects_unallowlisted_skip(self):
        raw = [{"test_id":"m.C.test_one","status":"skip","seconds":0,"detail":"x"}]
        self.assertFalse(runner.assess(raw, catalog(), sandbox_safe=False)["gate_passed"])

    def test_full_gate_allows_scoped_capability_skip_and_reports_it(self):
        raw = [{"test_id":"m.C.test_one","status":"skip","seconds":0,"detail":"IPv6 unavailable"}]
        result = runner.assess(raw, catalog(allowed=("test_one",)), sandbox_safe=False)
        self.assertTrue(result["gate_passed"])
        self.assertEqual(result["allowed_skips"], ["m.C.test_one"])

    def test_full_gate_rejects_catalog_metadata_gap(self):
        bad = catalog(); del bad["evaluations"][0]["owner"]
        raw = [{"test_id":"m.C.test_one","status":"pass","seconds":0,"detail":""}]
        self.assertFalse(runner.assess(raw, bad, sandbox_safe=False)["gate_passed"])

    def test_counts_distinguish_mapped_and_total(self):
        raw = [{"test_id":"m.C.test_one","status":"pass","seconds":0,"detail":""}, {"test_id":"m.C.unmapped","status":"pass","seconds":0,"detail":""}]
        result = runner.assess(raw, catalog(), sandbox_safe=False)
        self.assertEqual((result["mapped_outcome_count"], result["total_outcome_count"]), (1, 2))


if __name__ == "__main__": unittest.main()
