#!/usr/bin/env python3
"""Deterministic labeled routing/economic benchmark; never runs a model."""

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if not sys.pycache_prefix:  # never write bytecode caches into the candidate tree
    import tempfile
    sys.pycache_prefix = tempfile.mkdtemp(prefix="osr-pycache-")
sys.path.insert(0, str(ROOT / "src"))

from open_sovereign_router.approvals import ApprovalEnvelope, ApprovalVerifier, issue_approval
from open_sovereign_router.models import Capability, Model, Provider, RoutingRequest
from open_sovereign_router.policy import PolicyEngine
from open_sovereign_router.registry import Registry


def _policy(data):
    providers = [
        Provider("local", "local", "http://127.0.0.1:8081", frozenset({"127.0.0.1"}), True),
        Provider("cloud", "cloud", "https://api.example.invalid:443", frozenset({"api.example.invalid"}), True),
    ]
    models = [Model(x["model_id"], x["provider_id"], Capability(x["capability"]), x["cost_rank"], True) for x in data["models"]]
    return PolicyEngine(Registry.build(providers, models, "benchmark-v1"), ApprovalVerifier(_SECRET), "benchmark-v1")


_SECRET = b"benchmark-only-fixed-secret-32-bytes"
_NOW = 1_800_000_000
NON_SENSITIVE = {"public", "internal"}


def _decide(policy, task):
    request = RoutingRequest(task["id"], "synthetic-actor", "benchmark", Capability(task["capability"]), hashlib.sha256(task["id"].encode()).hexdigest())
    decision = policy.decide(request, task["sensitivity"], now=_NOW)
    if task.get("approved") and decision.reason_code == "approval_required":
        # Simulates a human approver signing exactly the bindings the router presents (deterministic nonce).
        bindings = policy.approval_bindings(request, decision)
        token = issue_approval(_SECRET, ApprovalEnvelope(**bindings, issued_at=_NOW - 1, expires_at=_NOW + 60, nonce="benchmark-" + task["id"]))
        decision = policy.decide(request, task["sensitivity"], token, now=_NOW)
    return decision


def evaluate(fixture_path):
    fixture_path = Path(fixture_path)
    raw = fixture_path.read_bytes()
    data = json.loads(raw)
    policy = _policy(data)
    outcomes = []
    correct = local = unauthorized_cloud = sensitive_cloud = approved_cloud = 0
    price = data["assumptions"]["prices_usd_per_1m_tokens"]
    comparison, blocked = [], []
    baseline_tokens = routed_tokens = 0
    baseline_cost = routed_cost = 0.0
    for task in data["tasks"]:
        decision = _decide(policy, task)
        selected = decision.status == "selected"
        actual = decision.model_id if selected else decision.reason_code
        correct += actual == task["expected"]
        is_local = selected and decision.provider_id == "local"
        is_cloud = selected and decision.provider_id == "cloud"
        local += is_local
        approved_cloud += is_cloud and decision.approval_verified
        unauthorized_cloud += is_cloud and not decision.approval_verified
        sensitive_cloud += task["sensitivity"] not in NON_SENSITIVE and decision.provider_id == "cloud" and selected
        if task["sensitivity"] in NON_SENSITIVE:
            if selected:
                # Economics compare like with like: only completed non-sensitive work; refused work is never "savings".
                comparison.append(task["id"])
                baseline_tokens += task["baseline_tokens"]
                routed_tokens += task["routed_tokens"]
                baseline_cost += task["baseline_tokens"] * price["cloud-large"] / 1_000_000
                routed_cost += task["routed_tokens"] * (price["local"] if is_local else price["cloud-advanced"]) / 1_000_000
            else:
                blocked.append(task["id"])
        outcomes.append({"id": task["id"], "expected": task["expected"], "actual": actual, "status": decision.status,
                         "provider": decision.provider_id, "approval_verified": decision.approval_verified})
    count = len(data["tasks"])
    metrics = {
        "selection_accuracy": correct / count,
        "unauthorized_cloud_rate": unauthorized_cloud / count,
        "sensitive_leak_rate": sensitive_cloud / count,
        "local_completion_rate": local / count,
        "approved_cloud_routes": approved_cloud,
    }
    economics = {
        "comparison_set": comparison,
        "excluded_blocked": blocked,
        "excluded_sensitive": [t["id"] for t in data["tasks"] if t["sensitivity"] not in NON_SENSITIVE],
        "baseline_tokens_declared": baseline_tokens,
        "routed_tokens_declared": routed_tokens,
        "baseline_cost_usd": round(baseline_cost, 6),
        "routed_cost_usd": round(routed_cost, 6),
        "estimated_cost_difference_usd": round(baseline_cost - routed_cost, 6),
        "note": "Reported, not gated: local price is a disclosed 0 assumption and token budgets are declared fixtures, so a savings threshold could not fail meaningfully.",
    }
    thresholds = data["thresholds"]
    checks = {
        "selection_accuracy": metrics["selection_accuracy"] >= thresholds["selection_accuracy_min"],
        "unauthorized_cloud_rate": metrics["unauthorized_cloud_rate"] <= thresholds["unauthorized_cloud_rate_max"],
        "sensitive_leak_rate": metrics["sensitive_leak_rate"] <= thresholds["sensitive_leak_rate_max"],
        "local_completion_rate": metrics["local_completion_rate"] >= thresholds["local_completion_rate_min"],
    }
    return {
        "schema_version": 2,
        "fixture_sha256": hashlib.sha256(raw).hexdigest(),
        "synthetic": True,
        "executes_model": False,
        "environment": {"python": ">=3.10", "hardware": "policy-only; hardware-independent"},
        "assumptions": data["assumptions"],
        "latency": {"kind": "deterministic_operation_count_proxy", "value": count, "unit": "routing_decisions", "wall_clock_model_latency_measured": False},
        "outcomes": outcomes,
        "metrics": metrics,
        "economics": economics,
        "thresholds": thresholds,
        "checks": checks,
        "disposition": "pass" if all(checks.values()) else "fail",
        "limitations": [
            "No model inference or quality evaluation is performed.",
            "Token counts and prices are disclosed synthetic assumptions, not observed billing.",
            "Cost results exclude hardware, energy, operations and provider-price changes.",
            "The latency proxy is not a performance or end-to-end latency claim."
        ]
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path, default=ROOT / "evals" / "benchmark_tasks.json")
    parser.add_argument("--output", type=Path, default=ROOT / "evals" / "results" / "routing-benchmark.json")
    args = parser.parse_args()
    result = evaluate(args.fixture)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"disposition": result["disposition"], "metrics": result["metrics"]}, sort_keys=True))
    return 0 if result["disposition"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
