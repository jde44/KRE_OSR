#!/usr/bin/env python3
"""Synthetic localhost-only fake-provider demo."""

import json
from pathlib import Path
import sys
import threading
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
if not sys.pycache_prefix:  # never write bytecode caches into the candidate tree
    import tempfile
    sys.pycache_prefix = tempfile.mkdtemp(prefix="osr-pycache-")
sys.path.insert(0, str(ROOT / "src"))

from open_sovereign_router.approvals import ApprovalVerifier
from open_sovereign_router.audit_sink import MemoryAuditSink
from open_sovereign_router.models import Capability, Model, Provider
from open_sovereign_router.policy import PolicyEngine
from open_sovereign_router.providers import FakeProvider
from open_sovereign_router.registry import Registry
from open_sovereign_router.transport import Identity, IdentityRegistry, RouterService, build_server


def build_demo():
    provider = Provider("local-demo", "local", "http://127.0.0.1:8081", frozenset({"127.0.0.1"}), True)
    model = Model("local-demo-model", "local-demo", Capability.BASIC, 0, True)
    registry = Registry.build([provider], [model], "demo-v1")
    policy = PolicyEngine(registry, ApprovalVerifier(b"demo-only-fixed-secret-32-bytes!!"), "demo-v1")
    fake = FakeProvider("SYNTHETIC_FAKE_PROVIDER_OK")
    audit = MemoryAuditSink()
    service = RouterService(policy, IdentityRegistry({"demo-local-key": Identity("demo-actor", "public")}), {"local-demo": fake}, audit)
    return service, fake, audit


def run_demo():
    service, fake, audit = build_demo()
    server = build_server(service, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        payload = json.dumps({"model": "local-demo-model", "messages": [{"role": "user", "content": "synthetic demo"}], "max_tokens": 16}).encode()
        request = Request(f"http://127.0.0.1:{port}/v1/chat/completions", payload, {"Content-Type": "application/json", "X-OSR-API-Key": "demo-local-key"})
        with urlopen(request, timeout=5) as response:
            result = json.load(response)
        summary = {"status": "pass", "localhost_only": True, "provider": "FakeProvider", "provider_calls": fake.calls, "audit_events": len(audit.events), "model": result["model"], "content": result["choices"][0]["message"]["content"]}
        print(json.dumps(summary, sort_keys=True))
        return summary
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    outcome = run_demo()
    raise SystemExit(0 if outcome["status"] == "pass" else 1)
