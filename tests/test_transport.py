import http.client
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from open_sovereign_router.approvals import ApprovalVerifier
from open_sovereign_router.audit import AuditEvent
from open_sovereign_router.audit_sink import FileAuditSink, MemoryAuditSink
from open_sovereign_router.models import Capability, Model, Provider
from open_sovereign_router.policy import PolicyEngine
from open_sovereign_router.providers import FakeProvider, ProviderResult
from open_sovereign_router.registry import Registry
from open_sovereign_router.transport import Identity, IdentityRegistry, Limits, RouterService, build_server


SECRET = b"s" * 32


def make_service(provider=None, audit=None, limits=None):
    registry = Registry.build(
        [Provider("local", "local", "http://127.0.0.1:8081", frozenset({"127.0.0.1"}))],
        [Model("tiny", "local", Capability.BASIC, 0)],
        version="registry-v1",
    )
    policy = PolicyEngine(registry, ApprovalVerifier(SECRET), "policy-v1")
    fake = provider or FakeProvider()
    sink = audit or MemoryAuditSink()
    service = RouterService(policy, IdentityRegistry({"test-key": Identity("actor-1", "internal")}), {"local": fake}, sink, limits)
    return service, fake, sink


class LocalServerMixin:
    def start_server(self, service):
        server = build_server(service)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def request(self, port, method, path, body=None, key="test-key", headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        self.addCleanup(conn.close)
        final = dict(headers or {})
        if key is not None:
            final["X-OSR-API-Key"] = key
        raw = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        if raw is not None:
            final["Content-Type"] = "application/json"
        conn.request(method, path, body=raw, headers=final)
        response = conn.getresponse()
        return response.status, json.loads(response.read())


class TransportIntegrationTests(LocalServerMixin, unittest.TestCase):
    def test_health_models_and_chat_require_auth_and_do_not_leak_key(self):
        service, fake, audit = make_service()
        port = self.start_server(service)
        for path in ("/health", "/v1/models"):
            self.assertEqual(self.request(port, "GET", path, key=None)[0], 401)
        status, health = self.request(port, "GET", "/health")
        self.assertEqual(status, 200)
        self.assertNotIn("test-key", json.dumps(health))
        status, models = self.request(port, "GET", "/v1/models")
        self.assertEqual(status, 200)
        self.assertNotIn("test-key", json.dumps(models))
        status, payload = self.request(port, "POST", "/v1/chat/completions", {"model": "tiny", "messages": [{"role": "user", "content": "hello"}]})
        self.assertEqual(status, 200)
        self.assertEqual(payload["choices"][0]["message"]["content"], "FAKE_OK")
        self.assertEqual(fake.calls, 1)
        self.assertEqual([(e.phase, e.outcome) for e in audit.events], [("decision", None), ("outcome", "completed")])  # decision + outcome events

    def test_actor_and_sensitivity_spoofing_are_rejected(self):
        service, fake, _ = make_service()
        port = self.start_server(service)
        for field in ("actor_id", "sensitivity"):
            body = {"messages": [{"role": "user", "content": "hello"}], field: "public"}
            status, payload = self.request(port, "POST", "/v1/chat/completions", body)
            self.assertEqual(status, 400)
            self.assertEqual(payload["error"]["type"], "invalid_request_error")
        self.assertEqual(fake.calls, 0)

    def test_malformed_oversized_streaming_and_model_override(self):
        service, fake, _ = make_service(limits=Limits(max_body_bytes=120))
        port = self.start_server(service)
        self.assertEqual(self.request(port, "POST", "/v1/chat/completions", b"{")[0], 400)
        self.assertEqual(self.request(port, "POST", "/v1/chat/completions", {"messages": [{"role": "user", "content": "x" * 200}]})[0], 413)
        service2, _, _ = make_service()
        port2 = self.start_server(service2)
        base = {"messages": [{"role": "user", "content": "hello"}]}
        self.assertEqual(self.request(port2, "POST", "/v1/chat/completions", {**base, "stream": True})[0], 400)
        status, payload = self.request(port2, "POST", "/v1/chat/completions", {**base, "model": "unlisted"})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["type"], "unknown_model")

    def test_audit_failure_blocks_provider_and_errors_are_structured(self):
        service, fake, _ = make_service(audit=MemoryAuditSink(fail=True))
        port = self.start_server(service)
        status, payload = self.request(port, "POST", "/v1/chat/completions", {"messages": [{"role": "user", "content": "private prompt"}]})
        self.assertEqual(status, 503)
        self.assertEqual(payload["error"]["type"], "audit_unavailable")
        self.assertEqual(fake.calls, 0)
        self.assertNotIn("private prompt", json.dumps(payload))

    def test_provider_error_is_bounded_and_redacted(self):
        service, _, _ = make_service(provider=FakeProvider(failure=True))
        port = self.start_server(service)
        status, payload = self.request(port, "POST", "/v1/chat/completions", {"messages": [{"role": "user", "content": "secret-text"}]})
        self.assertEqual(status, 503)
        self.assertEqual(payload["error"]["message"], "provider unavailable")
        self.assertNotIn("secret-text", json.dumps(payload))

    def test_non_loopback_bind_is_rejected(self):
        service, _, _ = make_service()
        with self.assertRaises(ValueError):
            build_server(service, "0.0.0.0")


class BlockingProvider:
    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()
        self.calls = 0
    def complete(self, model_id, messages, max_tokens):
        self.calls += 1
        self.entered.set()
        self.release.wait(2)
        return ProviderResult("OK", model_id)


class ServiceControlTests(unittest.TestCase):
    def test_service_auth_health_models_and_chat(self):
        service, fake, audit = make_service()
        self.assertEqual(service.health(None)[0], 401)
        self.assertEqual(service.models("wrong")[0], 401)
        self.assertEqual(service.health("test-key")[0], 200)
        self.assertEqual(service.models("test-key")[0], 200)
        status, payload = service.chat("test-key", None, {"model": "tiny", "messages": [{"role": "user", "content": "hello"}]})
        self.assertEqual(status, 200)
        self.assertEqual(fake.calls, 1)
        self.assertEqual([(e.phase, e.outcome) for e in audit.events], [("decision", None), ("outcome", "completed")])  # decision + outcome events
        self.assertNotIn("hello", json.dumps(audit.events[0].to_dict()))

    def test_service_rejects_spoof_stream_bad_model_and_oversized_message(self):
        service, fake, _ = make_service(limits=Limits(max_message_chars=5))
        base = {"messages": [{"role": "user", "content": "hello"}]}
        for body in ({**base, "actor_id": "other"}, {**base, "sensitivity": "public"}, {**base, "stream": True}, {**base, "model": "missing"}):
            self.assertEqual(service.chat("test-key", None, body)[0], 400)
        self.assertEqual(service.chat("test-key", None, {"messages": [{"role": "user", "content": "toolong"}]})[0], 400)
        self.assertEqual(fake.calls, 0)

    def test_service_audit_failure_is_fail_closed(self):
        service, fake, _ = make_service(audit=MemoryAuditSink(fail=True))
        status, payload = service.chat("test-key", None, {"messages": [{"role": "user", "content": "secret"}]})
        self.assertEqual((status, payload["error"]["type"], fake.calls), (503, "audit_unavailable", 0))
        self.assertNotIn("secret", json.dumps(payload))

    def test_service_provider_failure_is_redacted(self):
        service, _, _ = make_service(provider=FakeProvider(failure=True))
        status, payload = service.chat("test-key", None, {"messages": [{"role": "user", "content": "secret"}]})
        self.assertEqual((status, payload["error"]["message"]), (503, "provider unavailable"))
        self.assertNotIn("secret", json.dumps(payload))

    def test_concurrency_limit_rejects_second_request(self):
        provider = BlockingProvider()
        service, _, _ = make_service(provider=provider, limits=Limits(max_concurrency=1))
        body = {"messages": [{"role": "user", "content": "hello"}]}
        result = []
        thread = threading.Thread(target=lambda: result.append(service.chat("test-key", None, body)))
        thread.start(); self.assertTrue(provider.entered.wait(1))
        try:
            status, payload = service.chat("test-key", None, body)
            self.assertEqual(status, 429)
            self.assertEqual(payload["error"]["type"], "rate_limit_error")
        finally:
            provider.release.set(); thread.join(2)
        self.assertEqual(provider.calls, 1)

    def test_file_audit_sink_is_prompt_free_and_owner_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            sink = FileAuditSink(path)
            event = AuditEvent("r", "a", "2026-11-07T00:00:00Z", "internal", "selected", "local", "tiny", "selected", False)
            sink.append(event)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            text = path.read_text()
            self.assertNotIn("prompt", text)
            self.assertEqual(len(text.splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
