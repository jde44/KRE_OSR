"""Transport regressions: two-phase approval, audit completeness, provider integrity, strict parsing and socket hardening."""

import contextlib
import http.client
import io
import json
from pathlib import Path
import socket
import sys
import threading
import time
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from open_sovereign_router.approvals import BINDING_FIELDS, ApprovalEnvelope, ApprovalVerifier, issue_approval
from open_sovereign_router.audit_sink import AuditFailure, MemoryAuditSink
from open_sovereign_router.models import Capability, Model, Provider
from open_sovereign_router.policy import PolicyEngine
from open_sovereign_router.providers import FakeProvider, ProviderResult
from open_sovereign_router.registry import Registry
from open_sovereign_router.transport import Identity, IdentityRegistry, Limits, RouterService, build_server


SECRET = b"s" * 32
MSG = {"messages": [{"role": "user", "content": "hello"}]}
LOCAL = Provider("local", "local", "http://127.0.0.1:8081", frozenset({"127.0.0.1"}))
CLOUD = Provider("cloud", "cloud", "https://api.example.com:443", frozenset({"api.example.com"}))


class Clock:
    def __init__(self, start=1_800_000_000.0):
        self.now = start

    def __call__(self):
        return self.now


class FailNthSink(MemoryAuditSink):
    """Accepts the first n-1 events, then fails."""

    def __init__(self, fail_at):
        super().__init__()
        self.fail_at = fail_at
        self.attempts = 0

    def append(self, event):
        self.attempts += 1
        if self.attempts >= self.fail_at:
            raise AuditFailure("audit unavailable")
        self.events.append(event)


def make(providers=(LOCAL,), models=None, sensitivity="internal", provider=None, audit=None, limits=None, clock=None, identities=None, monotonic=None):
    models = models or [Model("tiny", "local", Capability.BASIC, 0)]
    registry = Registry.build(list(providers), list(models), version="registry-v1")
    policy = PolicyEngine(registry, ApprovalVerifier(SECRET), "policy-v1")
    fake = provider or FakeProvider()
    sink = audit if audit is not None else MemoryAuditSink()
    ids = identities or {"test-key": Identity("actor-1", sensitivity)}
    clock = clock or Clock()
    service = RouterService(policy, IdentityRegistry(ids), {p.provider_id: fake for p in providers}, sink, limits, clock=clock, monotonic=monotonic or clock)
    return service, fake, sink


def cloud_service(**kwargs):
    return make(providers=(CLOUD,), models=[Model("frontier", "cloud", Capability.BASIC, 0)], sensitivity="public", **kwargs)


def approve(pending, issued_at, nonce="nonce-0000001", ttl=120):
    bindings = pending["bindings"]
    return issue_approval(SECRET, ApprovalEnvelope(**bindings, issued_at=issued_at, expires_at=issued_at + ttl, nonce=nonce))


class TwoPhaseCloudApprovalTests(unittest.TestCase):
    """F1: the cloud approval path must be satisfiable over the transport, exactly once."""

    def phase_one(self, service):
        status, payload = service.chat("test-key", None, MSG)
        self.assertEqual(status, 409)
        self.assertEqual(payload["error"]["type"], "approval_required")
        pending = payload["approval_request"]
        self.assertEqual(set(pending["bindings"]), set(BINDING_FIELDS))
        self.assertEqual(pending["request_id"], pending["bindings"]["request_id"])
        self.assertEqual(pending["request_id"], payload["request_id"])
        self.assertNotIn("hello", json.dumps(payload))
        return pending

    def test_approve_then_execute_once(self):
        clock = Clock()
        service, fake, audit = cloud_service(clock=clock)
        pending = self.phase_one(service)
        token = approve(pending, int(clock()))
        status, payload = service.chat("test-key", token, MSG, pending["request_id"])
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["osr_routing"]["approval_verified"])
        self.assertEqual(payload["model"], "frontier")
        self.assertEqual(fake.calls, 1)
        status, payload = service.chat("test-key", token, MSG, pending["request_id"])
        self.assertEqual((status, payload["error"]["type"]), (409, "invalid_approval"))
        self.assertEqual(fake.calls, 1)

    def test_consumed_request_cannot_be_reapproved_with_new_nonce(self):
        clock = Clock()
        service, fake, _ = cloud_service(clock=clock)
        pending = self.phase_one(service)
        self.assertEqual(service.chat("test-key", approve(pending, int(clock())), MSG, pending["request_id"])[0], 200)
        second = approve(pending, int(clock()), nonce="nonce-0000002")
        self.assertEqual(service.chat("test-key", second, MSG, pending["request_id"])[0], 409)
        self.assertEqual(fake.calls, 1)

    def test_pending_request_expires(self):
        clock = Clock()
        service, fake, _ = cloud_service(clock=clock, limits=Limits(pending_approval_ttl_seconds=60))
        pending = self.phase_one(service)
        clock.now += 61
        token = approve(pending, int(clock()))
        status, payload = service.chat("test-key", token, MSG, pending["request_id"])
        self.assertEqual((status, payload["error"]["type"]), (409, "invalid_approval"))
        self.assertEqual(fake.calls, 0)

    def test_payload_change_between_phases_is_rejected(self):
        clock = Clock()
        service, fake, _ = cloud_service(clock=clock)
        pending = self.phase_one(service)
        token = approve(pending, int(clock()))
        changed = {"messages": [{"role": "user", "content": "something else"}]}
        self.assertEqual(service.chat("test-key", token, changed, pending["request_id"])[0], 409)
        self.assertEqual(fake.calls, 0)

    def test_other_actor_cannot_use_pending_request(self):
        clock = Clock()
        ids = {"test-key": Identity("actor-1", "public"), "other-key": Identity("actor-2", "public")}
        service, fake, _ = cloud_service(clock=clock, identities=ids)
        pending = self.phase_one(service)
        token = approve(pending, int(clock()))
        self.assertEqual(service.chat("other-key", token, MSG, pending["request_id"])[0], 409)
        self.assertEqual(fake.calls, 0)

    def test_request_reference_and_token_must_be_paired(self):
        clock = Clock()
        service, fake, _ = cloud_service(clock=clock)
        pending = self.phase_one(service)
        status, payload = service.chat("test-key", None, MSG, pending["request_id"])
        self.assertEqual((status, payload["error"]["type"], payload["error"]["message"]), (409, "invalid_approval", "invalid approval"))
        status, payload = service.chat("test-key", approve(pending, int(clock())), MSG)
        self.assertEqual((status, payload["error"]["type"]), (409, "invalid_approval"))
        for bad in ("../x", "A" * 200, 7):
            status, payload = service.chat("test-key", "t.t", MSG, bad)
            self.assertEqual((status, payload["error"]["message"]), (409, "invalid approval"))
        status, payload = service.chat("test-key", "x" * 9000, MSG)
        self.assertEqual((status, payload["error"]["message"]), (409, "invalid approval"))
        self.assertEqual(fake.calls, 0)

    def test_pending_store_is_bounded(self):
        service, _, _ = cloud_service(limits=Limits(max_pending_approvals=2))
        self.assertEqual(service.chat("test-key", None, MSG)[0], 409)
        self.assertEqual(service.chat("test-key", None, MSG)[0], 409)
        status, payload = service.chat("test-key", None, MSG)
        self.assertEqual((status, payload["error"]["type"]), (429, "rate_limit_error"))

    def test_expired_pending_entries_free_capacity(self):
        clock = Clock()
        service, _, _ = cloud_service(clock=clock, limits=Limits(max_pending_approvals=1, pending_approval_ttl_seconds=10))
        self.assertEqual(service.chat("test-key", None, MSG)[0], 409)
        clock.now += 11
        self.assertEqual(service.chat("test-key", None, MSG)[0], 409)

    def test_approval_failure_detail_is_not_echoed_but_is_audited(self):
        clock = Clock()
        service, _, audit = cloud_service(clock=clock)
        pending = self.phase_one(service)
        token = approve(pending, int(clock()))
        changed = {"messages": [{"role": "user", "content": "other"}]}
        status, payload = service.chat("test-key", token, changed, pending["request_id"])
        self.assertEqual(payload["error"]["message"], "invalid approval")
        self.assertIn("mismatch", audit.events[-1].detail)
        self.assertEqual(audit.events[-1].reason_code, "invalid_approval")


class AuditCompletenessTests(unittest.TestCase):
    """F5: every policy decision and every post-selection outcome is audited, fail-closed."""

    def test_blocked_decisions_are_audited(self):
        service, _, audit = cloud_service()
        service.chat("test-key", None, MSG)
        self.assertEqual([(e.phase, e.status, e.reason_code) for e in audit.events], [("decision", "blocked", "approval_required")])
        service, _, audit = make(providers=(CLOUD,), models=[Model("frontier", "cloud", Capability.BASIC, 0)], sensitivity="restricted")
        status, payload = service.chat("test-key", None, MSG)
        self.assertEqual(payload["error"]["type"], "sensitive_local_unavailable")
        self.assertEqual([(e.status, e.reason_code) for e in audit.events], [("blocked", "sensitive_local_unavailable")])

    def test_success_and_failure_outcomes_are_audited(self):
        service, _, audit = make()
        self.assertEqual(service.chat("test-key", None, MSG)[0], 200)
        self.assertEqual([(e.phase, e.outcome) for e in audit.events], [("decision", None), ("outcome", "completed")])
        service, _, audit = make(provider=FakeProvider(failure=True))
        self.assertEqual(service.chat("test-key", None, MSG)[0], 503)
        self.assertEqual([(e.phase, e.outcome) for e in audit.events], [("decision", None), ("outcome", "provider_error")])
        for event in audit.events:
            self.assertNotIn("hello", json.dumps(event.to_dict()))

    def test_blocked_decision_audit_failure_fails_closed(self):
        service, _, _ = cloud_service(audit=MemoryAuditSink(fail=True))
        status, payload = service.chat("test-key", None, MSG)
        self.assertEqual((status, payload["error"]["type"]), (503, "audit_unavailable"))
        self.assertNotIn("approval_request", payload)

    def test_outcome_audit_failure_withholds_provider_content(self):
        provider = FakeProvider(content="SENSITIVE_OUTPUT")
        service, _, _ = make(provider=provider, audit=FailNthSink(fail_at=2))
        status, payload = service.chat("test-key", None, MSG)
        self.assertEqual((status, payload["error"]["type"]), (503, "audit_unavailable"))
        self.assertEqual(provider.calls, 1)
        self.assertNotIn("SENSITIVE_OUTPUT", json.dumps(payload))


class ProviderIntegrityTests(unittest.TestCase):
    def test_provider_model_substitution_is_rejected(self):
        class Swap:
            def complete(self, model_id, messages, max_tokens):
                return ProviderResult("x", "some-other-model")
        service, _, audit = make(provider=Swap())
        status, payload = service.chat("test-key", None, MSG)
        self.assertEqual((status, payload["error"]["type"]), (502, "provider_error"))
        self.assertNotIn("some-other-model", json.dumps(payload))
        self.assertEqual(audit.events[-1].outcome, "model_mismatch")

    def test_unexpected_provider_exception_is_contained(self):
        class Broken:
            def complete(self, model_id, messages, max_tokens):
                raise KeyError("upstream secret detail")
        service, _, audit = make(provider=Broken())
        status, payload = service.chat("test-key", None, MSG)
        self.assertEqual((status, payload["error"]["message"]), (503, "provider unavailable"))
        self.assertNotIn("secret", json.dumps(payload))
        self.assertEqual(audit.events[-1].outcome, "provider_error")

    def test_non_result_provider_return_is_rejected(self):
        class Bad:
            def complete(self, model_id, messages, max_tokens):
                return {"content": "x"}
        service, _, _ = make(provider=Bad())
        self.assertEqual(service.chat("test-key", None, MSG)[0], 502)


class RequestStrictnessTests(unittest.TestCase):
    def test_unsupported_fields_are_rejected(self):
        service, fake, audit = make()
        for extra in ({"tools": []}, {"n": 5}, {"temperature": 0.2}, {"response_format": {}}, {"user": "u"}):
            status, payload = service.chat("test-key", None, {**MSG, **extra})
            self.assertEqual((status, payload["error"]["type"]), (400, "invalid_request_error"), extra)
        self.assertEqual(fake.calls, 0)

    def test_capability_must_be_a_true_integer(self):
        service, fake, _ = make()
        for value in (True, False, "1", 1.0):
            self.assertEqual(service.chat("test-key", None, {**MSG, "required_capability": value})[0], 400, value)
        self.assertEqual(service.chat("test-key", None, {**MSG, "required_capability": 1})[0], 200)


class SocketHardeningTests(unittest.TestCase):
    """F2, F3, I2 and the two-phase flow over a real loopback socket."""

    def start(self, service):
        server = build_server(service)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def post(self, port, body, headers=None, key="test-key"):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        self.addCleanup(conn.close)
        final = {"Content-Type": "application/json", **(headers or {})}
        if key:
            final["X-OSR-API-Key"] = key
        conn.request("POST", "/v1/chat/completions", body=body if isinstance(body, bytes) else json.dumps(body).encode(), headers=final)
        response = conn.getresponse()
        return response.status, json.loads(response.read() or b"{}")

    def raw(self, port, data, wait=3.0):
        sock = socket.create_connection(("127.0.0.1", port), timeout=wait)
        self.addCleanup(sock.close)
        sock.sendall(data)
        chunks = []
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        except (socket.timeout, ConnectionResetError):
            pass
        return b"".join(chunks)

    def test_two_phase_approval_over_http(self):
        clock = Clock()
        service, fake, _ = cloud_service(clock=clock)
        port = self.start(service)
        status, payload = self.post(port, MSG)
        self.assertEqual(status, 409)
        pending = payload["approval_request"]
        token = approve(pending, int(clock()))
        headers = {"X-OSR-Approval": token, "X-OSR-Approval-Request-Id": pending["request_id"]}
        status, payload = self.post(port, MSG, headers)
        self.assertEqual(status, 200, payload)
        self.assertEqual(fake.calls, 1)
        self.assertEqual(self.post(port, MSG, headers)[0], 409)

    def test_unauthenticated_post_is_rejected_before_body_is_read(self):
        service, _, _ = make(limits=Limits(socket_timeout_seconds=5))
        port = self.start(service)
        started = time.monotonic()
        response = self.raw(port, b"POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 100\r\n\r\n")
        self.assertTrue(response.startswith(b"HTTP/1.0 401") or response.startswith(b"HTTP/1.1 401"), response[:40])
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(self.post(port, b"{", key=None)[0], 401)

    def test_nested_and_non_finite_json_get_structured_errors(self):
        service, fake, _ = make()
        port = self.start(service)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status, payload = self.post(port, b"[" * 30000 + b"]" * 30000)
            time.sleep(0.1)
        self.assertEqual((status, payload["error"]["type"]), (400, "invalid_request_error"))
        self.assertNotIn("Traceback", stderr.getvalue())
        self.assertEqual(self.post(port, b'{"messages":[{"role":"user","content":"x"}],"max_tokens":NaN}')[0], 400)
        self.assertEqual(fake.calls, 0)

    def test_idle_connections_time_out(self):
        service, _, _ = make(limits=Limits(socket_timeout_seconds=0.3))
        port = self.start(service)
        started = time.monotonic()
        response = self.raw(port, b"GET /health HTTP/1.1\r\n")
        self.assertLess(time.monotonic() - started, 2.5)
        self.assertFalse(response.startswith(b"HTTP/1.1 200"))
        started = time.monotonic()
        response = self.raw(port, b"POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\nX-OSR-API-Key: test-key\r\nContent-Length: 100\r\n\r\n")
        self.assertLess(time.monotonic() - started, 2.5)
        self.assertIn(b" 408 ", response.split(b"\r\n", 1)[0] + b" ", response[:40])

    def test_connection_cap_rejects_excess_connections(self):
        service, _, _ = make(limits=Limits(max_connections=2, socket_timeout_seconds=5))
        port = self.start(service)
        stalled = []
        for _ in range(2):
            sock = socket.create_connection(("127.0.0.1", port), timeout=5)
            sock.sendall(b"GET /health HTTP/1.1\r\n")
            stalled.append(sock)
        time.sleep(0.2)
        response = self.raw(port, b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nX-OSR-API-Key: test-key\r\n\r\n")
        self.assertIn(b" 503 ", response.split(b"\r\n", 1)[0] + b" ")
        for sock in stalled:
            sock.close()
        deadline = time.monotonic() + 3
        while True:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            try:
                conn.request("GET", "/health", headers={"X-OSR-API-Key": "test-key"})
                if conn.getresponse().status == 200:
                    break
            except (ConnectionError, http.client.HTTPException):
                pass
            finally:
                conn.close()
            self.assertLess(time.monotonic(), deadline, "connection slots were not released")
            time.sleep(0.1)

    def test_non_loopback_host_header_is_rejected(self):
        """DNS-rebinding defence."""
        service, _, _ = make()
        port = self.start(service)
        response = self.raw(port, b"GET /health HTTP/1.1\r\nHost: attacker.example\r\nX-OSR-API-Key: test-key\r\nConnection: close\r\n\r\n")
        self.assertIn(b" 400 ", response.split(b"\r\n", 1)[0] + b" ")
        ok = self.raw(port, f"GET /health HTTP/1.1\r\nHost: localhost:{port}\r\nX-OSR-API-Key: test-key\r\nConnection: close\r\n\r\n".encode())
        self.assertIn(b" 200 ", ok.split(b"\r\n", 1)[0] + b" ")

    def test_duplicate_security_headers_are_rejected(self):
        service, fake, audit = make()
        port = self.start(service)
        cases = [
            b"Host: 127.0.0.1\r\nHost: localhost\r\nX-OSR-API-Key: test-key\r\n",
            b"Host: 127.0.0.1\r\nX-OSR-API-Key: test-key\r\nX-OSR-API-Key: attacker\r\n",
            b"Host: 127.0.0.1\r\nX-OSR-API-Key: test-key\r\nContent-Length: 61\r\nContent-Length: 61\r\n",
            b"Host: 127.0.0.1\r\nX-OSR-API-Key: test-key\r\nX-OSR-Approval: token-one\r\nX-OSR-Approval: token-two\r\nContent-Length: 68\r\n",
            b"Host: 127.0.0.1\r\nX-OSR-API-Key: test-key\r\nX-OSR-Approval-Request-Id: 00000000000000000000000000000000\r\nX-OSR-Approval-Request-Id: 11111111111111111111111111111111\r\nContent-Length: 68\r\n",
            b"Host: 127.0.0.1\r\nX-OSR-API-Key: test-key\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\nContent-Length: 68\r\n",
            b"Host: 127.0.0.1\r\nX-OSR-API-Key: test-key\r\nContent-Length: 68\r\nContent-Length: 12\r\n",
        ]
        body = b'{"messages":[{"role":"user","content":"ordinary synthetic input"}]}'
        for headers in cases:
            raw = b"POST /v1/chat/completions HTTP/1.1\r\n" + headers + b"Connection: close\r\n\r\n" + body
            response = self.raw(port, raw)
            self.assertTrue(b" 400 " in response[:40] or b" 411 " in response[:40], response[:80])
        self.assertEqual(fake.calls, 0)
        self.assertEqual(audit.events, [])



class ApprovalStoreHardeningTests(unittest.TestCase):
    """Pending-store quotas, max_tokens binding, audit of rejections, owner-only claims, monotonic expiry, exactly-once execution."""

    def test_bindings_match_an_independently_computed_expectation(self):
        import hashlib
        clock = Clock()
        service, _, _ = cloud_service(clock=clock)
        status, payload = service.chat("test-key", None, {**MSG, "max_tokens": 64})
        pending = payload["approval_request"]
        canonical = json.dumps({"max_tokens": 64, "messages": [{"content": "hello", "role": "user"}]}, sort_keys=True, separators=(",", ":")).encode()
        expected = {
            "version": 1, "issuer": "open-sovereign-router", "request_id": pending["request_id"], "actor_id": "actor-1",
            "task": "chat_completions", "required_capability": 1, "preferred_provider": None, "preferred_model": None,
            "payload_sha256": hashlib.sha256(canonical).hexdigest(), "sensitivity": "public", "provider_id": "cloud",
            "model_id": "frontier", "policy_version": "policy-v1", "registry_version": "registry-v1",
        }
        self.assertEqual(pending["bindings"], expected)

    def test_max_tokens_change_between_phases_is_rejected(self):
        clock = Clock()
        service, fake, _ = cloud_service(clock=clock)
        pending = service.chat("test-key", None, {**MSG, "max_tokens": 1})[1]["approval_request"]
        token = approve(pending, int(clock()))
        self.assertEqual(service.chat("test-key", token, {**MSG, "max_tokens": 2048}, pending["request_id"])[0], 409)
        self.assertEqual(service.chat("test-key", token, {**MSG, "max_tokens": 1}, pending["request_id"])[0], 200)
        self.assertEqual(fake.calls, 1)

    def test_per_actor_quota_prevents_queue_monopoly(self):
        """one actor cannot exhaust the shared pending store; its own oldest entries are evicted."""
        clock = Clock()
        ids = {"test-key": Identity("actor-1", "public"), "b-key": Identity("actor-b", "public")}
        service, _, audit = cloud_service(clock=clock, identities=ids, limits=Limits(max_pending_approvals=16, max_pending_per_actor=4))
        first = service.chat("b-key", None, MSG)[1]["approval_request"]
        for _ in range(30):
            self.assertEqual(service.chat("b-key", None, MSG)[0], 409)
        self.assertEqual(service.chat("test-key", None, MSG)[0], 409)
        self.assertEqual(service.chat("b-key", approve(first, int(clock())), MSG, first["request_id"])[0], 409)

    def test_queue_full_is_audited_as_such(self):
        """N4a."""
        ids = {"test-key": Identity("actor-1", "public"), "b-key": Identity("actor-b", "public")}
        service, _, audit = cloud_service(identities=ids, limits=Limits(max_pending_approvals=1, max_pending_per_actor=1))
        self.assertEqual(service.chat("test-key", None, MSG)[0], 409)
        status, payload = service.chat("b-key", None, MSG)
        self.assertEqual((status, payload["error"]["type"]), (429, "rate_limit_error"))
        self.assertEqual(audit.events[-1].reason_code, "approval_queue_full")
        self.assertEqual([e.reason_code for e in audit.events].count("approval_required"), 1)

    def test_unexpected_sink_exception_fails_closed_as_audit_unavailable(self):
        """N4b."""
        class Exploding:
            def append(self, event):
                raise RuntimeError("disk on fire")
        service, fake, _ = make(audit=Exploding())
        status, payload = service.chat("test-key", None, MSG)
        self.assertEqual((status, payload["error"]["type"], fake.calls), (503, "audit_unavailable", 0))

    def test_header_level_approval_rejections_are_audited(self):
        """N4c."""
        service, _, audit = cloud_service()
        service.chat("test-key", "x" * 9000, MSG)
        service.chat("test-key", "t.t", MSG, "not-an-id")
        self.assertEqual([e.reason_code for e in audit.events], ["invalid_approval", "invalid_approval"])

    def test_other_actor_cannot_disturb_a_pending_request(self):
        """a foreign attempt never removes the owner's entry, even transiently."""
        clock = Clock()
        ids = {"test-key": Identity("actor-1", "public"), "other-key": Identity("actor-2", "public")}
        service, fake, _ = cloud_service(clock=clock, identities=ids)
        pending = service.chat("test-key", None, MSG)[1]["approval_request"]
        token = approve(pending, int(clock()))
        stop = threading.Event()
        def hammer():
            while not stop.is_set():
                service.chat("other-key", token, MSG, pending["request_id"])
        threads = [threading.Thread(target=hammer) for _ in range(3)]
        for thread in threads:
            thread.start()
        try:
            time.sleep(0.05)
            self.assertEqual(service.chat("test-key", token, MSG, pending["request_id"])[0], 200)
        finally:
            stop.set()
            for thread in threads:
                thread.join(2)
        self.assertEqual(fake.calls, 1)

    def test_pending_expiry_uses_monotonic_clock(self):
        """a backward wall-clock step does not extend a pending request."""
        wall, mono = Clock(), Clock(start=1000.0)
        service, fake, _ = cloud_service(clock=wall, monotonic=mono, limits=Limits(pending_approval_ttl_seconds=60))
        pending = service.chat("test-key", None, MSG)[1]["approval_request"]
        mono.now += 61
        wall.now -= 1000
        self.assertEqual(service.chat("test-key", approve(pending, int(wall())), MSG, pending["request_id"])[0], 409)
        self.assertEqual(fake.calls, 0)

    def test_concurrent_resubmissions_execute_exactly_once(self):
        clock = Clock()
        service, fake, _ = cloud_service(clock=clock, limits=Limits(max_concurrency=32))
        pending = service.chat("test-key", None, MSG)[1]["approval_request"]
        tokens = [approve(pending, int(clock()), nonce=f"nonce-{i:08d}") for i in range(16)]
        results, barrier = [], threading.Barrier(16)
        def go(token):
            barrier.wait()
            results.append(service.chat("test-key", token, MSG, pending["request_id"])[0])
        threads = [threading.Thread(target=go, args=(token,)) for token in tokens]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        self.assertEqual(sorted(results), [200] + [409] * 15)
        self.assertEqual(fake.calls, 1)


class SocketDeadlineAndParsingTests(unittest.TestCase):
    """N1 (total read deadline), N6 (strict header parsing) and IPv6 loopback bind."""

    start = SocketHardeningTests.start
    raw = SocketHardeningTests.raw

    @staticmethod
    def _server_closed(sock):
        """Non-blocking probe: True once the peer has closed (EOF or reset)."""
        sock.setblocking(False)
        try:
            return sock.recv(4096) == b""
        except BlockingIOError:
            return False
        except OSError:
            return True
        finally:
            sock.setblocking(True)
            sock.settimeout(5)

    def _drip(self, port, first, stop, closed):
        """Drips one byte at a time; records whether the SERVER closed the connection.

        A send can still succeed after the server shut the socket down (kernel buffering), so after
        dripping stops, a bounded read decides deterministically: EOF or a reset means server-closed.
        """
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            try:
                sock.sendall(first)
                while not stop.is_set():
                    time.sleep(0.25)
                    sock.sendall(b"X")
                    if self._server_closed(sock):
                        closed.append(True)
                        return
            except OSError:
                closed.append(True)
                return
            sock.settimeout(3)
            try:
                while True:
                    data = sock.recv(4096)
                    if not data:
                        closed.append(True)
                        return
            except socket.timeout:
                return
            except OSError:
                closed.append(True)
        finally:
            sock.close()

    def _wait_for_health(self, port, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            try:
                conn.request("GET", "/health", headers={"X-OSR-API-Key": "test-key"})
                if conn.getresponse().status == 200:
                    return True
            except (OSError, http.client.HTTPException):
                pass
            finally:
                conn.close()
            time.sleep(0.1)
        return False

    def test_header_drip_cannot_hold_slots_past_read_deadline(self):
        service, _, _ = make(limits=Limits(max_connections=2, socket_timeout_seconds=1.0, read_deadline_seconds=1.5))
        port = self.start(service)
        stop, closed = threading.Event(), []
        drips = [threading.Thread(target=self._drip, args=(port, b"GET /health HTTP/1.1\r\nX-Pad: ", stop, closed)) for _ in range(2)]
        for thread in drips:
            thread.start()
        try:
            time.sleep(0.3)
            self.assertTrue(self._wait_for_health(port, 4.0), "drip connections held the cap past the read deadline")
        finally:
            stop.set()
            for thread in drips:
                thread.join(3)
        self.assertEqual(len(closed), 2)

    def test_authenticated_body_drip_is_cut_at_read_deadline(self):
        service, _, _ = make(limits=Limits(socket_timeout_seconds=1.0, read_deadline_seconds=1.5))
        port = self.start(service)
        stop, closed = threading.Event(), []
        head = b"POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\nX-OSR-API-Key: test-key\r\nContent-Length: 1000\r\n\r\n"
        started = time.monotonic()
        thread = threading.Thread(target=self._drip, args=(port, head, stop, closed))
        thread.start()
        thread.join(4.0)
        stop.set()
        thread.join(1)
        self.assertEqual(closed, [True])
        self.assertLess(time.monotonic() - started, 4.0)

    def test_strict_content_length_and_host_port(self):
        service, _, _ = make()
        port = self.start(service)
        body = b'{"messages":[]}'
        for value in (b"+15", b"1_5", b"0x0f", b"-15", b"15.0"):  # surrounding OWS is legal (RFC 9110) and stripped by the parser
            response = self.raw(port, b"POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\nX-OSR-API-Key: test-key\r\nContent-Length: " + value + b"\r\n\r\n" + body)
            self.assertIn(b" 411 ", response.split(b"\r\n", 1)[0] + b" ", value)
        for host in ("localhost:", "127.0.0.1:\u00b2", "127.0.0.1:70000", "127.0.0.1:0"):
            response = self.raw(port, b"GET /health HTTP/1.1\r\nHost: " + host.encode() + b"\r\nX-OSR-API-Key: test-key\r\n\r\n")
            self.assertIn(b" 400 ", response.split(b"\r\n", 1)[0] + b" ", host)

    def test_ipv6_loopback_bind(self):
        if not socket.has_ipv6:
            self.skipTest("IPv6 unavailable")
        service, _, _ = make()
        try:
            server = build_server(service, "::1")
        except OSError as exc:
            self.skipTest(f"IPv6 loopback unavailable: {exc.errno}")
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        conn = http.client.HTTPConnection("::1", server.server_address[1], timeout=3)
        self.addCleanup(conn.close)
        conn.request("GET", "/health", headers={"X-OSR-API-Key": "test-key"})
        self.assertEqual(conn.getresponse().status, 200)



class PendingStoreInvariantTests(unittest.TestCase):
    """Pending-store invariants: insertion-ordered eviction, capped restore, visible output budget."""

    def test_eviction_is_strictly_insertion_ordered_under_tied_clock(self):
        """the frozen clock makes every expiry tie; the oldest entry must still be evicted first, every time."""
        from open_sovereign_router.transport import PendingApprovals
        for _ in range(50):
            store = PendingApprovals(300, 100, 2, lambda: 5.0)
            ids = [f"{i:032x}" for i in (3, 1, 2)]  # insertion order differs from lexical order
            for request_id in ids:
                self.assertTrue(store.create(request_id, "actor", "d" * 64))
            self.assertIsNone(store.claim(ids[0], "actor", "d" * 64))
            self.assertIsNotNone(store.claim(ids[1], "actor", "d" * 64))
            self.assertIsNotNone(store.claim(ids[2], "actor", "d" * 64))

    def test_restore_never_exceeds_caps(self):
        from open_sovereign_router.transport import PendingApprovals
        store = PendingApprovals(300, 100, 2, lambda: 5.0)
        store.create("a" * 32, "actor", "d" * 64)
        store.create("b" * 32, "actor", "d" * 64)
        claimed = store.claim("a" * 32, "actor", "d" * 64)
        store.create("c" * 32, "actor", "d" * 64)
        store.restore("a" * 32, claimed)
        self.assertEqual(store.count("actor"), 2)

    def test_approver_sees_requested_output_budget(self):
        service, _, _ = cloud_service()
        pending = service.chat("test-key", None, {**MSG, "max_tokens": 77})[1]["approval_request"]
        self.assertEqual(pending["max_tokens"], 77)


if __name__ == "__main__":
    unittest.main()
