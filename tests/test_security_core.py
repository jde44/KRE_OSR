import concurrent.futures
from datetime import datetime, timezone
import inspect
import sys
from dataclasses import fields, replace
from pathlib import Path
from types import MappingProxyType
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from open_sovereign_router.approvals import ApprovalEnvelope, ApprovalError, ApprovalVerifier, issue_approval
from open_sovereign_router.audit import AuditEvent, event_from_decision
from open_sovereign_router.endpoints import UnsafeEndpoint
from open_sovereign_router.models import Capability, Model, Provider, RoutingRequest, Sensitivity
from open_sovereign_router.policy import PolicyEngine, SensitivityClassifier
from open_sovereign_router.registry import Registry


SECRET = b"s" * 32
PAYLOAD_HASH = "a" * 64


def build_registry(local_enabled=True, cloud_enabled=True):
    return Registry.build(
        [
            Provider("local", "local", "http://127.0.0.1:8081", frozenset({"127.0.0.1"}), local_enabled),
            Provider("cloud", "cloud", "https://api.example.invalid:443", frozenset({"api.example.invalid"}), cloud_enabled),
        ],
        [
            Model("tiny", "local", Capability.BASIC, 0),
            Model("small", "local", Capability.STANDARD, 1),
            Model("frontier", "cloud", Capability.ADVANCED, 10),
        ],
        version="registry-v1",
    )


def routing_request(capability=Capability.BASIC, provider=None, model=None, payload_hash=PAYLOAD_HASH):
    return RoutingRequest("req-1", "actor-1", "classify", capability, payload_hash, provider, model)


def envelope(req, **changes):
    base = ApprovalEnvelope(
        version=1,
        issuer="osr-test-issuer",
        request_id=req.request_id,
        actor_id=req.actor_id,
        task=req.task,
        required_capability=int(req.required_capability),
        preferred_provider=req.preferred_provider,
        preferred_model=req.preferred_model,
        payload_sha256=req.payload_sha256,
        sensitivity="public",
        provider_id="cloud",
        model_id="frontier",
        policy_version="policy-v1",
        registry_version="registry-v1",
        issued_at=100,
        expires_at=160,
        nonce="nonce-0001",
    )
    return replace(base, **changes)


class RegistryAndEndpointTests(unittest.TestCase):
    def test_registry_is_defensively_copied_and_immutable(self):
        providers = [Provider("local", "local", "http://127.0.0.1:8081", frozenset({"127.0.0.1"}))]
        models = [Model("tiny", "local", Capability.BASIC, 0)]
        reg = Registry.build(providers, models, version="v1")
        providers.clear(); models.clear()
        self.assertEqual(set(reg.providers), {"local"})
        self.assertIsInstance(reg.providers, MappingProxyType)
        with self.assertRaises(TypeError):
            reg.providers["x"] = reg.providers["local"]

    def test_unknown_model_provider_reference_is_rejected(self):
        with self.assertRaises(ValueError):
            Registry.build([], [Model("m", "missing", Capability.BASIC, 0)], version="v1")

    def test_registry_identifiers_and_version_are_bounded(self):
        valid_provider = Provider("local", "local", "http://127.0.0.1:8081", frozenset({"127.0.0.1"}))
        invalid_cases = [
            ([replace(valid_provider, provider_id="bad id")], [], "v1"),
            ([valid_provider], [Model("bad id", "local", Capability.BASIC, 0)], "v1"),
            ([valid_provider], [], "bad version"),
        ]
        for providers, models, version in invalid_cases:
            with self.subTest(version=version), self.assertRaises(ValueError):
                Registry.build(providers, models, version=version)

    def test_unsafe_and_normalization_edge_endpoints_are_rejected(self):
        unsafe = [
            Provider("p", "cloud", "http://api.example.invalid:80", frozenset({"api.example.invalid"})),
            Provider("p", "cloud", "https://user:pass@api.example.invalid:443", frozenset({"api.example.invalid"})),
            Provider("p", "cloud", "https://evil.invalid:443", frozenset({"api.example.invalid"})),
            Provider("p", "local", "http://192.168.1.2:8080", frozenset({"192.168.1.2"})),
            Provider("p", "cloud", "https://127.0.0.1:443", frozenset({"127.0.0.1"})),
            Provider("p", "cloud", "https://10.0.0.1:443", frozenset({"10.0.0.1"})),
            Provider("p", "cloud", "https://[::1]:443", frozenset({"::1"})),
            Provider("p", "cloud", "https://api.example.invalid.:443", frozenset({"api.example.invalid"})),
            Provider("p", "cloud", "https://api.example.invalid:443/path", frozenset({"api.example.invalid"})),
            Provider("p", "cloud", "https://api.example.invalid:443?x=1", frozenset({"api.example.invalid"})),
        ]
        for provider in unsafe:
            with self.subTest(endpoint=provider.endpoint), self.assertRaises(UnsafeEndpoint):
                Registry.build([provider], [], version="v1")

    def test_global_ipv4_and_ipv6_cloud_literals_are_allowed_when_allowlisted(self):
        providers = [
            Provider("v4", "cloud", "https://8.8.8.8:443", frozenset({"8.8.8.8"})),
            Provider("v6", "cloud", "https://[2606:4700:4700::1111]:443", frozenset({"2606:4700:4700::1111"})),
        ]
        self.assertEqual(len(Registry.build(providers, [], version="v1").providers), 2)


class ApprovalTests(unittest.TestCase):
    def test_secret_strength_at_issuer_and_verifier(self):
        req = routing_request(Capability.ADVANCED)
        with self.assertRaises(ValueError):
            issue_approval(b"short", envelope(req))
        with self.assertRaises(ValueError):
            ApprovalVerifier(b"short")

    def test_expiry_boundary_and_max_ttl(self):
        req = routing_request(Capability.ADVANCED)
        verifier = ApprovalVerifier(SECRET, max_ttl_seconds=120)
        with self.assertRaises(ApprovalError):
            boundary = envelope(req, issued_at=90, expires_at=100)
            verifier.verify_and_consume(issue_approval(SECRET, boundary), boundary.bindings(), now=100)
        with self.assertRaises(ApprovalError):
            verifier.verify_and_consume(issue_approval(SECRET, envelope(req, expires_at=500)), envelope(req, expires_at=500).bindings(), now=100)

    def test_id_nonce_and_hash_bounds(self):
        req = routing_request(Capability.ADVANCED)
        bad = [
            envelope(req, nonce="x"),
            envelope(req, nonce="x" * 129),
            envelope(req, actor_id=""),
            envelope(req, actor_id="x" * 257),
            envelope(req, payload_sha256="not-a-hash"),
        ]
        for item in bad:
            with self.subTest(item=item), self.assertRaises(ValueError):
                issue_approval(SECRET, item)

    def test_field_by_field_tampering_is_rejected(self):
        req = routing_request(Capability.ADVANCED)
        expected = envelope(req)
        mutations = {
            "version": 2, "issuer": "other", "request_id": "other", "actor_id": "other",
            "task": "other", "required_capability": 2, "preferred_provider": "cloud",
            "preferred_model": "other", "payload_sha256": "b" * 64, "sensitivity": "internal",
            "provider_id": "other", "model_id": "other", "policy_version": "other",
            "registry_version": "other",
        }
        for field, value in mutations.items():
            if field == "version":
                with self.subTest(field=field), self.assertRaises(ValueError):
                    issue_approval(SECRET, replace(expected, version=value))
                continue
            tampered_token = issue_approval(SECRET, replace(expected, **{field: value}))
            with self.subTest(field=field), self.assertRaises(ApprovalError):
                ApprovalVerifier(SECRET).verify_and_consume(tampered_token, expected.bindings(), now=110)

    def test_forged_replayed_expired_and_malformed_tokens(self):
        req = routing_request(Capability.ADVANCED)
        expected = envelope(req)
        verifier = ApprovalVerifier(SECRET)
        token = issue_approval(SECRET, expected)
        verifier.verify_and_consume(token, expected.bindings(), now=110)
        with self.assertRaises(ApprovalError): verifier.verify_and_consume(token, expected.bindings(), now=110)
        with self.assertRaises(ApprovalError): ApprovalVerifier(SECRET).verify_and_consume(issue_approval(b"x" * 32, expected), expected.bindings(), now=110)
        expired = replace(expected, expires_at=110, nonce="nonce-expired")
        with self.assertRaises(ApprovalError): ApprovalVerifier(SECRET).verify_and_consume(issue_approval(SECRET, expired), expired.bindings(), now=110)
        with self.assertRaises(ApprovalError): ApprovalVerifier(SECRET).verify_and_consume("bad", expected.bindings(), now=110)

    def test_replay_consume_is_thread_safe(self):
        req = routing_request(Capability.ADVANCED)
        expected = envelope(req)
        verifier = ApprovalVerifier(SECRET)
        token = issue_approval(SECRET, expected)
        def consume():
            try:
                verifier.verify_and_consume(token, expected.bindings(), now=110)
                return True
            except ApprovalError:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda _: consume(), range(24)))
        self.assertEqual(results.count(True), 1)


class PolicyAndAuditTests(unittest.TestCase):
    def engine(self):
        return PolicyEngine(build_registry(), ApprovalVerifier(SECRET), policy_version="policy-v1", approval_issuer="osr-test-issuer")

    def test_malformed_sensitivity_of_all_types_fails_restricted(self):
        classifier = SensitivityClassifier()
        for value in [None, "unknown", "", b"public", 1, [], {}, object()]:
            with self.subTest(value=value):
                self.assertEqual(classifier.classify(value), Sensitivity.RESTRICTED)

    def test_smallest_capable_local_and_routing_edges(self):
        engine = self.engine()
        self.assertEqual(engine.decide(routing_request(), "public").model_id, "tiny")
        self.assertEqual(engine.decide(routing_request(Capability.STANDARD), "internal").model_id, "small")
        self.assertEqual(engine.decide(routing_request(Capability.ADVANCED), "confidential").reason_code, "sensitive_local_unavailable")
        self.assertEqual(engine.decide(routing_request(provider="missing"), "public").reason_code, "unknown_provider")
        self.assertEqual(engine.decide(routing_request(model="missing"), "public").reason_code, "unknown_model")

    def test_internal_cloud_semantics_require_approval(self):
        req = routing_request(Capability.ADVANCED)
        engine = self.engine()
        self.assertEqual(engine.decide(req, "internal", now=110).reason_code, "approval_required")
        approved = envelope(req, sensitivity="internal")
        result = engine.decide(req, "internal", issue_approval(SECRET, approved), now=110)
        self.assertTrue(result.approval_verified)

    def test_payload_hash_and_all_routing_fields_are_bound(self):
        req = routing_request(Capability.ADVANCED)
        token = issue_approval(SECRET, envelope(req))
        changed = replace(req, payload_sha256="b" * 64)
        self.assertEqual(self.engine().decide(changed, "public", token, now=110).reason_code, "invalid_approval")

    def test_no_silent_fallback(self):
        result = self.engine().decide(routing_request(Capability.ADVANCED), "public", now=110)
        self.assertEqual(result.status, "blocked")
        self.assertFalse(result.fallback_permitted)
        self.assertEqual((result.provider_id, result.model_id), ("cloud", "frontier"))

    def test_audit_derives_verified_approval_and_has_no_content_fields(self):
        req = routing_request(Capability.ADVANCED)
        result = self.engine().decide(req, "public", issue_approval(SECRET, envelope(req)), now=110)
        event = event_from_decision(result, clock=lambda: datetime(2026, 11, 7, tzinfo=timezone.utc))
        self.assertTrue(event.approval_verified)
        self.assertEqual(event.actor_id, result.actor_id)
        self.assertNotIn("actor_id", inspect.signature(event_from_decision).parameters)
        names = {field.name for field in fields(AuditEvent)}
        forbidden = {"prompt", "messages", "content", "token", "secret", "endpoint", "headers", "retrieval"}
        self.assertTrue(names.isdisjoint(forbidden))

    def test_audit_actor_cannot_be_substituted_by_caller(self):
        req = routing_request()
        decision = self.engine().decide(req, "public")
        event = event_from_decision(decision, clock=lambda: datetime(2026, 11, 7, tzinfo=timezone.utc))
        self.assertEqual(decision.actor_id, "actor-1")
        self.assertEqual(event.actor_id, "actor-1")
        with self.assertRaises(ValueError):
            event_from_decision(decision, clock=lambda: datetime(2026, 11, 7))


if __name__ == "__main__":
    unittest.main()
