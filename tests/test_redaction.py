import copy
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from open_sovereign_router.approvals import ApprovalEnvelope, ApprovalVerifier, issue_approval
from open_sovereign_router.audit_sink import MemoryAuditSink
from open_sovereign_router.models import Capability, Model, Provider
from open_sovereign_router.policy import PolicyEngine
from open_sovereign_router.providers import ProviderResult
from open_sovereign_router.redaction import InspectionResult, REDACTION_MARKER, RedactionConfig, RedactionError, TextRedactor
from open_sovereign_router.registry import Registry
from open_sovereign_router.transport import Identity, IdentityRegistry, Limits, RouterService


SECRET = b"r" * 32


class RecordingProvider:
    def __init__(self):
        self.calls = 0
        self.messages = None

    def complete(self, model_id, messages, max_tokens):
        self.calls += 1
        self.messages = messages
        return ProviderResult("synthetic", model_id)


def make_service(sensitivity="public", capability=Capability.BASIC, redactor=None, cloud=False):
    kind = "cloud" if cloud else "local"
    provider_id = kind
    endpoint = "https://api.example.invalid:443" if cloud else "http://127.0.0.1:8081"
    host = "api.example.invalid" if cloud else "127.0.0.1"
    registry = Registry.build([Provider(provider_id, kind, endpoint, frozenset({host}))],
                              [Model("model", provider_id, capability, 0)], "redaction-registry-v1")
    policy = PolicyEngine(registry, ApprovalVerifier(SECRET), "redaction-policy-v1")
    executor = RecordingProvider()
    audit = MemoryAuditSink()
    service = RouterService(policy, IdentityRegistry({"key": Identity("actor", sensitivity)}),
                            {provider_id: executor}, audit, redactor=redactor)
    return service, executor, audit


def synthetic_sensitive_text():
    email = "person" + "@" + "example.invalid"
    phone = "212" + "-555-" + "0199"
    ssn = "123" + "-45-" + "6789"
    account = "4111" + " 1111" * 3
    token = "Bearer " + "synthetic.token.value"
    key = "-----BEGIN " + "PRIVATE" + " KEY-----\nSYNTHETIC"
    return " | ".join((email, phone, ssn, account, token, key))


class RedactorUnitTests(unittest.TestCase):
    def test_detection_roles_overlap_custom_literals_and_immutability(self):
        literal = "CLIENT-CONFIDENTIAL-CODE"
        source = [{"role": role, "content": synthetic_sensitive_text() + " " + literal + "-MORE"}
                  for role in ("system", "user", "assistant")]
        original = copy.deepcopy(source)
        result = TextRedactor(RedactionConfig((literal, literal + "-MORE"))).inspect(source)
        self.assertEqual(source, original)
        self.assertEqual([m["role"] for m in result.messages], ["system", "user", "assistant"])
        self.assertTrue(result.forces_local)
        self.assertGreaterEqual(result.finding_count, 18)
        self.assertNotIn(literal, json.dumps(result.messages))
        self.assertIn(REDACTION_MARKER, result.messages[0]["content"])

    def test_bounds_and_safe_errors(self):
        with self.assertRaises(RedactionError) as caught:
            TextRedactor(max_message_chars=2).inspect([{"role": "user", "content": "SOURCE"}])
        self.assertNotIn("SOURCE", str(caught.exception))
        for bad in ([], [{"role": "tool", "content": "x"}], [{"role": "user", "content": object()}]):
            with self.assertRaises(RedactionError):
                TextRedactor().inspect(bad)
        with self.assertRaises(RedactionError):
            RedactionConfig(tuple("x" + str(i) for i in range(129)))
        marker = "DO-NOT-REPR"
        config = RedactionConfig((marker,))
        result = TextRedactor(config).inspect([{"role": "user", "content": marker}])
        self.assertNotIn(marker, repr(config))
        self.assertNotIn(marker, repr(result))


class RedactionRoutingTests(unittest.TestCase):
    def test_only_redacted_messages_reach_local_provider(self):
        service, executor, _ = make_service()
        original = [{"role": "user", "content": synthetic_sensitive_text()}]
        body = {"messages": copy.deepcopy(original)}
        status, _ = service.chat("key", None, body)
        self.assertEqual(status, 200)
        self.assertEqual(body["messages"], original)
        self.assertEqual(executor.calls, 1)
        self.assertNotIn("example.invalid", executor.messages[0]["content"])

    def test_findings_block_cloud_for_public_and_internal(self):
        for sensitivity in ("public", "internal"):
            service, executor, _ = make_service(sensitivity=sensitivity, capability=Capability.ADVANCED, cloud=True)
            status, payload = service.chat("key", None, {"messages": [{"role": "user", "content": synthetic_sensitive_text()}]})
            self.assertEqual((status, payload["error"]["type"], executor.calls), (400, "sensitive_local_unavailable", 0))

    def test_authenticated_sensitive_labels_remain_local_only(self):
        for sensitivity in ("confidential", "restricted"):
            service, executor, _ = make_service(sensitivity=sensitivity, capability=Capability.ADVANCED, cloud=True)
            status, _ = service.chat("key", None, {"messages": [{"role": "user", "content": "ordinary synthetic text"}]})
            self.assertEqual((status, executor.calls), (400, 0))

    def test_detector_exception_and_malformed_result_fail_before_provider(self):
        class Broken:
            def inspect(self, messages):
                raise RuntimeError("raw source should not escape")
        class Malformed:
            def inspect(self, messages):
                return InspectionResult(tuple(), 0, False, "x")
        for redactor in (Broken(), Malformed()):
            service, executor, audit = make_service(redactor=redactor)
            status, payload = service.chat("key", None, {"messages": [{"role": "user", "content": "PRIVATE-SOURCE"}]})
            self.assertEqual((status, payload["error"]["type"], executor.calls), (503, "inspection_unavailable", 0))
            self.assertNotIn("PRIVATE-SOURCE", json.dumps(payload))
            self.assertNotIn("PRIVATE-SOURCE", json.dumps([e.to_dict() for e in audit.events]))

    def test_preview_is_authenticated_bounded_and_calls_no_provider(self):
        service, executor, _ = make_service()
        body = {"messages": [{"role": "user", "content": synthetic_sensitive_text()}], "max_tokens": 9}
        self.assertEqual(service.preview(None, body)[0], 401)
        status, preview = service.preview("key", body)
        self.assertEqual((status, executor.calls, preview["forces_local"]), (200, 0, True))
        self.assertIn(REDACTION_MARKER, preview["messages"][0]["content"])
        self.assertIn("does not establish clearance", preview["notice"])
        self.assertEqual(service.preview("key", {"messages": [{"role": "user", "content": "x" * 16001}]})[0], 400)
