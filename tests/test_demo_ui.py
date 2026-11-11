"""Tests for the local-only demo UI (scripts/demo_ui): API behaviour through the real transport, and static checks.

Browser-level checks (keyboard path, responsive layout, XSS rendering, zero external requests and screenshots)
live in scripts/demo_ui/e2e_check.py, an optional developer tool, so this suite stays standard-library only.
"""

import dataclasses
from html.parser import HTMLParser
import http.client
import importlib.util
import json
from pathlib import Path
import re
import socket
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
UI_DIR = ROOT / "scripts" / "demo_ui"


def load_demo_server():
    spec = importlib.util.spec_from_file_location("osr_demo_ui_server", UI_DIR / "server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


demo = load_demo_server()
from open_sovereign_router.approvals import BINDING_FIELDS  # noqa: E402  (path set by the demo module)
from open_sovereign_router.audit import AuditEvent  # noqa: E402

PRESETS = {p["id"]: p for p in demo.PRESETS}


def preset_request(preset_id, **overrides):
    p = PRESETS[preset_id]
    body = {"message": p["message"], "sensitivity": p["sensitivity"], "capability": p["capability"], "max_tokens": p["max_tokens"]}
    body.update(overrides)
    return body


class DemoServerMixin:
    def setUp(self):
        self.app = demo.DemoApp()
        self.server = demo.build_demo_server(self.app, "127.0.0.1", 0)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.app.close)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def call(self, method, path, body=None, token=True, host=None, raw=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        self.addCleanup(conn.close)
        final = dict(headers or {})
        if token:
            final["X-OSR-Demo-Token"] = self.app.ui_token if token is True else token
        if host:
            final["Host"] = host
        payload = raw if raw is not None else (None if body is None else json.dumps(body).encode())
        if payload is not None:
            final.setdefault("Content-Type", "application/json")
        conn.request(method, path, body=payload, headers=final)
        response = conn.getresponse()
        data = response.read()
        try:
            parsed = json.loads(data)
        except ValueError:
            parsed = data
        return response.status, parsed, dict(response.getheaders())

    def route(self, body):
        status, payload, _ = self.call("POST", "/demo/route", body)
        self.assertEqual(status, 200, payload)
        return payload

    def calls(self):
        return {name: provider.calls for name, provider in self.app.backend.providers.items()}


class PresetScenarioTests(DemoServerMixin, unittest.TestCase):
    def test_public_low_complexity_routes_to_smallest_local_model(self):
        result = self.route(preset_request("public-local"))
        self.assertEqual(result["outcome"], "routed")
        self.assertEqual((result["decision"]["provider"], result["decision"]["model"]), ("local", "local-small"))
        self.assertFalse(result["decision"]["approval_verified"])
        self.assertEqual(self.calls(), {"local": 1, "cloud": 0})
        self.assertEqual([e["phase"] for e in result["audit_events"]], ["outcome", "decision"])
        self.assertIn("smallest", result["explanation"])
        self.assertTrue(result["estimate"]["label"].startswith("Estimate only"))
        self.assertEqual(result["estimate"]["cost_usd_estimated"], 0.0)

    def test_public_cloud_route_requires_explicit_single_request_approval(self):
        body = preset_request("public-cloud-approval")
        first = self.route(body)
        self.assertEqual(first["outcome"], "approval_required")
        self.assertEqual(self.calls(), {"local": 0, "cloud": 0})
        bindings = first["approval_request"]["bindings"]
        self.assertEqual(set(bindings), set(BINDING_FIELDS))
        self.assertEqual((bindings["provider_id"], bindings["model_id"]), ("cloud", "cloud-advanced"))

        status, granted, _ = self.call("POST", "/demo/approve", {"bindings": bindings})
        self.assertEqual(status, 200)
        self.assertTrue(granted["single_use"])
        approval = {"token": granted["approval_token"], "request_id": granted["request_id"]}
        second = self.route(dict(body, approval=approval))
        self.assertEqual(second["outcome"], "routed")
        self.assertEqual((second["decision"]["provider"], second["decision"]["approval_verified"]), ("cloud", True))
        self.assertEqual(self.calls(), {"local": 0, "cloud": 1})

        replay = self.route(dict(body, approval=approval))
        self.assertEqual((replay["outcome"], replay["decision"]["reason_code"]), ("blocked", "invalid_approval"))
        self.assertEqual(self.calls(), {"local": 0, "cloud": 1})

    def test_restricted_request_is_never_routed_to_cloud(self):
        result = self.route(preset_request("restricted-blocked"))
        self.assertEqual((result["outcome"], result["decision"]["reason_code"]), ("blocked", "sensitive_local_unavailable"))
        self.assertNotIn("approval_request", result)
        self.assertEqual(self.calls(), {"local": 0, "cloud": 0})

    def test_confidential_preset_is_forced_local(self):
        result = self.route(preset_request("confidential-local"))
        self.assertEqual((result["decision"]["provider"], result["decision"]["model"]), ("local", "local-standard"))


class RoutingControlTests(DemoServerMixin, unittest.TestCase):
    def test_sensitive_data_never_reaches_cloud_at_any_capability(self):
        for sensitivity in ("confidential", "restricted"):
            for capability in ("basic", "standard", "advanced"):
                result = self.route({"message": "synthetic", "sensitivity": sensitivity, "capability": capability, "max_tokens": 16})
                self.assertNotEqual(result["decision"]["provider"], "cloud", (sensitivity, capability))
                self.assertNotIn("approval_request", result)
        self.assertEqual(self.calls()["cloud"], 0)

    def test_local_first_even_when_cloud_is_also_capable(self):
        result = self.route({"message": "synthetic", "sensitivity": "public", "capability": "standard", "max_tokens": 16})
        self.assertEqual(result["decision"]["model"], "local-standard")

    def test_no_silent_fallback_when_cloud_needs_approval(self):
        self.route(preset_request("public-cloud-approval"))
        self.assertEqual(self.calls(), {"local": 0, "cloud": 0})

    def test_approval_cannot_be_moved_to_a_different_request(self):
        body = preset_request("public-cloud-approval")
        first = self.route(body)
        _, granted, _ = self.call("POST", "/demo/approve", {"bindings": first["approval_request"]["bindings"]})
        approval = {"token": granted["approval_token"], "request_id": granted["request_id"]}
        changed = self.route(dict(body, message="a different synthetic request", approval=approval))
        self.assertEqual(changed["decision"]["reason_code"], "invalid_approval")
        self.assertEqual(self.calls()["cloud"], 0)

    def test_approve_endpoint_requires_exactly_the_presented_bindings(self):
        first = self.route(preset_request("public-cloud-approval"))
        bindings = dict(first["approval_request"]["bindings"])
        for bad in ({"bindings": dict(bindings, extra=1)}, {"bindings": {k: v for k, v in bindings.items() if k != "model_id"}},
                    {"bindings": bindings, "other": 1}, {"bindings": "x"}):
            self.assertEqual(self.call("POST", "/demo/approve", bad)[0], 400, bad)

    def test_reset_gives_a_fresh_router_and_invalidates_pending_approvals(self):
        body = preset_request("public-cloud-approval")
        first = self.route(body)
        _, granted, _ = self.call("POST", "/demo/approve", {"bindings": first["approval_request"]["bindings"]})
        old_backend = self.app.backend
        self.assertEqual(self.call("POST", "/demo/reset", {})[0], 200)
        self.assertIsNot(self.app.backend, old_backend)
        self.assertEqual(self.call("GET", "/demo/audit")[1]["events"], [])
        stale = self.route(dict(body, approval={"token": granted["approval_token"], "request_id": granted["request_id"]}))
        self.assertEqual(stale["decision"]["reason_code"], "invalid_approval")


class AuditAndPrivacyTests(DemoServerMixin, unittest.TestCase):
    MARKER = "UNIQUE-SYNTHETIC-MARKER-7f3a"

    def test_audit_view_is_metadata_only(self):
        self.route({"message": self.MARKER, "sensitivity": "public", "capability": "basic", "max_tokens": 8})
        self.route({"message": self.MARKER, "sensitivity": "restricted", "capability": "advanced", "max_tokens": 8})
        status, audit, _ = self.call("GET", "/demo/audit")
        self.assertEqual(status, 200)
        self.assertNotIn(self.MARKER, json.dumps(audit))
        allowed = {f.name for f in dataclasses.fields(AuditEvent)}
        self.assertTrue(audit["events"])
        for event in audit["events"]:
            self.assertLessEqual(set(event), allowed)

    def test_route_response_never_echoes_the_message(self):
        result = self.route({"message": self.MARKER, "sensitivity": "public", "capability": "basic", "max_tokens": 8})
        self.assertNotIn(self.MARKER, json.dumps(result))


class InputValidationTests(DemoServerMixin, unittest.TestCase):
    def test_invalid_requests_are_rejected(self):
        good = preset_request("public-local")
        for bad in (dict(good, sensitivity="secret"), dict(good, capability="expert"), dict(good, max_tokens=0),
                    dict(good, max_tokens=2049), dict(good, max_tokens=True), dict(good, max_tokens="64"),
                    dict(good, message=""), dict(good, message="x" * 2001), dict(good, extra=1),
                    dict(good, approval={"token": "t"}), [good]):
            self.assertEqual(self.call("POST", "/demo/route", bad)[0], 400, bad)
        self.assertEqual(self.calls(), {"local": 0, "cloud": 0})

    def test_oversized_malformed_and_chunked_bodies(self):
        self.assertEqual(self.call("POST", "/demo/route", raw=b"{" + b" " * 9000 + b"}")[0], 413)
        self.assertEqual(self.call("POST", "/demo/route", raw=b"{not json")[0], 400)
        self.assertEqual(self.call("POST", "/demo/route", raw=b"[" * 3000 + b"]" * 3000)[0], 400)
        status, _, _ = self.call("POST", "/demo/route", raw=b"{}", headers={"Transfer-Encoding": "chunked"})
        self.assertEqual(status, 411)


class BoundaryTests(DemoServerMixin, unittest.TestCase):
    def test_api_requires_the_per_launch_token(self):
        for method, path in (("GET", "/demo/config"), ("GET", "/demo/audit"), ("POST", "/demo/route"), ("POST", "/demo/approve"), ("POST", "/demo/reset")):
            self.assertEqual(self.call(method, path, {} if method == "POST" else None, token=False)[0], 401, path)
            self.assertEqual(self.call(method, path, {} if method == "POST" else None, token="wrong-token-value-123456")[0], 401, path)

    def test_non_loopback_host_header_is_rejected(self):
        self.assertEqual(self.call("GET", "/", token=False, host="attacker.example")[0], 400)
        self.assertEqual(self.call("GET", "/demo/config", host="attacker.example:80")[0], 400)

    def test_only_allowlisted_static_files_are_served(self):
        self.assertEqual(self.call("GET", "/", token=False)[0], 200)
        for path in ("/static/server.py", "/static/../server.py", "/server.py", "/static/", "/demo/unknown"):
            self.assertEqual(self.call("GET", path)[0], 404, path)

    def test_security_headers_on_every_response(self):
        for path, token in (("/", False), ("/static/app.js", False), ("/static/styles.css", False), ("/demo/config", True)):
            status, _, headers = self.call("GET", path, token=token)
            self.assertEqual(status, 200, path)
            self.assertEqual(headers["Content-Security-Policy"], demo.CSP)
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertIn("script-src 'self'", demo.CSP)
        self.assertNotIn("unsafe-inline", demo.CSP)
        self.assertNotIn("unsafe-eval", demo.CSP)

    def test_demo_server_refuses_non_loopback_bind(self):
        with self.assertRaises(ValueError):
            demo.build_demo_server(self.app, "0.0.0.0", 0)

    def test_full_walkthrough_makes_no_non_loopback_connection(self):
        destinations = []
        real = socket.create_connection

        def recording(address, *args, **kwargs):
            destinations.append(address[0])
            return real(address, *args, **kwargs)

        with mock.patch.object(socket, "create_connection", recording):
            for preset_id in PRESETS:
                result = self.route(preset_request(preset_id))
                if result["outcome"] == "approval_required":
                    _, granted, _ = self.call("POST", "/demo/approve", {"bindings": result["approval_request"]["bindings"]})
                    self.route(dict(preset_request(preset_id), approval={"token": granted["approval_token"], "request_id": granted["request_id"]}))
        self.assertTrue(destinations)
        self.assertEqual(set(destinations), {"127.0.0.1"})


class _MarkupAudit(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids, self.label_for, self.controls, self.problems = set(), set(), [], []
        self.label_depth = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "id" in a:
            self.ids.add(a["id"])
        if tag == "label":
            self.label_depth += 1
            if "for" in a:
                self.label_for.add(a["for"])
        if tag in ("input", "select", "textarea"):
            self.controls.append((tag, a.get("id"), self.label_depth > 0))
        if tag == "script" and "src" not in a:
            self.problems.append("inline script")
        if "style" in a:
            self.problems.append("inline style on " + tag)
        if any(name.startswith("on") for name in a):
            self.problems.append("inline event handler on " + tag)
        if "tabindex" in a and a["tabindex"].lstrip("-").isdigit() and int(a["tabindex"]) > 0:
            self.problems.append("positive tabindex on " + tag)
        if tag == "button" and "type" not in a:
            self.problems.append("button without type")

    def handle_endtag(self, tag):
        if tag == "label":
            self.label_depth -= 1


class StaticFrontendTests(unittest.TestCase):
    def read(self, name):
        return (UI_DIR / "static" / name).read_text(encoding="utf-8")

    def test_script_never_builds_html_from_data(self):
        js = self.read("app.js")
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setTimeout(\"", "srcdoc"):
            self.assertNotIn(sink, js, sink)
        self.assertIn("textContent", js)

    def test_markup_is_labelled_and_keyboard_friendly(self):
        audit = _MarkupAudit()
        audit.feed(self.read("index.html"))
        self.assertEqual(audit.problems, [])
        for tag, control_id, wrapped in audit.controls:
            self.assertTrue(wrapped or (control_id and control_id in audit.label_for), (tag, control_id))
        html = self.read("index.html")
        self.assertIn('<html lang="en">', html)
        self.assertIn('class="skip-link"', html)
        self.assertGreaterEqual(html.count('aria-live="polite"'), 3)

    def test_styles_have_visible_focus_and_responsive_rules(self):
        css = self.read("styles.css")
        self.assertIn(":focus-visible", css)
        self.assertGreaterEqual(len(re.findall(r"@media \(max-width: \d+px\)", css)), 2)
        self.assertIn("prefers-reduced-motion", css)

    def test_frontend_has_no_external_references(self):
        for name in ("index.html", "app.js", "styles.css"):
            text = self.read(name)
            self.assertIsNone(re.search(r"(?:https?:)?//[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text.replace("/static/", "")), name)
            self.assertNotIn("@import", text)
            self.assertNotIn("url(", text)

    def test_server_uses_only_stdlib_and_the_router_package(self):
        import ast
        import sys
        tree = ast.parse((UI_DIR / "server.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else (
                [node.module] if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module else [])
            for name in names:
                top = name.split(".")[0]
                self.assertTrue(top in sys.stdlib_module_names or top == "open_sovereign_router", name)

    def test_server_only_opens_loopback_connections(self):
        source = (UI_DIR / "server.py").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"HTTPConnection\(([^,]+),", source), ['"127.0.0.1"'])
        for forbidden in ("urllib.request", "urlopen", "import requests", "socket.create_connection"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
