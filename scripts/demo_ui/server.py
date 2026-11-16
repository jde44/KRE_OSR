#!/usr/bin/env python3
"""Local-only demonstration UI for Open Sovereign Router.

The browser never decides a route. Every routing request is forwarded over HTTP to the existing
authenticated localhost transport (``open_sovereign_router.transport.build_server``), and the page renders
only what that backend returns: the decision, its reason code, any approval request and the audit events.

Security boundaries:
- binds to loopback only and checks the Host header;
- a per-launch random UI token (delivered in the URL fragment) is required on every API route;
- router API keys and the approval secret are per-launch, held server-side, never sent to the browser;
- strict Content-Security-Policy; only three allowlisted static files are served; no external requests;
- providers are FakeProvider instances: nothing is sent to any model or network;
- request bodies, message length and output budgets are bounded.
"""

import argparse
import hmac
import http.client
import json
import math
from pathlib import Path
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[2]
if not sys.pycache_prefix:  # never write bytecode caches into the candidate tree
    import tempfile
    sys.pycache_prefix = tempfile.mkdtemp(prefix="osr-pycache-")
sys.path.insert(0, str(ROOT / "src"))

from open_sovereign_router.approvals import BINDING_FIELDS, ApprovalEnvelope, ApprovalVerifier, issue_approval  # noqa: E402
from open_sovereign_router.audit_sink import MemoryAuditSink  # noqa: E402
from open_sovereign_router.models import Capability, Model, Provider  # noqa: E402
from open_sovereign_router.policy import PolicyEngine  # noqa: E402
from open_sovereign_router.providers import FakeProvider  # noqa: E402
from open_sovereign_router.registry import Registry  # noqa: E402
from open_sovereign_router.transport import Identity, IdentityRegistry, Limits, RouterService, build_server  # noqa: E402

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_ROUTES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/static/styles.css": ("styles.css", "text/css; charset=utf-8"),
}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}
LOOPBACK_NAMES = {"127.0.0.1", "localhost", "[::1]"}
SENSITIVITIES = ("public", "internal", "confidential", "restricted")
MAX_BODY_BYTES = 8192
MAX_MESSAGE_CHARS = 2000
MAX_OUTPUT_TOKENS = 2048
APPROVAL_TTL_SECONDS = 120
REQUEST_POLICY_VERSION = "demo-policy-v1"
REGISTRY_VERSION = "demo-registry-v1"

# Synthetic, disclosed price assumptions used only for clearly labelled estimates.
MODEL_CATALOG = (
    {"model_id": "local-small", "provider_id": "local", "kind": "local", "capability": "basic", "cost_rank": 0,
     "usd_per_million_tokens": 0.0, "label": "Small local model"},
    {"model_id": "local-standard", "provider_id": "local", "kind": "local", "capability": "standard", "cost_rank": 1,
     "usd_per_million_tokens": 0.0, "label": "Standard local model"},
    {"model_id": "cloud-advanced", "provider_id": "cloud", "kind": "cloud", "capability": "advanced", "cost_rank": 4,
     "usd_per_million_tokens": 4.0, "label": "Advanced cloud model (simulated; no network)"},
)
CAPABILITIES = {"basic": Capability.BASIC, "standard": Capability.STANDARD, "advanced": Capability.ADVANCED}
CAPABILITY_NAMES = {int(v): k for k, v in CAPABILITIES.items()}

PRESETS = (
    {"id": "public-local", "title": "Public, simple request",
     "summary": "Routed to the smallest capable local model.",
     "message": "Summarise this public product FAQ in two sentences: the router keeps sensitive work local.",
     "sensitivity": "public", "capability": "basic", "max_tokens": 128},
    {"id": "public-cloud-approval", "title": "Public, needs the cloud model",
     "summary": "The only capable model is in the cloud, so a human must approve this one request.",
     "message": "Write a detailed comparison of three public open-source licences for a general audience.",
     "sensitivity": "public", "capability": "advanced", "max_tokens": 256},
    {"id": "restricted-blocked", "title": "Restricted, cloud prohibited",
     "summary": "Restricted data can never go to cloud; with no capable local model it is blocked.",
     "message": "Analyse this synthetic restricted incident note and recommend next steps.",
     "sensitivity": "restricted", "capability": "advanced", "max_tokens": 256},
    {"id": "confidential-local", "title": "Confidential, kept local",
     "summary": "Confidential data is forced onto a local model.",
     "message": "Classify this synthetic confidential memo by topic.",
     "sensitivity": "confidential", "capability": "standard", "max_tokens": 128},
)


class DemoError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


class RouterBackend:
    """One isolated router instance: registry, policy, fake providers, audit sink and the real transport."""

    def __init__(self):
        self.approval_secret = secrets.token_bytes(32)
        self.caller_keys = {s: secrets.token_urlsafe(32) for s in SENSITIVITIES}
        providers = [
            Provider("local", "local", "http://127.0.0.1:8081", frozenset({"127.0.0.1"}), True),
            Provider("cloud", "cloud", "https://cloud.example.invalid:443", frozenset({"cloud.example.invalid"}), True),
        ]
        models = [Model(m["model_id"], m["provider_id"], CAPABILITIES[m["capability"]], m["cost_rank"], True) for m in MODEL_CATALOG]
        registry = Registry.build(providers, models, REGISTRY_VERSION)
        policy = PolicyEngine(registry, ApprovalVerifier(self.approval_secret, APPROVAL_TTL_SECONDS), REQUEST_POLICY_VERSION)
        self.providers = {
            "local": FakeProvider("SYNTHETIC_LOCAL_RESPONSE: generated by the local FakeProvider; no model was run."),
            "cloud": FakeProvider("SYNTHETIC_CLOUD_RESPONSE: generated by the simulated cloud FakeProvider; nothing left this machine."),
        }
        self.audit = MemoryAuditSink()
        identities = IdentityRegistry({key: Identity("demo-" + s, s) for s, key in self.caller_keys.items()})
        self.service = RouterService(policy, identities, self.providers, self.audit, Limits(max_tokens=MAX_OUTPUT_TOKENS))
        self.transport = build_server(self.service, "127.0.0.1", 0)
        self.port = self.transport.server_address[1]
        self.thread = threading.Thread(target=self.transport.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.transport.shutdown()
        self.transport.server_close()
        self.thread.join(timeout=5)

    def forward(self, sensitivity, body, approval=None):
        headers = {"Content-Type": "application/json", "X-OSR-API-Key": self.caller_keys[sensitivity]}
        if approval:
            headers["X-OSR-Approval"] = approval["token"]
            headers["X-OSR-Approval-Request-Id"] = approval["request_id"]
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.request("POST", "/v1/chat/completions", body=json.dumps(body).encode(), headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read() or b"{}")
        finally:
            connection.close()

    def approve(self, bindings):
        """Signs exactly the bindings the router presented. Called only after an explicit human click in the UI."""
        if not isinstance(bindings, dict) or set(bindings) != set(BINDING_FIELDS):
            raise DemoError(400, "approval must carry exactly the bindings the router presented")
        now = int(time.time())
        try:
            envelope = ApprovalEnvelope(**bindings, issued_at=now, expires_at=now + APPROVAL_TTL_SECONDS, nonce="demo-" + secrets.token_hex(12))
            return issue_approval(self.approval_secret, envelope)
        except (TypeError, ValueError) as exc:
            raise DemoError(400, "approval bindings are invalid") from exc

    def audit_events(self, limit=50):
        return [event.to_dict() for event in reversed(self.audit.events[-limit:])]


def _catalog_entry(model_id):
    return next((m for m in MODEL_CATALOG if m["model_id"] == model_id), None)


def estimate(message, max_tokens, model_id, executed):
    """Server-side estimate from synthetic price assumptions; never a measurement."""
    input_tokens = math.ceil(len(message) / 4)
    entry = _catalog_entry(model_id)
    cloud = _catalog_entry("cloud-advanced")
    total = input_tokens + max_tokens
    result = {
        "label": "Estimate only: tokens approximated as characters / 4; prices are synthetic assumptions, not measured.",
        "input_tokens_estimated": input_tokens,
        "output_tokens_budget": max_tokens,
        "executed": executed,
        "cloud_reference_cost_usd": round(total * cloud["usd_per_million_tokens"] / 1_000_000, 6),
    }
    if entry:
        result["model_id"] = entry["model_id"]
        result["usd_per_million_tokens"] = entry["usd_per_million_tokens"]
        result["cost_usd_estimated"] = round(total * entry["usd_per_million_tokens"] / 1_000_000, 6) if executed else 0.0
    return result


def explain(outcome, decision, sensitivity, capability):
    model = decision.get("model")
    cap = capability
    if outcome == "routed" and decision.get("provider") == "local":
        text = f"Routed to {model} on the local provider: the smallest enabled model that meets the {cap} capability, and local models are preferred. Nothing left this machine."
        if sensitivity in ("confidential", "restricted"):
            text += f" Because the data is {sensitivity}, cloud models were never eligible."
        return text
    if outcome == "routed":
        return (f"Routed to {model} (simulated cloud) only because a human approved this single request. "
                "The approval was bound to this exact request and has now been used; repeating it is refused.")
    if outcome == "approval_required":
        return (f"No local model meets the {cap} capability, so the only eligible route is the cloud model {model}. "
                "Cloud use needs explicit approval for this one request. Nothing has been sent: review the bindings, then approve or cancel.")
    reason = decision.get("reason_code")
    if reason == "sensitive_local_unavailable":
        return (f"{sensitivity.capitalize()} data may never be routed to cloud, and no local model meets the {cap} capability. "
                "The request is blocked rather than sent to cloud. There is no silent fallback.")
    if reason == "invalid_approval":
        return "The approval did not match this request, had expired or was already used. Nothing was executed."
    if reason == "no_permitted_model":
        return "No enabled model meets the requested capability. Nothing was executed."
    return "The router rejected the request. Nothing was executed."


def _validate_route(payload):
    if not isinstance(payload, dict):
        raise DemoError(400, "request body must be an object")
    allowed = {"message", "sensitivity", "capability", "max_tokens", "approval"}
    if set(payload) - allowed:
        raise DemoError(400, "unsupported field")
    message = payload.get("message")
    if not isinstance(message, str) or not message.strip():
        raise DemoError(400, "a synthetic message is required")
    if len(message) > MAX_MESSAGE_CHARS:
        raise DemoError(400, f"message is longer than {MAX_MESSAGE_CHARS} characters")
    sensitivity = payload.get("sensitivity")
    if sensitivity not in SENSITIVITIES:
        raise DemoError(400, "sensitivity must be public, internal, confidential or restricted")
    capability = payload.get("capability")
    if capability not in CAPABILITIES:
        raise DemoError(400, "capability must be basic, standard or advanced")
    max_tokens = payload.get("max_tokens")
    if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or not (1 <= max_tokens <= MAX_OUTPUT_TOKENS):
        raise DemoError(400, f"output-token budget must be a whole number from 1 to {MAX_OUTPUT_TOKENS}")
    approval = payload.get("approval")
    if approval is not None:
        if not isinstance(approval, dict) or set(approval) != {"token", "request_id"} or not all(isinstance(v, str) and 0 < len(v) <= 8192 for v in approval.values()):
            raise DemoError(400, "approval must carry a token and the request id")
    return message, sensitivity, capability, max_tokens, approval


class DemoApp:
    def __init__(self):
        self.ui_token = secrets.token_urlsafe(32)
        self._lock = threading.Lock()
        self.backend = RouterBackend()

    def close(self):
        with self._lock:
            self.backend.close()

    def reset(self):
        with self._lock:
            old, self.backend = self.backend, RouterBackend()
        old.close()

    def config(self):
        return {
            "models": list(MODEL_CATALOG),
            "presets": list(PRESETS),
            "sensitivities": list(SENSITIVITIES),
            "capabilities": list(CAPABILITIES),
            "limits": {"max_message_chars": MAX_MESSAGE_CHARS, "max_output_tokens": MAX_OUTPUT_TOKENS},
            "notice": "Local-only demonstration. Synthetic data only. Providers are FakeProvider instances; no model or network is contacted.",
        }

    def route(self, payload):
        message, sensitivity, capability, max_tokens, approval = _validate_route(payload)
        body = {"messages": [{"role": "user", "content": message}], "max_tokens": max_tokens,
                "required_capability": int(CAPABILITIES[capability])}
        backend = self.backend
        status, result = backend.forward(sensitivity, body, approval)
        error = result.get("error", {}) if isinstance(result, dict) else {}
        decision = {}
        approval_request = None
        if status == 200:
            routing = result.get("osr_routing", {})
            decision = {"provider": routing.get("provider"), "model": routing.get("model"),
                        "reason_code": routing.get("reason_code"), "approval_verified": routing.get("approval_verified")}
            outcome = "routed"
        elif status == 409 and error.get("type") == "approval_required":
            approval_request = result.get("approval_request")
            bindings = (approval_request or {}).get("bindings", {})
            decision = {"provider": bindings.get("provider_id"), "model": bindings.get("model_id"),
                        "reason_code": "approval_required", "approval_verified": False}
            outcome = "approval_required"
        else:
            decision = {"provider": None, "model": None, "reason_code": error.get("type"), "approval_verified": False}
            outcome = "blocked" if status in (400, 409) else "error"
        request_id = result.get("request_id") or (result.get("id", "")[len("chatcmpl-"):] if status == 200 else None)
        events = [e for e in backend.audit_events() if request_id and e["request_id"] == request_id]
        response = {
            "outcome": outcome,
            "http_status": status,
            "request_id": request_id,
            "decision": decision,
            "explanation": explain(outcome, decision, sensitivity, capability),
            "estimate": estimate(message, max_tokens, decision.get("model"), outcome == "routed"),
            "audit_events": events,
            "router_error": error.get("message") if outcome in ("blocked", "error") else None,
        }
        if approval_request:
            response["approval_request"] = approval_request
        if status == 200:
            response["response_preview"] = result["choices"][0]["message"]["content"]
        return response


def _loopback_host(header):
    if not header or len(header) > 255 or not header.isascii():
        return False
    host = header.strip().lower()
    if host.startswith("["):
        end = host.find("]")
        name, rest = host[: end + 1], host[end + 1:]
    else:
        name, sep, port = host.partition(":")
        rest = sep + port
    if name not in LOOPBACK_NAMES:
        return False
    return rest == "" or (rest.startswith(":") and rest[1:].isdigit() and 1 <= int(rest[1:]) <= 65535)


def build_demo_server(app, host="127.0.0.1", port=0):
    if host not in {"127.0.0.1", "::1"}:
        raise ValueError("the demo UI must bind to loopback")

    class Handler(BaseHTTPRequestHandler):
        server_version = "OSRDemo"
        sys_version = ""
        timeout = 10

        def log_message(self, format, *args):  # no request logging: nothing about requests is written anywhere
            return

        def _send(self, status, body, content_type="application/json; charset=utf-8"):
            raw = body if isinstance(body, bytes) else json.dumps(body, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            for name, value in SECURITY_HEADERS.items():
                self.send_header(name, value)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)
            self.close_connection = True

        def _error(self, status, message):
            self._send(status, {"error": message[:200]})

        def _authorized(self):
            supplied = self.headers.get("X-OSR-Demo-Token", "")
            return isinstance(supplied, str) and hmac.compare_digest(supplied.encode(), app.ui_token.encode())

        def _guard(self, needs_token):
            if not _loopback_host(self.headers.get("Host")):
                self._error(400, "invalid host")
                return False
            if needs_token and not self._authorized():
                self._error(401, "demo token required; open the URL printed by the launcher")
                return False
            return True

        def _body(self):
            declared = self.headers.get("Content-Length", "")
            if self.headers.get("Transfer-Encoding") or not declared.isdigit():
                raise DemoError(411, "content length required")
            length = int(declared)
            if length > MAX_BODY_BYTES:
                raise DemoError(413, "request body too large")
            raw = self.rfile.read(length)
            try:
                return json.loads(raw or b"{}")
            except (ValueError, RecursionError) as exc:
                raise DemoError(400, "malformed JSON") from exc

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path in STATIC_ROUTES:
                if not self._guard(needs_token=False):
                    return
                name, content_type = STATIC_ROUTES[path]
                return self._send(200, (STATIC_DIR / name).read_bytes(), content_type)
            if not self._guard(needs_token=True):
                return
            if path == "/demo/config":
                return self._send(200, app.config())
            if path == "/demo/audit":
                return self._send(200, {"events": app.backend.audit_events(),
                                        "note": "Metadata only. The audit schema has no field for prompt or response text."})
            return self._error(404, "not found")

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            if not self._guard(needs_token=True):
                return
            try:
                if path == "/demo/route":
                    return self._send(200, app.route(self._body()))
                if path == "/demo/approve":
                    payload = self._body()
                    if not isinstance(payload, dict) or set(payload) != {"bindings"}:
                        raise DemoError(400, "approval needs exactly the presented bindings")
                    token = app.backend.approve(payload["bindings"])
                    return self._send(200, {"approval_token": token, "request_id": payload["bindings"]["request_id"],
                                            "expires_in_seconds": APPROVAL_TTL_SECONDS, "single_use": True})
                if path == "/demo/reset":
                    self._body()
                    app.reset()
                    return self._send(200, {"status": "reset"})
                return self._error(404, "not found")
            except DemoError as exc:
                return self._error(exc.status, exc.message)
            except Exception:
                return self._error(500, "internal error")

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        block_on_close = False

        def handle_error(self, request, client_address):  # never print tracebacks
            return

    return Server((host, port), Handler)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Start the local-only Open Sovereign Router demo UI.")
    parser.add_argument("--port", type=int, default=8765, help="loopback port (0 picks a free port; default 8765)")
    args = parser.parse_args(argv)
    app = DemoApp()
    try:
        server = build_demo_server(app, "127.0.0.1", args.port)
    except OSError as exc:
        app.close()
        raise SystemExit(f"could not bind 127.0.0.1:{args.port} ({exc.strerror}); try --port 0") from None
    port = server.server_address[1]
    print("Open Sovereign Router demo UI (local-only, synthetic data, FakeProvider)")
    print(f"Open this URL in a browser on this machine: http://127.0.0.1:{port}/#t={app.ui_token}")
    print("Press Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        app.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
