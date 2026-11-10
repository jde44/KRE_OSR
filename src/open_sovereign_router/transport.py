"""Authenticated localhost OpenAI-compatible transport."""

import hashlib
import hmac
import json
import re
import socket
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .audit import event_from_decision
from .audit_sink import AuditFailure, AuditSink
from .models import Capability, Decision, RoutingRequest
from .policy import PolicyEngine
from .providers import ProviderExecutor, ProviderFailure, ProviderResult


ALLOWED_BODY_FIELDS = frozenset({"model", "messages", "max_tokens", "stream", "required_capability"})
SERVER_OWNED_FIELDS = frozenset({"actor", "actor_id", "sensitivity", "provider", "endpoint", "base_url"})
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "[::1]"})
_REQUEST_ID = re.compile(r"^[0-9a-f]{32}$")
_CONTENT_LENGTH = re.compile(r"^[0-9]{1,7}$")
_PORT = re.compile(r"^[0-9]{1,5}$")


@dataclass(frozen=True)
class Identity:
    actor_id: str
    sensitivity: str


class IdentityRegistry:
    def __init__(self, api_keys: dict[str, Identity]):
        self._entries = tuple((hashlib.sha256(key.encode()).digest(), identity) for key, identity in api_keys.items())

    def authenticate(self, supplied: str | None) -> Identity | None:
        if not supplied or not isinstance(supplied, str) or len(supplied) > 512:
            return None
        digest = hashlib.sha256(supplied.encode()).digest()
        found = None
        for expected, identity in self._entries:
            if hmac.compare_digest(digest, expected):
                found = identity
        return found


@dataclass(frozen=True)
class Limits:
    max_body_bytes: int = 64_000
    max_messages: int = 32
    max_message_chars: int = 16_000
    max_output_chars: int = 32_000
    max_tokens: int = 2_048
    max_provider_seconds: float = 30.0
    max_concurrency: int = 4
    max_connections: int = 16
    socket_timeout_seconds: float = 10.0
    read_deadline_seconds: float = 15.0
    pending_approval_ttl_seconds: int = 300
    max_pending_approvals: int = 256
    max_pending_per_actor: int = 8


def error(status: int, message: str, error_type: str, request_id: str | None = None):
    payload = {"error": {"message": message[:256], "type": error_type}}
    if request_id:
        payload["request_id"] = request_id
    return status, payload


@dataclass(frozen=True)
class _Pending:
    actor_id: str
    payload_sha256: str
    expires_at: float
    sequence: int


class PendingApprovals:
    """Bounded, single-process store of server-minted request IDs awaiting cloud approval.

    Expiry uses a monotonic clock. Each actor holds at most `per_actor` entries (its own
    oldest entry is evicted first), so one actor cannot exhaust the shared store. `claim`
    removes an entry atomically and only for the owning actor and payload digest, so other
    actors can never disturb it and two concurrent resubmissions cannot both execute.
    """

    def __init__(self, ttl_seconds: int, capacity: int, per_actor: int, monotonic: Callable[[], float]):
        self._ttl = ttl_seconds
        self._capacity = capacity
        self._per_actor = per_actor
        self._monotonic = monotonic
        self._entries: dict[str, _Pending] = {}
        self._sequence = 0
        self._lock = threading.Lock()

    def _purge(self, now: float) -> None:
        for key in [k for k, v in self._entries.items() if v.expires_at <= now]:
            del self._entries[key]

    def create(self, request_id: str, actor_id: str, payload_sha256: str) -> bool:
        with self._lock:
            now = self._monotonic()
            self._purge(now)
            # Insertion order (a strictly increasing sequence), never clock ties or random IDs, decides "oldest".
            own = sorted((v.sequence, k) for k, v in self._entries.items() if v.actor_id == actor_id)
            while own and len(own) >= self._per_actor:
                del self._entries[own.pop(0)[1]]
            if len(self._entries) >= self._capacity:
                return False
            self._sequence += 1
            self._entries[request_id] = _Pending(actor_id, payload_sha256, now + self._ttl, self._sequence)
            return True

    def claim(self, request_id: str, actor_id: str, payload_sha256: str) -> _Pending | None:
        with self._lock:
            self._purge(self._monotonic())
            entry = self._entries.get(request_id)
            if entry is None or entry.actor_id != actor_id or entry.payload_sha256 != payload_sha256:
                return None
            return self._entries.pop(request_id)

    def restore(self, request_id: str, entry: _Pending) -> None:
        """Return a claimed entry after a failed attempt, only if it is unexpired and the caps still allow it."""
        with self._lock:
            now = self._monotonic()
            self._purge(now)
            own = sum(1 for v in self._entries.values() if v.actor_id == entry.actor_id)
            if entry.expires_at > now and own < self._per_actor and len(self._entries) < self._capacity:
                self._entries.setdefault(request_id, entry)

    def count(self, actor_id: str | None = None) -> int:
        with self._lock:
            return sum(1 for v in self._entries.values() if actor_id is None or v.actor_id == actor_id)

    def discard(self, request_id: str) -> None:
        with self._lock:
            self._entries.pop(request_id, None)


class RouterService:
    def __init__(
        self,
        policy: PolicyEngine,
        identities: IdentityRegistry,
        executors: dict[str, ProviderExecutor],
        audit: AuditSink,
        limits: Limits | None = None,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.policy = policy
        self.identities = identities
        self.executors = dict(executors)
        self.audit = audit
        self.limits = limits or Limits()
        self.clock = clock
        self._slots = threading.BoundedSemaphore(self.limits.max_concurrency)
        self.pending = PendingApprovals(self.limits.pending_approval_ttl_seconds, self.limits.max_pending_approvals, self.limits.max_pending_per_actor, monotonic)

    def health(self, api_key: str | None):
        if not self.identities.authenticate(api_key):
            return error(401, "authentication required", "authentication_error")
        return 200, {"status": "ok", "service": "open-sovereign-router", "version": "0.1.0"}

    def models(self, api_key: str | None):
        if not self.identities.authenticate(api_key):
            return error(401, "authentication required", "authentication_error")
        data = [{"id": model.model_id, "object": "model", "owned_by": model.provider_id} for model in self.policy.registry.models.values() if model.enabled]
        return 200, {"object": "list", "data": data}

    def chat(self, api_key: str | None, approval_token: str | None, body: object, approval_request_id: object = None):
        identity = self.identities.authenticate(api_key)
        if not identity:
            return error(401, "authentication required", "authentication_error")
        if not self._slots.acquire(blocking=False):
            return error(429, "concurrency limit reached", "rate_limit_error")
        try:
            return self._chat_locked(identity, approval_token, body, approval_request_id)
        finally:
            self._slots.release()

    def _audit(self, decision: Decision, outcome: str | None = None) -> bool:
        try:
            self.audit.append(event_from_decision(decision, phase="outcome" if outcome else "decision", outcome=outcome))
            return True
        except Exception:  # any sink defect fails closed as audit_unavailable
            return False

    def _validate(self, body: object, request_id: str):
        """Returns (clean_messages, max_tokens, model, capability) or an error tuple."""
        if not isinstance(body, dict):
            return error(400, "request body must be an object", "invalid_request_error", request_id)
        if SERVER_OWNED_FIELDS & set(body):
            return error(400, "server-owned fields are not accepted", "invalid_request_error", request_id)
        if set(body) - ALLOWED_BODY_FIELDS:
            return error(400, "unsupported request field", "invalid_request_error", request_id)
        if body.get("stream") not in (None, False):
            return error(400, "streaming is not supported", "unsupported_feature", request_id)
        messages = body.get("messages")
        if not isinstance(messages, list) or not (1 <= len(messages) <= self.limits.max_messages):
            return error(400, "messages must be a bounded non-empty list", "invalid_request_error", request_id)
        clean = []
        for message in messages:
            if not isinstance(message, dict) or set(message) != {"role", "content"}:
                return error(400, "each message requires only role and content", "invalid_request_error", request_id)
            role, content = message["role"], message["content"]
            if role not in {"system", "user", "assistant"} or not isinstance(content, str) or len(content) > self.limits.max_message_chars:
                return error(400, "invalid or oversized message", "invalid_request_error", request_id)
            clean.append({"role": role, "content": content})
        max_tokens = body.get("max_tokens", 256)
        if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or not (1 <= max_tokens <= self.limits.max_tokens):
            return error(400, "max_tokens is outside server limit", "invalid_request_error", request_id)
        model = body.get("model")
        if model is not None and not isinstance(model, str):
            return error(400, "model must be a configured identifier", "invalid_request_error", request_id)
        capability_value = body.get("required_capability", int(Capability.BASIC))
        if not isinstance(capability_value, int) or isinstance(capability_value, bool):
            return error(400, "invalid required capability", "invalid_request_error", request_id)
        try:
            capability = Capability(capability_value)
        except ValueError:
            return error(400, "invalid required capability", "invalid_request_error", request_id)
        return clean, max_tokens, model, capability

    def _reject_approval(self, identity: Identity, request_id: str, detail: str):
        rejected = Decision("blocked", request_id, identity.actor_id, self.policy.classifier.classify(identity.sensitivity), None, None,
                            "invalid_approval", detail, True)
        if not self._audit(rejected):
            return error(503, "audit unavailable", "audit_unavailable", request_id)
        return error(409, "invalid approval", "invalid_approval", request_id)

    def _chat_locked(self, identity: Identity, approval_token: str | None, body: object, approval_request_id: object):
        if approval_token is not None and (not isinstance(approval_token, str) or not approval_token or len(approval_token) > 8192):
            return self._reject_approval(identity, uuid.uuid4().hex, "invalid approval token header")
        if approval_request_id is not None:
            if not isinstance(approval_request_id, str) or not _REQUEST_ID.fullmatch(approval_request_id):
                return self._reject_approval(identity, uuid.uuid4().hex, "invalid approval request reference")
            if approval_token is None:
                return self._reject_approval(identity, approval_request_id, "approval request reference without token")
        request_id = approval_request_id or uuid.uuid4().hex
        validated = self._validate(body, request_id)
        if isinstance(validated[0], int):
            return validated
        clean, max_tokens, model, capability = validated
        # The digest covers everything that changes what an approver authorizes: messages and output budget.
        canonical = json.dumps({"max_tokens": max_tokens, "messages": clean}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        routing = RoutingRequest(request_id, identity.actor_id, "chat_completions", capability, hashlib.sha256(canonical).hexdigest(), None, model)

        claimed = None
        if approval_request_id is not None:
            claimed = self.pending.claim(request_id, routing.actor_id, routing.payload_sha256)
            if claimed is None:
                return self._reject_approval(identity, request_id, "unknown, expired or mismatched approval request")

        decision = self.policy.decide(routing, identity.sensitivity, approval_token, now=int(self.clock()))
        if claimed is not None and decision.status != "selected":
            self.pending.restore(request_id, claimed)

        if decision.reason_code == "approval_required":
            if not self.pending.create(request_id, routing.actor_id, routing.payload_sha256):
                full = Decision("blocked", request_id, routing.actor_id, decision.sensitivity, decision.provider_id, decision.model_id,
                                "approval_queue_full", "approval queue is full", True)
                if not self._audit(full):
                    return error(503, "audit unavailable", "audit_unavailable", request_id)
                return error(429, "approval queue is full", "rate_limit_error", request_id)
            if not self._audit(decision):
                self.pending.discard(request_id)
                return error(503, "audit unavailable", "audit_unavailable", request_id)
            status, payload = error(409, decision.reason, "approval_required", request_id)
            payload["approval_request"] = {
                "request_id": request_id,
                "expires_at": int(self.clock()) + self.limits.pending_approval_ttl_seconds,
                # Informational, for the approver: the signed digest already covers it, but the approver should see the budget.
                "max_tokens": max_tokens,
                "bindings": self.policy.approval_bindings(routing, decision),
            }
            return status, payload

        if not self._audit(decision):
            return error(503, "audit unavailable; provider not called", "audit_unavailable", request_id)
        if decision.status != "selected":
            if decision.reason_code == "invalid_approval":
                return error(409, "invalid approval", "invalid_approval", request_id)
            return error(409 if decision.approval_required else 400, decision.reason, decision.reason_code, request_id)
        return self._execute(decision, clean, max_tokens, request_id)

    def _fail(self, decision: Decision, outcome: str, status: int, message: str, error_type: str, request_id: str):
        if not self._audit(decision, outcome):
            return error(503, "audit unavailable", "audit_unavailable", request_id)
        return error(status, message, error_type, request_id)

    def _execute(self, decision: Decision, clean: list, max_tokens: int, request_id: str):
        executor = self.executors.get(decision.provider_id or "")
        if executor is None:
            return self._fail(decision, "provider_unavailable", 503, "provider unavailable", "provider_error", request_id)
        started = time.monotonic()
        try:
            result = executor.complete(decision.model_id or "", tuple(clean), max_tokens)
        except Exception:  # any provider defect is contained; details are never echoed
            return self._fail(decision, "provider_error", 503, "provider unavailable", "provider_error", request_id)
        if time.monotonic() - started > self.limits.max_provider_seconds:
            return self._fail(decision, "timeout", 504, "provider time limit exceeded", "timeout_error", request_id)
        if not isinstance(result, ProviderResult) or not isinstance(result.content, str) or len(result.content) > self.limits.max_output_chars:
            return self._fail(decision, "invalid_output", 502, "provider returned invalid output", "provider_error", request_id)
        if result.model_id != decision.model_id:
            return self._fail(decision, "model_mismatch", 502, "provider returned an unexpected model", "provider_error", request_id)
        if not self._audit(decision, "completed"):
            return error(503, "audit unavailable", "audit_unavailable", request_id)
        return 200, {
            "id": "chatcmpl-" + request_id,
            "object": "chat.completion",
            "model": decision.model_id,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": result.content}, "finish_reason": "stop"}],
            "osr_routing": {"provider": decision.provider_id, "model": decision.model_id, "reason_code": decision.reason_code, "approval_verified": decision.approval_verified},
        }


def _reject_constant(value: str):
    raise ValueError("non-finite number")


def _reject_duplicate_pairs(pairs):
    """Reject ambiguous JSON objects instead of silently taking the last member."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _loopback_host(header: str | None) -> bool:
    if not header or len(header) > 255 or not header.isascii():
        return False
    host = header.strip().lower()
    if host.startswith("["):
        end = host.find("]")
        if end < 0:
            return False
        name, rest = host[: end + 1], host[end + 1:]
    else:
        name, sep, port = host.partition(":")
        rest = sep + port
    if rest == "":
        return name in LOOPBACK_HOSTS
    return name in LOOPBACK_HOSTS and rest.startswith(":") and bool(_PORT.fullmatch(rest[1:])) and 1 <= int(rest[1:]) <= 65535


class _BoundedServer(ThreadingHTTPServer):
    """Caps simultaneous connections; excess connections get an immediate 503 and are closed."""

    daemon_threads = True
    block_on_close = False

    def __init__(self, address, handler, max_connections: int):
        self._connection_slots = threading.BoundedSemaphore(max_connections)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self._connection_slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._connection_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()

    def handle_error(self, request, client_address):
        # Never print tracebacks: they can carry request-derived data. Handlers return structured errors.
        return


def build_server(service: RouterService, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    if host not in {"127.0.0.1", "::1"}:
        raise ValueError("server must bind to loopback")
    deadline = service.limits.read_deadline_seconds

    class Handler(BaseHTTPRequestHandler):
        server_version = "OpenSovereignRouter/0.1.0"
        sys_version = ""
        timeout = service.limits.socket_timeout_seconds

        def log_message(self, format, *args): return
        def _key(self): return self.headers.get("X-OSR-API-Key")
        def _single_header(self, name):
            values = self.headers.get_all(name, failobj=[])
            return values[0] if len(values) == 1 else None

        def _ambiguous_security_headers(self):
            names = ("Host", "X-OSR-API-Key", "X-OSR-Approval", "X-OSR-Approval-Request-Id", "Content-Length", "Transfer-Encoding")
            return any(len(self.headers.get_all(name, failobj=[])) > 1 for name in names)

        # Total read deadline: the per-read socket timeout alone lets a client drip bytes forever.
        # A watchdog shuts the socket down if headers and body are not fully read in time.
        def setup(self):
            super().setup()
            self._read_lock = threading.Lock()
            self._reading = True
            self._expired = False
            self._watchdog = threading.Timer(deadline, self._expire)
            self._watchdog.daemon = True
            self._watchdog.start()

        def _expire(self):
            with self._read_lock:
                if not self._reading:
                    return
                self._expired = True
                self._reading = False
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        def _read_complete(self) -> bool:
            """Stops the watchdog; False if the read deadline already expired."""
            with self._read_lock:
                self._reading = False
                self._watchdog.cancel()
                return not self._expired

        def finish(self):
            self._watchdog.cancel()
            try:
                super().finish()
            except OSError:
                pass

        def _send(self, status, payload):
            self.close_connection = True
            if not self._read_complete():
                return
            raw = json.dumps(payload, separators=(",", ":")).encode()
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw)
            except OSError:
                pass
            self.close_connection = True

        def _host_ok(self):
            if not self._ambiguous_security_headers() and _loopback_host(self._single_header("Host")):
                return True
            self._send(*error(400, "invalid host", "invalid_request_error"))
            return False

        def do_GET(self):
            if not self._read_complete():
                self.close_connection = True
                return
            if not self._host_ok():
                return
            path = self.path.rstrip("/")
            if path in {"/health", "/v1/health"}: status, payload = service.health(self._key())
            elif path in {"/models", "/v1/models"}: status, payload = service.models(self._key())
            else: status, payload = error(404, "not found", "not_found")
            self._send(status, payload)

        def do_POST(self):
            if not self._host_ok():
                return
            if self.path.rstrip("/") != "/v1/chat/completions":
                return self._send(*error(404, "not found", "not_found"))
            if not service.identities.authenticate(self._key()):
                return self._send(*error(401, "authentication required", "authentication_error"))
            if self._ambiguous_security_headers() or self.headers.get("Transfer-Encoding"):
                return self._send(*error(411, "content length required", "invalid_request_error"))
            declared = self.headers.get("Content-Length", "")
            if not _CONTENT_LENGTH.fullmatch(declared):
                return self._send(*error(411, "content length required", "invalid_request_error"))
            length = int(declared)
            if not (1 <= length <= service.limits.max_body_bytes):
                return self._send(*error(413, "request body too large", "request_too_large"))
            try:
                raw = self.rfile.read(length)
            except OSError:  # includes socket timeouts
                return self._send(*error(408, "request body timed out", "timeout_error"))
            if not self._read_complete():
                self.close_connection = True
                return
            if len(raw) != length:
                return self._send(*error(400, "incomplete request body", "invalid_request_error"))
            try:
                body = json.loads(raw, parse_constant=_reject_constant, object_pairs_hook=_reject_duplicate_pairs)
            except (ValueError, RecursionError):  # JSONDecodeError and UnicodeDecodeError are ValueErrors
                return self._send(*error(400, "malformed JSON", "invalid_request_error"))
            try:
                status, payload = service.chat(self._key(), self._single_header("X-OSR-Approval"), body, self._single_header("X-OSR-Approval-Request-Id"))
            except Exception:
                status, payload = error(500, "internal error", "internal_error")
            self._send(status, payload)

    server_class = _BoundedServer
    if host == "::1":
        server_class = type("_BoundedServer6", (_BoundedServer,), {"address_family": socket.AF_INET6})
    return server_class((host, port), Handler, service.limits.max_connections)
