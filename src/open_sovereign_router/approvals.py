"""Versioned, canonical, one-time cloud approval envelopes."""

import base64
import hashlib
import hmac
import json
import re
import threading
import time
from dataclasses import asdict, dataclass


class ApprovalError(ValueError):
    pass


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_NONCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
BINDING_FIELDS = (
    "version", "issuer", "request_id", "actor_id", "task", "required_capability",
    "preferred_provider", "preferred_model", "payload_sha256", "sensitivity",
    "provider_id", "model_id", "policy_version", "registry_version",
)


@dataclass(frozen=True)
class ApprovalEnvelope:
    version: int
    issuer: str
    request_id: str
    actor_id: str
    task: str
    required_capability: int
    preferred_provider: str | None
    preferred_model: str | None
    payload_sha256: str
    sensitivity: str
    provider_id: str
    model_id: str
    policy_version: str
    registry_version: str
    issued_at: int
    expires_at: int
    nonce: str

    def bindings(self) -> dict[str, object]:
        values = asdict(self)
        return {name: values[name] for name in BINDING_FIELDS}


def _validate(envelope: ApprovalEnvelope) -> None:
    if envelope.version != 1:
        raise ValueError("unsupported approval envelope version")
    for name in ("issuer", "request_id", "actor_id", "provider_id", "model_id", "policy_version", "registry_version"):
        if not isinstance(getattr(envelope, name), str) or not _ID.fullmatch(getattr(envelope, name)):
            raise ValueError(f"invalid {name}")
    if not isinstance(envelope.task, str) or not (1 <= len(envelope.task) <= 256):
        raise ValueError("invalid task")
    if not isinstance(envelope.required_capability, int) or not (1 <= envelope.required_capability <= 100):
        raise ValueError("invalid required capability")
    for name in ("preferred_provider", "preferred_model"):
        value = getattr(envelope, name)
        if value is not None and (not isinstance(value, str) or not _ID.fullmatch(value)):
            raise ValueError(f"invalid {name}")
    if not isinstance(envelope.payload_sha256, str) or not _SHA256.fullmatch(envelope.payload_sha256):
        raise ValueError("invalid payload SHA-256")
    if envelope.sensitivity not in {"public", "internal", "confidential", "restricted"}:
        raise ValueError("invalid sensitivity")
    if not isinstance(envelope.issued_at, int) or not isinstance(envelope.expires_at, int) or envelope.expires_at <= envelope.issued_at:
        raise ValueError("invalid approval time range")
    if not isinstance(envelope.nonce, str) or not _NONCE.fullmatch(envelope.nonce):
        raise ValueError("invalid nonce")


def _canonical(envelope: ApprovalEnvelope) -> bytes:
    _validate(envelope)
    return json.dumps(asdict(envelope), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def issue_approval(secret: bytes, envelope: ApprovalEnvelope) -> str:
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("approval secret must be at least 32 bytes")
    payload = _canonical(envelope)
    return _encode(payload) + "." + _encode(hmac.new(secret, payload, hashlib.sha256).digest())


class ApprovalVerifier:
    """Single-process replay verifier; durable distributed replay defense is out of scope."""

    def __init__(self, secret: bytes, max_ttl_seconds: int = 300):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("approval secret must be at least 32 bytes")
        if not isinstance(max_ttl_seconds, int) or not (1 <= max_ttl_seconds <= 3600):
            raise ValueError("invalid maximum TTL")
        self._secret = secret
        self._max_ttl = max_ttl_seconds
        self._used_nonces: set[str] = set()
        self._lock = threading.Lock()

    def verify_and_consume(self, token: str, expected_bindings: dict[str, object], now: int | None = None) -> ApprovalEnvelope:
        try:
            encoded_payload, encoded_signature = token.split(".", 1)
            payload = _decode(encoded_payload)
            signature = _decode(encoded_signature)
            data = json.loads(payload)
            envelope = ApprovalEnvelope(**data)
            canonical = _canonical(envelope)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise ApprovalError("malformed approval") from exc
        if payload != canonical:
            raise ApprovalError("non-canonical approval")
        expected_signature = hmac.new(self._secret, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected_signature):
            raise ApprovalError("forged approval")
        current = int(time.time()) if now is None else now
        if envelope.expires_at <= current:
            raise ApprovalError("expired approval")
        if envelope.expires_at - envelope.issued_at > self._max_ttl:
            raise ApprovalError("approval TTL exceeds maximum")
        if envelope.issued_at > current:
            raise ApprovalError("approval issued in the future")
        if set(expected_bindings) != set(BINDING_FIELDS):
            raise ApprovalError("incomplete expected bindings")
        actual = envelope.bindings()
        for name in BINDING_FIELDS:
            if actual[name] != expected_bindings[name]:
                raise ApprovalError(f"approval binding mismatch: {name}")
        with self._lock:
            if envelope.nonce in self._used_nonces:
                raise ApprovalError("replayed approval")
            self._used_nonces.add(envelope.nonce)
        return envelope
