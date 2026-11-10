"""Prompt-free audit schema."""

from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from .models import Decision


@dataclass(frozen=True)
class AuditEvent:
    request_id: str
    actor_id: str
    timestamp: str
    sensitivity: str
    status: str
    provider_id: str | None
    model_id: str | None
    reason_code: str
    approval_verified: bool
    phase: str = "decision"
    outcome: str | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


_PHASES = {"decision", "outcome"}
_OUTCOMES = {None, "completed", "provider_error", "provider_unavailable", "timeout", "invalid_output", "model_mismatch"}


def event_from_decision(
    decision: Decision,
    clock: Callable[[], datetime] | None = None,
    phase: str = "decision",
    outcome: str | None = None,
) -> AuditEvent:
    """Build a prompt-free event. Detail is copied only from fixed approval-verifier reasons."""
    if phase not in _PHASES or outcome not in _OUTCOMES or (phase == "outcome") == (outcome is None):
        raise ValueError("invalid audit phase/outcome")
    observed = (clock or (lambda: datetime.now(timezone.utc)))()
    if not isinstance(observed, datetime) or observed.tzinfo is None or observed.utcoffset() is None:
        raise ValueError("audit clock must return a timezone-aware datetime")
    return AuditEvent(
        request_id=decision.request_id,
        actor_id=decision.actor_id,
        timestamp=observed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        sensitivity=decision.sensitivity.value,
        status=decision.status,
        provider_id=decision.provider_id,
        model_id=decision.model_id,
        reason_code=decision.reason_code,
        approval_verified=decision.approval_verified,
        phase=phase,
        outcome=outcome,
        detail=decision.reason[:128] if decision.reason_code == "invalid_approval" else None,
    )
