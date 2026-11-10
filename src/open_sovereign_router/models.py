"""Typed configuration and decision models for the routing core."""

from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import FrozenSet


class Sensitivity(str, Enum):
    """String-valued enum; (str, Enum) keeps the declared Python 3.10 support (StrEnum is 3.11+)."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class Capability(IntEnum):
    BASIC = 1
    STANDARD = 2
    ADVANCED = 3


@dataclass(frozen=True)
class Provider:
    provider_id: str
    kind: str
    endpoint: str
    allowed_hosts: FrozenSet[str]
    enabled: bool = True


@dataclass(frozen=True)
class Model:
    model_id: str
    provider_id: str
    capability: Capability
    cost_rank: int
    enabled: bool = True


@dataclass(frozen=True)
class RoutingRequest:
    request_id: str
    actor_id: str
    task: str
    required_capability: Capability
    payload_sha256: str
    preferred_provider: str | None = None
    preferred_model: str | None = None


@dataclass(frozen=True)
class Decision:
    status: str
    request_id: str
    actor_id: str
    sensitivity: Sensitivity
    provider_id: str | None
    model_id: str | None
    reason_code: str
    reason: str
    approval_required: bool
    fallback_permitted: bool = False
    approval_verified: bool = False
