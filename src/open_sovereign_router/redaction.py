"""Bounded, offline text inspection and irreversible redaction.

This deliberately narrow detector is a safety control, not a clearance or
anonymisation system. It performs no I/O and retains no restoration mapping.
"""

import hashlib
import json
import re
from dataclasses import dataclass, field


REDACTION_MARKER = "[REDACTED]"
REDACTION_VERSION = "zess-redactor-v1"
MAX_CUSTOM_LITERALS = 128
MAX_CUSTOM_LITERAL_CHARS = 512
MAX_CONFIG_CHARS = 16_384


class RedactionError(ValueError):
    """Safe inspection failure whose text never includes source content."""

    def __init__(self, code: str = "inspection_failed"):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class RedactionConfig:
    custom_literals: tuple[str, ...] = field(default=(), repr=False)
    version: str = REDACTION_VERSION

    def __post_init__(self):
        if not isinstance(self.version, str) or not (1 <= len(self.version) <= 128):
            raise RedactionError("invalid_configuration")
        if not isinstance(self.custom_literals, tuple) or len(self.custom_literals) > MAX_CUSTOM_LITERALS:
            raise RedactionError("invalid_configuration")
        total = 0
        for value in self.custom_literals:
            if not isinstance(value, str) or not (2 <= len(value) <= MAX_CUSTOM_LITERAL_CHARS):
                raise RedactionError("invalid_configuration")
            total += len(value)
        if total > MAX_CONFIG_CHARS:
            raise RedactionError("invalid_configuration")

    @property
    def fingerprint(self) -> str:
        # Literal values are hashed before entering the canonical configuration representation.
        data = {
            "literal_sha256": sorted(hashlib.sha256(v.encode("utf-8")).hexdigest() for v in self.custom_literals),
            "marker": REDACTION_MARKER,
            "version": self.version,
        }
        raw = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class Finding:
    category: str
    start: int
    end: int


@dataclass(frozen=True)
class InspectionResult:
    messages: tuple[dict[str, str], ...] = field(repr=False)
    finding_count: int
    forces_local: bool
    configuration_sha256: str


_PATTERNS = (
    ("private_key", re.compile(r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----[\s\S]*?(?:-----END(?: [A-Z0-9]+)? PRIVATE KEY-----|\Z)", re.I)),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", re.I)),
    ("credential", re.compile(r"\b(?:api[_ -]?key|access[_ -]?token|secret|password|passwd)\s*[:=]\s*[^\s,;]{4,}", re.I)),
    ("email", re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}(?![\w.-])", re.I)),
    ("ssn_like", re.compile(r"(?<!\d)\d{3}[- ]\d{2}[- ]\d{4}(?!\d)")),
    ("phone", re.compile(r"(?<!\d)(?:\+?\d{1,3}[-. ]?)?(?:\(\d{3}\)|\d{3})[-. ]\d{3}[-. ]\d{4}(?!\d)")),
    ("digit_identifier", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")),
)


class TextRedactor:
    def __init__(self, config: RedactionConfig | None = None, max_messages: int = 32, max_message_chars: int = 16_000):
        self.config = config or RedactionConfig()
        if not isinstance(max_messages, int) or not (1 <= max_messages <= 256):
            raise RedactionError("invalid_bounds")
        if not isinstance(max_message_chars, int) or not (1 <= max_message_chars <= 1_000_000):
            raise RedactionError("invalid_bounds")
        self.max_messages = max_messages
        self.max_message_chars = max_message_chars

    def inspect(self, messages: object) -> InspectionResult:
        if not isinstance(messages, (list, tuple)) or not (1 <= len(messages) <= self.max_messages):
            raise RedactionError("invalid_input")
        output = []
        count = 0
        for message in messages:
            if not isinstance(message, dict) or set(message) != {"role", "content"}:
                raise RedactionError("invalid_input")
            role, content = message.get("role"), message.get("content")
            if role not in {"system", "user", "assistant"} or not isinstance(content, str) or len(content) > self.max_message_chars:
                raise RedactionError("invalid_input")
            redacted, found = self._redact(content)
            output.append({"role": role, "content": redacted})
            count += found
        return InspectionResult(tuple(output), count, count > 0, self.config.fingerprint)

    def _redact(self, text: str) -> tuple[str, int]:
        matches = []
        for category, pattern in _PATTERNS:
            matches.extend(Finding(category, match.start(), match.end()) for match in pattern.finditer(text))
        for literal in self.config.custom_literals:
            start = 0
            while True:
                index = text.find(literal, start)
                if index < 0:
                    break
                matches.append(Finding("client_literal", index, index + len(literal)))
                start = index + 1
        if not matches:
            return text, 0
        ordered = sorted(matches, key=lambda item: (item.start, -item.end))
        merged = []
        for match in ordered:
            if merged and match.start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], match.end))
            else:
                merged.append((match.start, match.end))
        pieces, cursor = [], 0
        for start, end in merged:
            pieces.extend((text[cursor:start], REDACTION_MARKER))
            cursor = end
        pieces.append(text[cursor:])
        return "".join(pieces), len(merged)
