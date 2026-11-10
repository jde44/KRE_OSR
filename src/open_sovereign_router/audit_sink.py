"""Append-only, prompt-free audit sinks."""

import json
import os
from pathlib import Path
from typing import Protocol

from .audit import AuditEvent


class AuditFailure(RuntimeError):
    pass


class AuditSink(Protocol):
    def append(self, event: AuditEvent) -> None: ...


class FileAuditSink:
    """Append-only process behavior with owner-only file permissions.

    Filesystem administrators can still alter the file; tamper-evident durable
    storage is a later gate. No prompt or token is accepted by this interface.
    """

    def __init__(self, path: Path):
        self.path = path

    def append(self, event: AuditEvent) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            raw = (json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":")) + "\n").encode()
            fd = os.open(self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                os.write(fd, raw)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.chmod(self.path, 0o600)
        except OSError as exc:
            raise AuditFailure("audit unavailable") from exc


class MemoryAuditSink:
    def __init__(self, fail: bool = False):
        self.events: list[AuditEvent] = []
        self.fail = fail

    def append(self, event: AuditEvent) -> None:
        if self.fail:
            raise AuditFailure("audit unavailable")
        self.events.append(event)

