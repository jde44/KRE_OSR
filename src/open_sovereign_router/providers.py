"""Provider execution interfaces; the test suite uses only FakeProvider."""

import json
from dataclasses import dataclass
from typing import Protocol
from urllib.request import HTTPRedirectHandler, Request, build_opener


class ProviderFailure(RuntimeError):
    """Safe public provider failure; never include upstream bodies or credentials."""


@dataclass(frozen=True)
class ProviderResult:
    content: str
    model_id: str


class ProviderExecutor(Protocol):
    def complete(self, model_id: str, messages: tuple[dict[str, str], ...], max_tokens: int) -> ProviderResult: ...


class FakeProvider:
    def __init__(self, content: str = "FAKE_OK", failure: bool = False):
        self.content = content
        self.failure = failure
        self.calls = 0

    def complete(self, model_id: str, messages: tuple[dict[str, str], ...], max_tokens: int) -> ProviderResult:
        self.calls += 1
        if self.failure:
            raise ProviderFailure("provider unavailable")
        return ProviderResult(self.content, model_id)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class LlamaCppAdapter:
    """Configured-endpoint adapter design; real execution is outside the test suite.

    Endpoint/model are constructor-owned, never request-owned. Redirects are
    disabled. A future real-network gate must add resolved-address pinning and
    TLS/DNS controls before cloud use.
    """

    def __init__(self, endpoint: str, configured_model: str, timeout_seconds: float = 30.0):
        self.endpoint = endpoint.rstrip("/")
        self.configured_model = configured_model
        self.timeout_seconds = timeout_seconds
        self._opener = build_opener(_NoRedirect)

    def complete(self, model_id: str, messages: tuple[dict[str, str], ...], max_tokens: int) -> ProviderResult:
        if model_id != self.configured_model:
            raise ProviderFailure("model is not configured")
        payload = json.dumps({"model": self.configured_model, "messages": messages, "max_tokens": max_tokens, "stream": False}).encode()
        request = Request(self.endpoint + "/chat/completions", payload, {"Content-Type": "application/json"})
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                body = json.loads(response.read(1_000_000))
                content = body["choices"][0]["message"]["content"]
                if not isinstance(content, str):
                    raise ValueError
                return ProviderResult(content, self.configured_model)
        except Exception as exc:
            raise ProviderFailure("provider unavailable") from exc

