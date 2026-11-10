"""Strict startup-time provider endpoint validation."""

import ipaddress
from urllib.parse import urlsplit


class UnsafeEndpoint(ValueError):
    pass


def validate_endpoint(endpoint: str, kind: str, allowed_hosts: frozenset[str]) -> None:
    if not isinstance(endpoint, str) or endpoint != endpoint.strip() or "\\" in endpoint or "%" in endpoint:
        raise UnsafeEndpoint("endpoint contains unsafe normalization characters")
    parsed = urlsplit(endpoint)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise UnsafeEndpoint("endpoint must not contain credentials, query, or fragment")
    if parsed.path not in ("", "/"):
        raise UnsafeEndpoint("endpoint base path must be empty")
    host = (parsed.hostname or "").lower()
    if host.endswith("."):
        raise UnsafeEndpoint("trailing-dot hosts are not allowed")
    normalized_allowlist = set()
    for item in allowed_hosts:
        if not isinstance(item, str) or item != item.strip() or item.endswith(".") or "%" in item:
            raise UnsafeEndpoint("invalid allowlisted host")
        normalized_allowlist.add(item.lower())
    if not host or host not in normalized_allowlist:
        raise UnsafeEndpoint("endpoint host is not explicitly allowlisted")
    if kind == "local":
        if parsed.scheme != "http":
            raise UnsafeEndpoint("local endpoints must use http")
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise UnsafeEndpoint("local endpoint must be a loopback IP")
        except ValueError as exc:
            raise UnsafeEndpoint("local endpoint must use an explicit loopback IP") from exc
    elif kind == "cloud":
        if parsed.scheme != "https":
            raise UnsafeEndpoint("cloud endpoints must use https")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None and not address.is_global:
            raise UnsafeEndpoint("cloud IP literals must be globally routable")
    else:
        raise UnsafeEndpoint("unknown provider kind")
    if parsed.port is None:
        raise UnsafeEndpoint("endpoint must use an explicit port")
