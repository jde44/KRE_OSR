"""Validated provider and model registry."""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping
import re

from .endpoints import validate_endpoint
from .models import Model, Provider


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")


@dataclass(frozen=True)
class Registry:
    providers: Mapping[str, Provider]
    models: Mapping[str, Model]
    version: str

    @classmethod
    def build(cls, providers: list[Provider], models: list[Model], version: str) -> "Registry":
        if not isinstance(version, str) or not _IDENTIFIER.fullmatch(version):
            raise ValueError("registry version is required and bounded")
        provider_map: dict[str, Provider] = {}
        for provider in providers:
            if not isinstance(provider.provider_id, str) or not _IDENTIFIER.fullmatch(provider.provider_id):
                raise ValueError("invalid provider identifier")
            if provider.provider_id in provider_map:
                raise ValueError("duplicate provider")
            validate_endpoint(provider.endpoint, provider.kind, provider.allowed_hosts)
            provider_map[provider.provider_id] = provider
        model_map: dict[str, Model] = {}
        for model in models:
            if not isinstance(model.model_id, str) or not _IDENTIFIER.fullmatch(model.model_id):
                raise ValueError("invalid model identifier")
            if model.model_id in model_map:
                raise ValueError("duplicate model")
            if model.provider_id not in provider_map:
                raise ValueError("model references unknown provider")
            model_map[model.model_id] = model
        return cls(MappingProxyType(dict(provider_map)), MappingProxyType(dict(model_map)), version)
