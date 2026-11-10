"""Deterministic local-first routing policy."""

import re

from .approvals import ApprovalError, ApprovalVerifier, BINDING_FIELDS
from .models import Decision, RoutingRequest, Sensitivity
from .registry import Registry


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class SensitivityClassifier:
    """Classifies only authenticated server-boundary values and fails closed."""

    def classify(self, server_label: object) -> Sensitivity:
        if not isinstance(server_label, str):
            return Sensitivity.RESTRICTED
        try:
            return Sensitivity(server_label.lower())
        except ValueError:
            return Sensitivity.RESTRICTED


class PolicyEngine:
    def __init__(
        self,
        registry: Registry,
        approvals: ApprovalVerifier,
        policy_version: str,
        approval_issuer: str = "open-sovereign-router",
        classifier: SensitivityClassifier | None = None,
    ):
        if not policy_version or len(policy_version) > 128:
            raise ValueError("policy version is required and bounded")
        self.registry = registry
        self.approvals = approvals
        self.policy_version = policy_version
        self.approval_issuer = approval_issuer
        self.classifier = classifier or SensitivityClassifier()

    def decide(self, request: RoutingRequest, server_sensitivity_label: object = None, approval_token: str | None = None, now: int | None = None) -> Decision:
        sensitivity = self.classifier.classify(server_sensitivity_label)
        if not isinstance(request.payload_sha256, str) or not _SHA256.fullmatch(request.payload_sha256):
            return self._blocked(request, sensitivity, "invalid_payload_digest", "canonical payload SHA-256 is required")
        if request.preferred_provider and request.preferred_provider not in self.registry.providers:
            return self._blocked(request, sensitivity, "unknown_provider", "requested provider is not registered")
        if request.preferred_model and request.preferred_model not in self.registry.models:
            return self._blocked(request, sensitivity, "unknown_model", "requested model is not registered")

        candidates = []
        for model in self.registry.models.values():
            provider = self.registry.providers[model.provider_id]
            if not (model.enabled and provider.enabled) or model.capability < request.required_capability:
                continue
            if request.preferred_provider and provider.provider_id != request.preferred_provider:
                continue
            if request.preferred_model and model.model_id != request.preferred_model:
                continue
            if sensitivity in (Sensitivity.CONFIDENTIAL, Sensitivity.RESTRICTED) and provider.kind != "local":
                continue
            candidates.append((provider, model))

        candidates.sort(key=lambda pair: (pair[1].capability, pair[1].cost_rank, 0 if pair[0].kind == "local" else 1, pair[1].model_id))
        local = [pair for pair in candidates if pair[0].kind == "local"]
        selected = local[0] if local else (candidates[0] if candidates else None)
        if selected is None:
            code = "sensitive_local_unavailable" if sensitivity in (Sensitivity.CONFIDENTIAL, Sensitivity.RESTRICTED) else "no_permitted_model"
            return self._blocked(request, sensitivity, code, "no capable permitted model is available")

        provider, model = selected
        approval_verified = False
        if provider.kind == "cloud":
            if not approval_token:
                return Decision("blocked", request.request_id, request.actor_id, sensitivity, provider.provider_id, model.model_id, "approval_required", "cloud route requires a single-request approval", True)
            bindings = self._bindings(request, sensitivity, provider.provider_id, model.model_id)
            if set(bindings) != set(BINDING_FIELDS):
                return self._blocked(request, sensitivity, "internal_binding_error", "approval binding set is incomplete", provider.provider_id, model.model_id, True)
            try:
                self.approvals.verify_and_consume(approval_token, bindings, now)
                approval_verified = True
            except ApprovalError as exc:
                return self._blocked(request, sensitivity, "invalid_approval", str(exc), provider.provider_id, model.model_id, True)
        return Decision("selected", request.request_id, request.actor_id, sensitivity, provider.provider_id, model.model_id, "selected_smallest_capable", "smallest capable permitted model selected", False, False, approval_verified)

    def approval_bindings(self, request: RoutingRequest, decision: Decision) -> dict[str, object]:
        """Exact fields an approver must sign for an `approval_required` decision."""
        if decision.reason_code != "approval_required" or not decision.provider_id or not decision.model_id:
            raise ValueError("bindings exist only for approval_required decisions")
        return self._bindings(request, decision.sensitivity, decision.provider_id, decision.model_id)

    def _bindings(self, request: RoutingRequest, sensitivity: Sensitivity, provider_id: str, model_id: str) -> dict[str, object]:
        return {
            "version": 1,
            "issuer": self.approval_issuer,
            "request_id": request.request_id,
            "actor_id": request.actor_id,
            "task": request.task,
            "required_capability": int(request.required_capability),
            "preferred_provider": request.preferred_provider,
            "preferred_model": request.preferred_model,
            "payload_sha256": request.payload_sha256,
            "sensitivity": sensitivity.value,
            "provider_id": provider_id,
            "model_id": model_id,
            "policy_version": self.policy_version,
            "registry_version": self.registry.version,
        }

    @staticmethod
    def _blocked(request, sensitivity, code, reason, provider=None, model=None, approval=False):
        return Decision("blocked", request.request_id, request.actor_id, sensitivity, provider, model, code, reason, approval, False, False)
