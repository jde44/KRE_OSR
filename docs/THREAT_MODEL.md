# Threat Model

Status: mixed implementation. The policy, approval, registry, endpoint-configuration and audit-schema controls have offline tests. The authenticated localhost transport has loopback tests for two-phase approval, connection and timeout limits, Host checks, complete decision and outcome audit, and provider-model integrity. Outbound provider DNS/rebinding/TLS controls, durable replay and pending state, secret lifecycle and production controls remain design requirements; they are not implemented or validated.

The adversarial evaluation catalog provides raw machine-readable outcomes and regression coverage across the invariants below. It found and remediated a duplicate JSON/security-header ambiguity test-first. The residual risks below remain development-only constraints, and production claims remain prohibited.

## Assets and trust boundaries

Protected assets include prompts and retrieved content, credentials, approval decisions, policy configuration, routing/audit integrity, provider responses, and operator privacy. Trust boundaries exist between the calling application, router API, policy engine, local runtime, cloud provider, configuration store, audit sink, and human approver.

## Security invariants

1. Sensitive classifications cannot route to cloud, even if cloud is preferred or an approval flag is present.
2. Cloud is disabled unless explicitly configured; enabling a provider does not approve a request.
3. Approval is scoped to one request, expires, cannot be replayed, and is bound to the route/model/data classification shown to the approver.
4. No silent fallback changes provider, model, jurisdiction, or privacy boundary.
5. Audit events contain routing metadata, not prompt or retrieved content.
6. A failure to enforce policy or write required audit evidence fails closed.

## Initial threats and planned controls

| Threat | Impact | Planned control and test |
|---|---|---|
| Misclassified sensitive content | Unauthorized cloud disclosure | Caller classification plus configurable detectors; hard local-only policy; adversarial labeled tests; clearly document residual detector limits |
| Forged/replayed approval | Unauthorized cloud use | HMAC envelope bound to a server-minted request ID, a payload digest covering messages and `max_tokens`, actor, model and classification; owner-only claim; atomic pending-request claim and consumption; short expiry; generic failure message with no oracle; replay, expiry, actor and digest tests |
| Prompt injection changes route | Policy bypass | Route fields accepted only through trusted typed request/config channels; never derive authorization from prompt text; injection tests |
| Silent provider fallback or model substitution | Undisclosed boundary/cost change | No fallback by default; a provider-reported model that differs from the routed model is rejected and audited as `model_mismatch`; explicit fallback policy and fresh approval when the boundary changes; outage tests |
| Malicious or compromised provider | Data loss or harmful output | Allowlist, TLS verification, minimum disclosure, response labeling, timeouts, operator kill switch; fake-provider tests |
| SSRF or arbitrary endpoint configuration | Internal network access | Startup-time endpoint allowlist/scheme validation; reject non-global cloud IP literals and normalization ambiguity; block per-request endpoint overrides. DNS/rebinding, redirect and connection-time IP controls remain mandatory at the future transport gate |
| Secrets in logs/errors | Credential or data exposure | Header/body redaction, structured allowlisted audit fields, bounded upstream errors; log-capture tests |
| Audit deletion/tampering, disk exhaustion or gaps | Lost accountability | Every decision and outcome is audited and fails closed; append-only target option; request IDs; integrity chaining/signing roadmap; storage preflight |
| Denial of service / oversized request | Resource exhaustion | Body, token and concurrency limits; connection cap with immediate 503; per-read socket timeout plus a total read deadline against slow-drip clients; authentication before the body is read; pending-approval store bounded in total and per actor; **accepted residual:** slots are claimed before authentication, so any local process that keeps reopening connections can lock clients out indefinitely (see Residual risks); nested-JSON handling; localhost default; boundary and socket tests |
| Dependency or model supply-chain compromise | Code execution or corrupted behavior | Pinned versions/hashes, SBOM, official provenance, license/advisory scan; release gate |
| Cost-estimate manipulation | Unexpected spend | Server-owned price table/version, budget ceiling, post-use reconciliation; unit tests |
| Browser DNS rebinding to localhost | Local router abused from a web page | Loopback-only `Host` allowlist; custom API-key header forces a CORS preflight; no CORS headers served |
| Duplicate JSON members or security headers | Parser disagreement or authority ambiguity | Reject duplicate JSON object members and duplicate Host, API-key, approval, approval-reference, Content-Length or Transfer-Encoding headers; raw socket/parser regressions |
| Cross-tenant leakage | Confidentiality breach | Multi-tenancy out of initial scope; no production multi-tenant claim |

## Residual risks

The localhost transport can be denied indefinitely, without credentials, by any process on the same host that keeps reopening slow connections, because connection slots are claimed before authentication. This is accepted only for single-user localhost development, and must be revisited before multi-user or non-localhost use. Local processing does not make model output correct or safe. Sensitivity detection can fail. A compromised host can observe local prompts. Cloud providers retain their own risks and terms. These limitations must remain visible in documentation and demonstrations.
