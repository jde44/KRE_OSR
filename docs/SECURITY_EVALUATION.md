# Security and Adversarial Evaluation

Status: all evaluation groups pass in the full loopback run recorded in `evals/results/adversarial-full.json`, which is regenerated for each release candidate. This is a development evaluation, not a certification.

## Evaluation contract

The machine-readable source of truth is `evals/adversarial_catalog.json`. Each evaluation records its purpose, threshold, owner, due point, evidence and required remediation. The deterministic stdlib runner emits environment and Python versions, every raw unittest outcome, per-evaluation mappings and a summary to `evals/results/`.

The release threshold is all applicable evaluations passing, zero unauthorized provider calls, and zero prompt/secret reflection in checked errors or audit paths. A sandbox result may be `pass_with_environment_gaps`; that is not sufficient until the excluded loopback tests pass in an environment that permits loopback binding.

## Coverage

The catalog covers authentication bypass and timing-shaped inputs; actor/sensitivity/provider spoofing; approval forgery, replay, tampering, races and expiry; pending-store exhaustion and restore edges; malformed, deeply nested, nonfinite, duplicate and oversized inputs; Host, Content-Length and Transfer-Encoding ambiguity; slow-drip and connection exhaustion; audit failure, log injection and prompt leakage; provider exceptions, model substitution, output bounds and elapsed timeout; silent fallback; request-ID/error leakage; and Unicode/control/instruction-override strings treated as opaque message data.

## Finding and remediation

The evaluation found one parsing ambiguity: duplicate JSON members and duplicate security-relevant HTTP headers were not explicitly rejected. Test-first evidence began with an import/test failure because duplicate rejection did not exist. The transport now rejects duplicate JSON object members and duplicate Host, API-key, approval, approval-reference, Content-Length or Transfer-Encoding headers. Regression tests cover the JSON parser and raw loopback requests. No control was weakened.

## Current evidence

- Full loopback result: `evals/results/adversarial-full.json`. Sandbox-safe result (loopback groups explicitly excluded): `evals/results/adversarial-sandbox.json`.
- Each result records the Python version and platform, every raw test outcome, per-evaluation mappings, mapped-versus-total counts, and the SHA-256 of the catalog and of the source and tests it ran against. `scripts/test.sh` fails if either result does not match the current catalog and source, so stale evidence cannot pass.
- Gates: a full run succeeds only with no absent or failing evaluation group, no mapping gap, no failure or error, and no skip other than the explicitly allowlisted IPv6 capability test. Runner self-tests cover these gates. Raw loopback cases include duplicate approval, approval-request-ID, Transfer-Encoding and differing duplicate Content-Length headers, each with zero provider calls.
- Results are synthetic and contain no real prompts, secrets, client data or external network traffic.

## Residuals

The accepted single-user localhost pre-authentication reconnection lockout remains. Provider elapsed timeout is detected after return and is not preemptive. Durable multi-process approval/replay state, outbound DNS/TLS pinning, secret lifecycle and tamper-evident production audit remain later gates. These residuals prevent production-readiness claims.
