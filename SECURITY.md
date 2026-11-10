# Security Policy

Open Sovereign Router is an alpha development release, not a production security product or certified control. Do not use it with confidential, regulated, personal, client, or production data.

## Reporting

Use GitHub's private vulnerability reporting for this repository. Do not open a public issue for an undisclosed vulnerability. Do not include secrets, prompts, client content, credentials, or exploit data from systems you do not own.

## Supported versions

The current `0.1.x` alpha series receives best-effort security review. No production support commitment is made.

## Security posture

The candidate is localhost-only, cloud-disabled by example/default, approval-gated for enabled cloud routes, prompt-free in its audit schema, and fail-closed on required audit failure. See `docs/THREAT_MODEL.md` and `docs/SECURITY_EVALUATION.md` for tested controls and residual risks. Security findings block release until dispositioned; a passing test suite is not a security guarantee.
