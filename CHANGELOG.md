# Changelog

All notable changes are recorded here.

## 0.1.0 — 2026-11-10

- Added offline setup/test/demo commands and localhost fake-provider demonstration.
- Added deterministic synthetic routing/economic benchmark and raw evidence.
- Added exact classified candidate manifest, SPDX 2.3 SBOM, and release scans.
- Added security, contribution, conduct, governance, maintainer, reproducibility, and release-readiness documentation.
- Private development records are excluded from the hashed manifest through a private-path list, so changes to them do not stale the evidence; build artifacts are ignored.
- Adopted Apache License 2.0 with KRE SOLUTION ENGINEERING LLC copyright and notice.
- Evidence-integrity hardening: `test.sh` verifies committed evidence instead of regenerating it; whole-manifest verification with null self-size; symlink rejection; build outputs ignored only at their real locations; wider secret, path and email scanning with positive fixtures; conformant SBOM (`filesAnalyzed` false); a dependency-lock declaration; and benchmark economics restricted to completed non-sensitive work, with an approved-cloud task.

- Release-candidate controls: adversarial results must match the current source and catalog; an allowlisted export that refuses on scan findings, stale evidence or a missing private list; private development records excluded from the candidate.

## Unreleased

- Added a local-only browser demo for reviewers (`./scripts/demo_ui.sh`, `docs/DEMO_UI.md`). A standard-library adapter bound to loopback forwards synthetic requests to the existing authenticated transport with `FakeProvider`, and the page renders the router's decision, explanation, single-request approval flow, labelled estimates and prompt-free audit. Per-launch UI token, Host check, strict CSP, bounded input, no external requests. No change to the routing policy, approvals, transport or audit.
- Added `tests/test_demo_ui.py` (standard library) and an optional Playwright browser check (`scripts/demo_ui/e2e_check.py`); Playwright is recorded as an optional developer tool in `release/dependency-lock.json` and is not a runtime or test dependency.

## Earlier development

- Deterministic adversarial evaluation and duplicate-input hardening.
- Local-first policy, authenticated localhost transport, explicit cloud approval, provider interface and prompt-free audit.
- Scaffold, provenance discipline and security core.
