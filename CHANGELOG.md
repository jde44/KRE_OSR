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

## Earlier development

- Deterministic adversarial evaluation and duplicate-input hardening.
- Local-first policy, authenticated localhost transport, explicit cloud approval, provider interface and prompt-free audit.
- Scaffold, provenance discipline and security core.
