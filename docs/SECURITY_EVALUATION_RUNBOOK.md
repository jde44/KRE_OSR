# Security Evaluation Runbook

## Preconditions

Use Python 3.10 or newer, no external network, synthetic fixtures only, and an external bytecode cache. Do not place credentials or real prompt content in fixtures.

## Sandbox-safe run

```bash
PYTHONPYCACHEPREFIX="${TMPDIR:-/tmp}/osr-adv" python3 scripts/run_adversarial_eval.py --sandbox-safe --output evals/results/adversarial-sandbox.json
```

Expected: process exit 0, no failures/errors, and summary `pass_with_environment_gaps` because socket classes are intentionally excluded. Review every per-evaluation `absent_tests` list.

## Full approved loopback run

Run only where localhost socket binding is approved:

```bash
PYTHONPYCACHEPREFIX="${TMPDIR:-/tmp}/osr-adv-full" python3 scripts/run_adversarial_eval.py --output evals/results/adversarial-full.json
```

Expected: process exit 0, summary `pass`, zero failures/errors, and no absent tests. A skip is acceptable only for the documented IPv6-loopback capability check; record it explicitly.

## Evidence review

1. Confirm `environment`, `raw_outcomes`, `evaluations` and `summary` are present.
2. Confirm every catalog evaluation has matched raw outcomes and no unexpected absence.
3. Search results and project files for secrets, private paths, prompt markers and tracebacks.
4. Run compile validation with an external bytecode cache.
5. Verify the project contains no `__pycache__` or `.pyc`.
6. Have the exact change and evidence set reviewed by someone other than its author; the author's own evidence is not sufficient.

Any fail/error blocks the evaluation. Reproduce the defect, add a failing regression, implement the smallest correction, rerun all applicable evaluations, disclose the finding in the evaluation record, and request an independent review.
