# Data sovereignty and local text controls

## ZESS-DS-001

Sensitive client data must remain within the client's approved infrastructure and jurisdiction. External processing is blocked by default. Any permitted release requires an approved destination, minimum necessary data, and auditable authorization.

This rule applies to prompts, attachments, responses, embeddings, databases, logs, backups, telemetry, administrative access, and support access. Client-approved private cloud may qualify, but local hardware or a "sovereign" router label alone does not establish sovereignty.

## Controls implemented in this alpha

- After authenticated request validation and before policy evaluation or provider execution, a bounded standard-library detector inspects `system`, `user`, and `assistant` text.
- It detects bounded patterns for email addresses; formatted phone and SSN-like values; card/account-like digit strings; labelled credentials and bearer tokens; complete or truncated private-key blocks; and optional exact confidential literals supplied by trusted server configuration.
- Overlapping matches are merged and irreversibly replaced with `[REDACTED]`. The original request is not mutated and no restoration dictionary is created.
- Any finding makes the request local-only. Redaction never authorizes cloud release. If no capable permitted local model exists, the request is blocked.
- Inspection failure or malformed inspection output fails closed before every provider call. Audit records remain metadata-only.
- Cloud approval binds the exact outgoing messages and output budget, the original request fingerprint, the redaction configuration/version fingerprint, and the existing actor, route, policy, and registry fields. Approvals remain expiring and single use.
- The loopback browser demonstration offers an authenticated preview that calls no model. It shows the exact redacted messages, finding count, local-only result, and—when cloud approval is possible—the exact outgoing messages.

The runtime performs no redactor network calls or telemetry and does not write inspected content to disk. Optional literals must come from trusted server configuration, not caller-controlled request fields.

## Important limitations

Pattern matching is incomplete. It misses many names, street and postal addresses, contextual business secrets, obfuscation, languages, and jurisdiction-specific identifiers. A result with zero findings does not establish clearance and must never be treated as permission for external release. Presidio may be evaluated later for broader detection, but is not a promise of comprehensive anonymisation.

Only message text is supported. PDF, image, spreadsheet, attachment, multimodal, tool, and streaming inspection are deferred and remain blocked by the interface. Visual PDF masking is not sufficient to remove underlying text, hidden layers, comments, attachments, or metadata.

These controls do not establish production data residency, jurisdictional enforcement, isolation, certification, or compliance. Production stacks still require approved endpoint and resolved-network controls, jurisdiction controls, tenant isolation, key and secret management, retention and deletion enforcement, backup governance, durable tamper-evident audit, administrative and support-access controls, incident response, and independently validated deployment configuration.

Grant drafting through an AI system and final submission to a grant authority are separate approval events. This project does not automatically submit grants or indiscriminately remove required application fields.

## Validation

All fixtures are synthetic. Run focused checks and then the authoritative suite:

```bash
python3 -m unittest tests.test_redaction -v
python3 scripts/run_adversarial_eval.py --output evals/results/adversarial-full.json
python3 scripts/run_adversarial_eval.py --sandbox-safe --output evals/results/adversarial-sandbox.json
python3 scripts/validate_release.py --regenerate
sh scripts/test.sh
```

Regeneration intentionally updates retained evidence. Review the diff and rerun the non-regenerating authoritative check before relying on it.
