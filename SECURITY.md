# Security policy

## Scope

This repository contains a focused persistence/security extraction and its
public-neutral documentation. It is not a complete production deployment
configuration.

## Reporting

Report suspected vulnerabilities privately to the repository owner rather than
publishing exploit details. Include the affected version or commit, feature
configuration, a minimal disposable reproduction, and the confidentiality,
integrity, availability, or migration-safety impact.

Do not include live credentials, private keys, broker tokens, decrypted values,
production connection strings, private migrations, or internal deployment
identifiers in a report.

## Security expectations

- Prefer broker-mediated short-lived database access.
- Keep protected values encrypted before persistence.
- Treat static/bootstrap modes as explicit exceptions, never silent fallbacks.
- Use fresh disposable PostgreSQL state for behavioral proof.
- Do not log plaintext protected fields or secret-recovery material.
- Keep query metadata and reviewed source changes synchronized.
- Treat optional attestation, proof, and provider integrations as unavailable
  until their external prerequisites are empirically validated.

## Disclosure

No vulnerability disclosure timeline or security contact is asserted here
until the repository owner publishes one. No license is granted at this time;
all rights reserved.
