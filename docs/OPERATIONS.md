# Secure Database operations

## Operating principle

Use fresh disposable state for development and proof. Do not use production,
shared development, or inherited runtime state as a behavioral test fixture.

The normal security path obtains short-lived database access through the
Secret Broker. Any static or local bootstrap path must be an explicit,
reviewable exception; it must never be selected silently when broker access
fails.

## Proof workflow

A meaningful proof should demonstrate, at minimum:

1. a clean database can be initialized from the reviewed persistence baseline;
2. sensitive values are ciphertext at rest;
3. an authorized read recovers the original logical value;
4. ordinary plaintext is rejected for protected fields;
5. a ciphertext copied to another record or field fails authenticated
   validation;
6. restart and reconnect do not depend on stale in-memory state;
7. locked offline compilation succeeds with the checked-in query metadata.

Record the toolchain, database version, broker mode, feature set, commands, and
exit statuses. Redact credentials, client identities, broker tokens, URLs, and
secret values from evidence.

## SQL and schema maintenance

The crate is PostgreSQL-specific. Query metadata and migration state must stay
in sync with reviewed source changes. Prepare metadata only against disposable
PostgreSQL state, review generated changes, and run the repository's locked
offline check before publication.

Do not publish private migration history, complete internal schemas, role names,
deployment manifests, or database topology. Public documentation should state
the invariant being proven rather than reproduce the private implementation.

## Secret handling

Never place secret plaintext in command arguments, source files, shell history,
logs, or evidence bundles. Broker handles and encrypted envelopes are still
sensitive. Observability must record operation type and outcome without
recording decrypted values, private keys, authorization material, or complete
connection strings.

## Failure handling

Invalid configuration, unavailable broker authorization, malformed protected
values, failed authentication, expired records, and unavailable optional
integrations are explicit failures. The system must not silently switch to a
weaker credential source, alternate persistence path, or simulated success.
