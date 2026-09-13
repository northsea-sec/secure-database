# Secure Database

Secure Database is a public-neutral Rust extraction of database and security
concepts from a larger private system-design corpus.

It represents a focused persistence boundary:

- PostgreSQL-first durable storage;
- broker-mediated database access rather than long-lived application-held
  credentials;
- encrypted handling of sensitive values before persistence;
- authenticated, context-bound protected records;
- typed persistence for credential, session, ticket, guard, audit, and
  attestation-related state;
- explicit separation between persistence, secret brokering, transport, and
  application orchestration.

This repository is a conceptual and behavioral extraction of the
security/persistence slice of a larger universe.

## Design boundary

The database is a governed persistence component. It stores durable state and
enforces storage-local integrity rules; it does not decide mission policy,
execute network actions, issue transport identities, or replace the Secret
Broker. Sensitive material is handed across those boundaries only through
typed, authorized operations.

Protected values are represented as authenticated envelopes. Their
authenticated context includes the record identity, protected field, schema
version, and field purpose. A ciphertext copied to another record or protected
field therefore does not become valid in its new context.

The extraction also preserves the design distinction between ticket lifecycle
state and recovery of sensitive ticket material. Status and lifecycle
operations do not implicitly grant secret-recovery authority.

## Evidence

The extraction has been exercised against fresh disposable PostgreSQL state and
a disposable broker test path. The behavioral proof covers migration,
ciphertext-at-rest, authorized recovery, plaintext rejection, context-binding
failure on ciphertext reuse, and locked offline compilation.

Those results validate this extraction's local behavior. They are not claims
about private deployments, hardware attestation providers, or production
readiness of optional integrations.

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — the conceptual boundary and trust
  model.
- [Operations](docs/OPERATIONS.md) — the public-neutral proof and maintenance
  model.
- [Design sources](docs/DESIGN_SOURCES.md) — the source concepts read in full
  and the concepts derived from them.
- [Security](SECURITY.md) — disclosure and handling guidance.

No private credentials, internal runtime state, sensitive migration history, or
complete source schema is published here.

## License

No license is granted at this time. All rights reserved.
