# Secure Database architecture

## Purpose

Secure Database implements a durable persistence/security boundary described by
the source design set. It is deliberately narrower than the surrounding
platform.

## Ownership boundary

The component owns:

- PostgreSQL-backed durable state;
- migrations and persistence-local integrity rules;
- typed records for security and gateway-adjacent state;
- encryption and authenticated handling of protected fields;
- database-local audit and health records.

## Trust boundaries

1. **Application boundary.** Callers use typed APIs and receive typed records or
   explicit errors.
2. **Secret-broker boundary.** Database credentials and encryption operations
   are broker-mediated. The persistence layer does not copy the broker into
   the repository.
3. **PostgreSQL boundary.** PostgreSQL provides durable storage and relational
   constraints; connection protection and identity policy are established by
   the surrounding deployment.
4. **Protected-record boundary.** Sensitive fields are encrypted before
   persistence and decrypted only through an authorized operation.
5. **Authority boundary.** Stored evidence, runtime state, doctrine, ontology,
   and telemetry are not silently collapsed into one database truth.

## Storage model

The public extraction keeps operational records and higher-sensitivity records
logically distinct. A deployment may realize that distinction with separate
schemas, pools, roles, or database instances; the choice is explicit rather
than a hidden credential fallback.

The durable model covers the security/persistence concepts needed for
credentials, sessions, tickets, guard health, audit records, attestation
metadata, and optional proof material. Broader platform storage families are
outside this extraction.

## Protected values

Sensitive values are accepted in process memory only long enough to perform the
authorized broker-mediated encryption operation. The persisted representation
is versioned and authenticated. Plaintext and retired envelope formats are
rejected for protected fields.

Authenticated context binds each value to:

- a schema version;
- its logical table and field;
- a stable record identifier;
- a field-purpose domain.

This prevents valid ciphertext from being transplanted between records or
fields.

## Ticket lifecycle

Issuance persists the ticket lifecycle record while protecting sensitive
material. Verification performs explicit authorized recovery. Status and
lifecycle reads expose only the information appropriate to that operation.
Single-use and expiry state are durable facts, not caller-supplied hints.

## Optional integrations

Attestation, telemetry, proof systems, and provider-specific extensions are
separate integration surfaces. Their presence in the API does not imply that a
deployment has the required hardware, provider, or policy configuration.
