# Design sources and authority

This document records the source concepts read for the public Secure Database
documentation. The extraction is intentionally conceptual: it demonstrates
security and persistence ideas without publishing private migrations, complete
schemas, deployment topology, credentials, or runtime state.

## Authority interpretation

The source corpus distinguishes system authorities instead of treating one
database as the owner of every kind of truth. Evidence, doctrine, execution,
ontology, telemetry, and operator projections remain separate. This extraction
therefore represents only the durable persistence and security boundary.

The standalone repository is a focused extraction from that design family. It
is not identical to any private implementation and does not claim to be a
canonical replacement for one.

## Fifteen documents read to EOF

1. Authority matrix — separates evidence, blueprint, doctrine, runtime,
   ontology, telemetry, and projection authority.
2. Whole-system design draft — places persistence inside a shared runtime,
   execution, ontology, telemetry, and operator architecture.
3. Canonical architecture specification — defines ownership boundaries and
   prevents persistence from becoming runtime or doctrine authority.
4. Domain/runtime architecture report — defines shared runtime and
   domain-support relationships around durable state.
5. Database-layer design — describes PostgreSQL, broker-mediated credentials,
   protected values, attestation, proofs, and storage tiers.
6. Database security hardening plan — defines attested credential flow,
   hot-column AEAD, broker handles, zero-knowledge storage intent,
   segmentation, and operational guardrails.
7. Database security research — records the rationale for stronger in-use
   protection, broker-controlled keys, attestation, and verifiable storage.
8. Updated database hardening note — records the hardened PostgreSQL direction
   and removal of weaker legacy persistence paths.
9. PostgreSQL-only SQLx strategy — establishes query and metadata discipline.
10. Ticket-secret gateway plan — separates ticket lifecycle state from
    broker-controlled sensitive ticket material.
11. Ticket helper implementation plan — defines typed issue, redeem, status,
    expiry, validation, and telemetry operations.
12. Ticket-stack audit — records the required remote ticket-store boundary and
    identifies persistence/authentication gaps.
13. Hybrid onion/ticket implementation report — describes dual-onion lifecycle
    and the need for durable ticket integration.
14. Attestation-verification note — establishes attestation verification as an
    explicit trust decision rather than an implicit database property.
15. Four-tier storage architecture — places PostgreSQL among cache, graph, and
    analytical stores and limits what this extraction claims.

## Remaining related documents

The broader attestation, storage-validation, telemetry/ML, Armory, backup,
secret-broker, and historical audit documents were skimmed for consistency.
They refine adjacent deployment and analytical concerns but do not replace the
fifteen-document conceptual authority set above. They are not copied into the
public repository.

## Concept-to-extraction mapping

| Source concept | Representation here |
| --- | --- |
| PostgreSQL-first durable persistence | Present |
| Broker-mediated short-lived access | Present |
| Protected values and authenticated context binding | Present |
| Separation of operational and sensitive state | Present in reduced form |
| Ticket lifecycle versus secret recovery | Present in reduced form |
| Attestation as an explicit trust boundary | Present as an integration boundary |
| Full platform ontology, mission, Armory, and telemetry stores | Intentionally excluded |
| Private deployment, migrations, complete schemas, and credentials | Intentionally excluded |
| Provider-specific hardware proof | Not claimed |

The public contract is therefore a faithful representation of the selected
concepts, not a claim of full platform completeness or exact source identity.
