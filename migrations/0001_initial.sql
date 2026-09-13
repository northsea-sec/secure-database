-- Canonical final-state schema for the standalone secure database.
BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA gateway_data;
CREATE SCHEMA gateway_secrets;
CREATE SCHEMA database_extensions;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA gateway_data FROM PUBLIC;
REVOKE CREATE ON SCHEMA gateway_secrets FROM PUBLIC;
REVOKE CREATE ON SCHEMA database_extensions FROM PUBLIC;

GRANT USAGE, CREATE ON SCHEMA gateway_data TO CURRENT_USER;
GRANT USAGE, CREATE ON SCHEMA gateway_secrets TO CURRENT_USER;
GRANT USAGE, CREATE ON SCHEMA database_extensions TO CURRENT_USER;

ALTER DEFAULT PRIVILEGES IN SCHEMA gateway_data REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA gateway_secrets REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA gateway_data GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO CURRENT_USER;
ALTER DEFAULT PRIVILEGES IN SCHEMA gateway_secrets GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO CURRENT_USER;

CREATE FUNCTION database_extensions.touch_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE database_extensions.extension_allowlist (
    name TEXT PRIMARY KEY
);

INSERT INTO database_extensions.extension_allowlist (name) VALUES
    ('plpgsql'),
    ('pgcrypto');

CREATE TABLE gateway_data.tor_connect_audits (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, occurred_at)
);
CREATE INDEX idx_tor_connect_audits_user
    ON gateway_data.tor_connect_audits (user_id, occurred_at DESC);

CREATE TABLE gateway_data.guard_health (
    guard_fpr TEXT PRIMARY KEY,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_ok TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    fail_count INTEGER NOT NULL DEFAULT 0,
    uptime_ratio DOUBLE PRECISION,
    asn BIGINT,
    rpki_valid BOOLEAN,
    pow_score DOUBLE PRECISION,
    rtt_p50_ms DOUBLE PRECISION,
    rtt_p95_ms DOUBLE PRECISION,
    tee_capable BOOLEAN NOT NULL DEFAULT FALSE,
    tee_label TEXT,
    tee_policy TEXT,
    tee_verified_at TIMESTAMPTZ
);
CREATE INDEX idx_guard_health_routing ON gateway_data.guard_health (asn, rpki_valid);
CREATE INDEX idx_guard_health_last_ok ON gateway_data.guard_health (last_ok DESC);

CREATE TABLE gateway_secrets.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    operation TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    payload_cipher BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_hash TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_audit_logs_user ON gateway_secrets.audit_logs (user_id, created_at DESC);

CREATE TABLE gateway_secrets.zk_proofs (
    id UUID NOT NULL,
    user_id UUID NOT NULL,
    protocol TEXT NOT NULL,
    circuit TEXT NOT NULL,
    circuit_security SMALLINT NOT NULL,
    expected_hash TEXT NOT NULL,
    public_inputs JSONB NOT NULL,
    proof BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    PRIMARY KEY (id, user_id)
);
CREATE INDEX idx_zk_proofs_user ON gateway_secrets.zk_proofs (user_id, created_at DESC);
CREATE INDEX idx_zk_proofs_protocol ON gateway_secrets.zk_proofs (protocol, verified);

CREATE TABLE gateway_secrets.tee_attestations (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    app_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    compose_hash TEXT NOT NULL,
    key_provider_info TEXT NOT NULL,
    quote BYTEA NOT NULL,
    rtmr JSONB NOT NULL,
    event_log JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, user_id)
);
CREATE INDEX idx_tee_attestations_user
    ON gateway_secrets.tee_attestations (user_id, recorded_at DESC);

CREATE TABLE gateway_secrets.tor_auth_credentials (
    id UUID PRIMARY KEY,
    onion_entry TEXT NOT NULL UNIQUE,
    tier TEXT NOT NULL,
    credential_hash TEXT NOT NULL,
    operational_onion TEXT,
    guard_nodes TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    rate_limit_per_minute INTEGER NOT NULL DEFAULT 30,
    last_rotated_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_tor_auth_credentials_disabled
    ON gateway_secrets.tor_auth_credentials (disabled);
CREATE TRIGGER trg_tor_auth_credentials_touch
BEFORE UPDATE ON gateway_secrets.tor_auth_credentials
FOR EACH ROW EXECUTE FUNCTION database_extensions.touch_updated_at();

CREATE TABLE gateway_secrets.tor_auth_sessions (
    id UUID PRIMARY KEY,
    credential_id UUID NOT NULL REFERENCES gateway_secrets.tor_auth_credentials(id) ON DELETE CASCADE,
    session_key UUID NOT NULL,
    circuit_id TEXT,
    fingerprint TEXT,
    guard_nodes TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    client_onion TEXT,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_tor_auth_sessions_credential_time
    ON gateway_secrets.tor_auth_sessions (credential_id, issued_at DESC);
CREATE INDEX idx_tor_auth_sessions_expires_at
    ON gateway_secrets.tor_auth_sessions (expires_at);

CREATE TABLE gateway_secrets.tor_access_tickets (
    id UUID PRIMARY KEY,
    credential_id UUID NOT NULL REFERENCES gateway_secrets.tor_auth_credentials(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    entry_onion TEXT NOT NULL,
    client_fingerprint TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    redeemed_at TIMESTAMPTZ,
    redeemed_operational_onion TEXT,
    client_auth_public_key TEXT NOT NULL,
    client_auth_secret_path TEXT NOT NULL,
    client_auth_secret_redeem_token TEXT,
    attestation_session_id UUID NOT NULL,
    attestation_nonce_digest TEXT NOT NULL,
    attestation_quote_hash TEXT NOT NULL,
    attested_at TIMESTAMPTZ NOT NULL,
    tee_kind TEXT NOT NULL,
    tee_label TEXT,
    tee_policy TEXT,
    tls_pubkey_digest TEXT NOT NULL
);
CREATE INDEX idx_tor_access_tickets_credential
    ON gateway_secrets.tor_access_tickets (credential_id, created_at DESC);
CREATE INDEX idx_tor_access_tickets_expires_at
    ON gateway_secrets.tor_access_tickets (expires_at);
CREATE UNIQUE INDEX idx_tor_access_tickets_attestation_session
    ON gateway_secrets.tor_access_tickets (attestation_session_id)
    WHERE attestation_session_id <> '00000000-0000-0000-0000-000000000000'::uuid;

CREATE TABLE gateway_secrets.ra_nonce_log (
    nonce_digest BYTEA PRIMARY KEY,
    enclave_id TEXT NOT NULL,
    seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_ra_nonce_seen_at ON gateway_secrets.ra_nonce_log (seen_at);

CREATE TABLE gateway_secrets.ra_attestation_cache (
    quote_hash BYTEA PRIMARY KEY,
    tee TEXT NOT NULL,
    decision JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_ra_attestation_cache_expires_at
    ON gateway_secrets.ra_attestation_cache (expires_at);

COMMIT;
