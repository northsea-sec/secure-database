use chrono::{DateTime, Utc};
use tracing::debug;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    aes_decrypt_with_aad, aes_encrypt_with_aad, decode_aead_payload, encode_aead_payload,
    is_aead_payload, is_aead_payload_v2, secret_broker_client::SecretBrokerClient, DatabaseError,
    DbResult, PgPool,
};

use broker_protocol_client::{MintAeadKeyV2Params, SecretLifecycle};

const CLIENT_ONION_AAD: &[u8] = b"tor-session-client-onion";
const REDEEMED_ONION_AAD: &[u8] = b"tor-ticket-redeemed-onion";
pub const TICKET_CLIENT_PUBLIC_KEY_AAD: &[u8] = b"tor-ticket-client-auth-public-key";
pub const TICKET_CLIENT_SECRET_PATH_AAD: &[u8] = b"tor-ticket-client-auth-secret-path";
pub const TICKET_CLIENT_SECRET_REDEEM_TOKEN_AAD: &[u8] =
    b"tor-ticket-client-auth-secret-redeem-token";
pub const TICKET_ATTESTATION_NONCE_AAD: &[u8] = b"tor-ticket-attestation-nonce";
pub const TICKET_ATTESTATION_QUOTE_AAD: &[u8] = b"tor-ticket-attestation-quote";
pub const TICKET_TLS_PUBKEY_DIGEST_AAD: &[u8] = b"tor-ticket-tls-pubkey-digest";
const AEAD_KEY_TTL_SECONDS: u64 = 900;

/// Representation of a stored Tor credential.
#[derive(Debug, Clone)]
pub struct TorCredential {
    pub id: Uuid,
    pub onion_entry: String,
    pub tier: String,
    pub credential_hash: String,
    pub operational_onion: Option<String>,
    pub guard_nodes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub disabled: bool,
    pub rate_limit_per_minute: i32,
    pub last_rotated_at: Option<DateTime<Utc>>,
}

/// Session record used to persist successful authentications.
#[derive(Debug, Clone)]
pub struct TorSessionRecord {
    pub id: Uuid,
    pub credential_id: Uuid,
    pub circuit_id: Option<String>,
    pub fingerprint: Option<String>,
    pub guard_nodes: Vec<String>,
    pub client_onion: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct TorCredentialRow {
    id: Uuid,
    onion_entry: String,
    tier: String,
    credential_hash: String,
    operational_onion: Option<String>,
    guard_nodes: Option<Vec<String>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    disabled: bool,
    rate_limit_per_minute: i32,
    last_rotated_at: Option<DateTime<Utc>>,
}

impl From<TorCredentialRow> for TorCredential {
    fn from(row: TorCredentialRow) -> Self {
        Self {
            id: row.id,
            onion_entry: row.onion_entry,
            tier: row.tier,
            credential_hash: row.credential_hash,
            operational_onion: row.operational_onion,
            guard_nodes: row.guard_nodes.unwrap_or_default(),
            created_at: row.created_at,
            updated_at: row.updated_at,
            expires_at: row.expires_at,
            disabled: row.disabled,
            rate_limit_per_minute: row.rate_limit_per_minute,
            last_rotated_at: row.last_rotated_at,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IssuedTorAccessTicket {
    pub id: Uuid,
    pub credential_id: Uuid,
    pub entry_onion: String,
    pub client_fingerprint: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub redeemed_at: Option<DateTime<Utc>>,
    pub redeemed_operational_onion: Option<String>,
    pub client_auth_public_key: String,
    pub client_auth_secret_path: String,
    pub client_auth_secret_redeem_token: Option<String>,
    pub attestation_session_id: Uuid,
    pub attestation_nonce_digest: String,
    pub attestation_quote_hash: String,
    pub attested_at: DateTime<Utc>,
    pub tee_kind: String,
    pub tee_label: Option<String>,
    pub tee_policy: Option<String>,
    pub tls_pubkey_digest: String,
}

#[derive(Debug, Clone)]
pub struct TicketVerificationRecord {
    pub id: Uuid,
    pub credential_id: Uuid,
    pub token_hash: String,
    pub client_fingerprint: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub redeemed_at: Option<DateTime<Utc>>,
    pub client_auth_public_key: String,
    pub client_auth_secret_path: String,
    pub client_auth_secret_redeem_token: Option<String>,
    pub attestation_session_id: Uuid,
    pub attestation_nonce_digest: String,
    pub attestation_quote_hash: String,
    pub attested_at: DateTime<Utc>,
    pub tee_kind: String,
    pub tee_label: Option<String>,
    pub tee_policy: Option<String>,
    pub tls_pubkey_digest: String,
}

#[derive(Debug, Clone)]
pub struct TicketStatusRecord {
    pub id: Uuid,
    pub credential_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub redeemed_at: Option<DateTime<Utc>>,
}

pub struct NewTorAccessTicket {
    pub id: Uuid,
    pub credential_id: Uuid,
    pub entry_onion: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub client_fingerprint: Option<String>,
    pub client_auth_public_key: String,
    pub client_auth_secret_path: String,
    pub client_auth_secret_redeem_token: Option<String>,
    pub attestation_session_id: Uuid,
    pub attestation_nonce_digest: String,
    pub attestation_quote_hash: String,
    pub attested_at: DateTime<Utc>,
    pub tee_kind: String,
    pub tee_label: Option<String>,
    pub tee_policy: Option<String>,
    pub tls_pubkey_digest: String,
}

#[derive(sqlx::FromRow)]
struct IssuedTorAccessTicketRow {
    id: Uuid,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct TicketVerificationRow {
    id: Uuid,
    credential_id: Uuid,
    token_hash: String,
    client_fingerprint: Option<String>,
    expires_at: DateTime<Utc>,
    redeemed_at: Option<DateTime<Utc>>,
    client_auth_public_key: String,
    client_auth_secret_path: String,
    client_auth_secret_redeem_token: Option<String>,
    attestation_session_id: Uuid,
    attestation_nonce_digest: String,
    attestation_quote_hash: String,
    attested_at: DateTime<Utc>,
    tee_kind: String,
    tee_label: Option<String>,
    tee_policy: Option<String>,
    tls_pubkey_digest: String,
}

#[derive(sqlx::FromRow)]
struct TicketStatusRow {
    id: Uuid,
    credential_id: Uuid,
    expires_at: DateTime<Utc>,
    redeemed_at: Option<DateTime<Utc>>,
}

impl PgPool {
    /// Fetch a Tor credential by its entry onion.
    pub async fn fetch_tor_credential(&self, onion_entry: &str) -> DbResult<Option<TorCredential>> {
        let record = sqlx::query_as!(
            TorCredentialRow,
            r#"SELECT id, onion_entry, tier, credential_hash, operational_onion, guard_nodes,
                       created_at, updated_at, expires_at, disabled, rate_limit_per_minute,
                       last_rotated_at
                FROM gateway_secrets.tor_auth_credentials
                WHERE onion_entry = $1"#,
            onion_entry
        )
        .fetch_optional(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;

        Ok(record.map(Into::into))
    }

    /// Fetch a Tor credential by its identifier.
    pub async fn fetch_tor_credential_by_id(
        &self,
        credential_id: Uuid,
    ) -> DbResult<Option<TorCredential>> {
        let record = sqlx::query_as!(
            TorCredentialRow,
            r#"SELECT id, onion_entry, tier, credential_hash, operational_onion, guard_nodes,
                       created_at, updated_at, expires_at, disabled, rate_limit_per_minute,
                       last_rotated_at
                FROM gateway_secrets.tor_auth_credentials
                WHERE id = $1"#,
            credential_id
        )
        .fetch_optional(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;

        Ok(record.map(Into::into))
    }

    /// Persist a Tor session record.
    pub async fn record_tor_session(
        &self,
        client: &SecretBrokerClient,
        session: TorSessionRecord,
    ) -> DbResult<()> {
        let TorSessionRecord {
            id,
            credential_id,
            circuit_id,
            fingerprint,
            guard_nodes,
            client_onion,
            expires_at,
        } = session;

        let guard_nodes_db = guard_nodes.to_vec();

        let client_onion_aad = record_bound_aad(
            "gateway_secrets.tor_auth_sessions",
            "client_onion",
            id,
            CLIENT_ONION_AAD,
        );
        let client_onion_db = ensure_aead_encrypted(
            client,
            client_onion.as_deref(),
            &client_onion_aad,
            "tor-session-client-onion",
        )
        .await?;

        sqlx::query!(
            r#"INSERT INTO gateway_secrets.tor_auth_sessions (
                    id, credential_id, session_key, circuit_id, fingerprint, guard_nodes,
                    client_onion, expires_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
            id,
            credential_id,
            Uuid::new_v4(),
            circuit_id,
            fingerprint,
            guard_nodes_db.as_slice(),
            client_onion_db,
            expires_at
        )
        .execute(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;
        Ok(())
    }

    /// Count the number of sessions issued within the provided window (seconds).
    pub async fn count_recent_sessions(
        &self,
        credential_id: Uuid,
        window_seconds: i64,
    ) -> DbResult<i64> {
        let record = sqlx::query!(
            r#"SELECT COUNT(*) AS count
                FROM gateway_secrets.tor_auth_sessions
                WHERE credential_id = $1
                  AND issued_at >= NOW() - ($2 * INTERVAL '1 second')"#,
            credential_id,
            window_seconds as f64
        )
        .fetch_one(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;

        Ok(record.count.unwrap_or(0))
    }

    /// Count active sessions (optionally respecting expiry).
    pub async fn count_active_sessions(&self) -> DbResult<i64> {
        let record = sqlx::query!(
            r#"SELECT COUNT(*) AS count
                FROM gateway_secrets.tor_auth_sessions
                WHERE expires_at IS NULL OR expires_at > NOW()"#
        )
        .fetch_one(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;

        Ok(record.count.unwrap_or(0))
    }

    /// Count all persisted sessions.
    pub async fn count_total_sessions(&self) -> DbResult<i64> {
        let record =
            sqlx::query!(r#"SELECT COUNT(*) AS count FROM gateway_secrets.tor_auth_sessions"#)
                .fetch_one(self.secrets().as_ref())
                .await
                .map_err(DatabaseError::from)?;

        Ok(record.count.unwrap_or(0))
    }

    /// Count credentials that are not disabled.
    pub async fn count_active_credentials(&self) -> DbResult<i64> {
        let record = sqlx::query!(
            r#"SELECT COUNT(*) AS count
                FROM gateway_secrets.tor_auth_credentials
                WHERE disabled = FALSE"#
        )
        .fetch_one(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;

        Ok(record.count.unwrap_or(0))
    }

    /// Update the operational onion and guard metadata for a credential.
    pub async fn rotate_operational_onion(
        &self,
        credential_id: Uuid,
        new_onion: &str,
        guard_nodes: &[String],
    ) -> DbResult<()> {
        sqlx::query!(
            r#"UPDATE gateway_secrets.tor_auth_credentials
                SET operational_onion = $2,
                    guard_nodes = $3,
                    last_rotated_at = NOW(),
                    updated_at = NOW()
                WHERE id = $1"#,
            credential_id,
            new_onion,
            guard_nodes
        )
        .execute(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;
        Ok(())
    }

    /// Persist a new entry onion for the provided credential identifier.
    pub async fn set_entry_onion(
        &self,
        credential_id: Uuid,
        entry_onion: &str,
        guard_nodes: &[String],
    ) -> DbResult<()> {
        sqlx::query!(
            r#"UPDATE gateway_secrets.tor_auth_credentials
                SET onion_entry = $2,
                    guard_nodes = $3,
                    updated_at = NOW()
                WHERE id = $1"#,
            credential_id,
            entry_onion,
            guard_nodes
        )
        .execute(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;

        Ok(())
    }

    /// Import or replace the bootstrap credential row for a tenant-local entry onion.
    pub async fn import_bootstrap_tor_credential(
        &self,
        credential_id: Uuid,
        entry_onion: &str,
        credential_hash: &str,
        tier: &str,
        rate_limit_per_minute: i32,
        expires_at: Option<DateTime<Utc>>,
        guard_nodes: &[String],
    ) -> DbResult<TorCredential> {
        let now = Utc::now();
        let guard_nodes_db = guard_nodes.to_vec();

        sqlx::query(
            r#"INSERT INTO gateway_secrets.tor_auth_credentials
                (id, onion_entry, tier, credential_hash, guard_nodes,
                 rate_limit_per_minute, expires_at, created_at, updated_at, disabled)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, FALSE)
            ON CONFLICT (id) DO UPDATE
                SET onion_entry = EXCLUDED.onion_entry,
                    tier = EXCLUDED.tier,
                    credential_hash = EXCLUDED.credential_hash,
                    guard_nodes = EXCLUDED.guard_nodes,
                    rate_limit_per_minute = EXCLUDED.rate_limit_per_minute,
                    expires_at = EXCLUDED.expires_at,
                    updated_at = NOW(),
                    disabled = FALSE"#,
        )
        .bind(credential_id)
        .bind(entry_onion.trim())
        .bind(tier)
        .bind(credential_hash)
        .bind(guard_nodes_db.as_slice())
        .bind(rate_limit_per_minute)
        .bind(expires_at)
        .bind(now)
        .execute(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;

        Ok(TorCredential {
            id: credential_id,
            onion_entry: entry_onion.trim().to_string(),
            tier: tier.to_string(),
            credential_hash: credential_hash.to_string(),
            operational_onion: None,
            guard_nodes: guard_nodes.to_vec(),
            created_at: now,
            updated_at: now,
            expires_at,
            disabled: false,
            rate_limit_per_minute,
            last_rotated_at: None,
        })
    }

    /// Create a new Tor credential with a pre-hashed key.
    pub async fn create_tor_credential(
        &self,
        entry_onion: &str,
        credential_hash: &str,
        tier: &str,
        rate_limit_per_minute: i32,
        expires_at: Option<DateTime<Utc>>,
        guard_nodes: &[String],
    ) -> DbResult<TorCredential> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let guard_nodes_db = guard_nodes.to_vec();

        sqlx::query(
            r#"INSERT INTO gateway_secrets.tor_auth_credentials
                (id, onion_entry, tier, credential_hash, guard_nodes,
                 rate_limit_per_minute, expires_at, created_at, updated_at, disabled)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, FALSE)"#,
        )
        .bind(id)
        .bind(entry_onion.trim())
        .bind(tier)
        .bind(credential_hash)
        .bind(guard_nodes_db.as_slice())
        .bind(rate_limit_per_minute)
        .bind(expires_at)
        .bind(now)
        .execute(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;

        Ok(TorCredential {
            id,
            onion_entry: entry_onion.trim().to_string(),
            tier: tier.to_string(),
            credential_hash: credential_hash.to_string(),
            operational_onion: None,
            guard_nodes: guard_nodes.to_vec(),
            created_at: now,
            updated_at: now,
            expires_at,
            disabled: false,
            rate_limit_per_minute,
            last_rotated_at: None,
        })
    }

    /// Fetch a bounded list of Tor credentials for observability/admin workflows.
    pub async fn list_tor_credentials(&self, limit: i64) -> DbResult<Vec<TorCredential>> {
        let capped_limit = if limit <= 0 { 100 } else { limit.min(1_000) };
        let records = sqlx::query_as!(
            TorCredentialRow,
            r#"SELECT id, onion_entry, tier, credential_hash, operational_onion, guard_nodes,
                       created_at, updated_at, expires_at, disabled, rate_limit_per_minute,
                       last_rotated_at
                FROM gateway_secrets.tor_auth_credentials
                ORDER BY created_at ASC
                LIMIT $1"#,
            capped_limit
        )
        .fetch_all(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;

        Ok(records.into_iter().map(Into::into).collect())
    }

    pub async fn update_tor_credential_disabled(
        &self,
        id: uuid::Uuid,
        disabled: bool,
    ) -> DbResult<()> {
        sqlx::query(
            r#"UPDATE gateway_secrets.tor_auth_credentials SET disabled = $2, updated_at = NOW() WHERE id = $1"#,
        )
        .bind(id)
        .bind(disabled)
        .execute(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;
        Ok(())
    }

    pub async fn delete_tor_credential(&self, id: uuid::Uuid) -> DbResult<bool> {
        let result =
            sqlx::query(r#"DELETE FROM gateway_secrets.tor_auth_credentials WHERE id = $1"#)
                .bind(id)
                .execute(self.secrets().as_ref())
                .await
                .map_err(DatabaseError::from)?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn issue_tor_ticket(
        &self,
        client: &SecretBrokerClient,
        ticket: NewTorAccessTicket,
    ) -> DbResult<IssuedTorAccessTicket> {
        let NewTorAccessTicket {
            id,
            credential_id,
            entry_onion,
            token_hash,
            expires_at,
            client_fingerprint,
            client_auth_public_key,
            client_auth_secret_path,
            client_auth_secret_redeem_token,
            attestation_session_id,
            attestation_nonce_digest,
            attestation_quote_hash,
            attested_at,
            tee_kind,
            tee_label,
            tee_policy,
            tls_pubkey_digest,
        } = ticket;
        debug!(ticket_id = %id, %credential_id, "secure-database: issue_tor_ticket start");

        let client_auth_public_key_aad = record_bound_aad(
            "gateway_secrets.tor_access_tickets",
            "client_auth_public_key",
            id,
            TICKET_CLIENT_PUBLIC_KEY_AAD,
        );
        let client_auth_public_key_db = ensure_aead_encrypted_required(
            client,
            &client_auth_public_key,
            &client_auth_public_key_aad,
            "tor-ticket-client-auth-public-key",
            "client_auth_public_key",
        )
        .await?;
        debug!(ticket_id = %id, "secure-database: encrypted client_auth_public_key");
        let client_auth_secret_path_aad = record_bound_aad(
            "gateway_secrets.tor_access_tickets",
            "client_auth_secret_path",
            id,
            TICKET_CLIENT_SECRET_PATH_AAD,
        );
        let client_auth_secret_path_db = ensure_aead_encrypted_required(
            client,
            &client_auth_secret_path,
            &client_auth_secret_path_aad,
            "tor-ticket-client-auth-secret-path",
            "client_auth_secret_path",
        )
        .await?;
        debug!(ticket_id = %id, "secure-database: encrypted client_auth_secret_path");
        let attestation_nonce_digest_aad = record_bound_aad(
            "gateway_secrets.tor_access_tickets",
            "attestation_nonce_digest",
            id,
            TICKET_ATTESTATION_NONCE_AAD,
        );
        let attestation_nonce_digest_db = ensure_aead_encrypted_required(
            client,
            &attestation_nonce_digest,
            &attestation_nonce_digest_aad,
            "tor-ticket-attestation-nonce",
            "attestation_nonce_digest",
        )
        .await?;
        debug!(ticket_id = %id, "secure-database: encrypted attestation_nonce_digest");
        let attestation_quote_hash_aad = record_bound_aad(
            "gateway_secrets.tor_access_tickets",
            "attestation_quote_hash",
            id,
            TICKET_ATTESTATION_QUOTE_AAD,
        );
        let attestation_quote_hash_db = ensure_aead_encrypted_required(
            client,
            &attestation_quote_hash,
            &attestation_quote_hash_aad,
            "tor-ticket-attestation-quote",
            "attestation_quote_hash",
        )
        .await?;
        debug!(ticket_id = %id, "secure-database: encrypted attestation_quote_hash");
        let client_auth_secret_redeem_token_aad = record_bound_aad(
            "gateway_secrets.tor_access_tickets",
            "client_auth_secret_redeem_token",
            id,
            TICKET_CLIENT_SECRET_REDEEM_TOKEN_AAD,
        );
        let client_auth_secret_redeem_token_db = ensure_aead_encrypted(
            client,
            client_auth_secret_redeem_token.as_deref(),
            &client_auth_secret_redeem_token_aad,
            "tor-ticket-client-auth-secret-redeem-token",
        )
        .await?;
        let tls_pubkey_digest_aad = record_bound_aad(
            "gateway_secrets.tor_access_tickets",
            "tls_pubkey_digest",
            id,
            TICKET_TLS_PUBKEY_DIGEST_AAD,
        );
        let tls_pubkey_digest_db = ensure_aead_encrypted_required(
            client,
            &tls_pubkey_digest,
            &tls_pubkey_digest_aad,
            "tor-ticket-tls-pubkey-digest",
            "tls_pubkey_digest",
        )
        .await?;
        debug!(ticket_id = %id, "secure-database: encrypted tls_pubkey_digest");

        let record = sqlx::query_as::<_, IssuedTorAccessTicketRow>(
            r#"INSERT INTO gateway_secrets.tor_access_tickets
                    (id, credential_id, token_hash, entry_onion, client_fingerprint, expires_at,
                     client_auth_public_key, client_auth_secret_path, attestation_session_id,
                     client_auth_secret_redeem_token,
                     attestation_nonce_digest, attestation_quote_hash, attested_at, tee_kind,
                     tee_label, tee_policy, tls_pubkey_digest)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
                RETURNING id, created_at, expires_at"#,
        )
        .bind(id)
        .bind(credential_id)
        .bind(token_hash)
        .bind(&entry_onion)
        .bind(&client_fingerprint)
        .bind(expires_at)
        .bind(client_auth_public_key_db)
        .bind(client_auth_secret_path_db)
        .bind(attestation_session_id)
        .bind(client_auth_secret_redeem_token_db)
        .bind(attestation_nonce_digest_db)
        .bind(attestation_quote_hash_db)
        .bind(attested_at)
        .bind(&tee_kind)
        .bind(&tee_label)
        .bind(&tee_policy)
        .bind(tls_pubkey_digest_db)
        .fetch_one(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;
        debug!(ticket_id = %id, "secure-database: issue_tor_ticket inserted row");

        // Build directly from pre-encryption plaintext — do NOT decrypt.
        // Decrypting would consume single-use redeem tokens needed for later
        // verification reads.
        Ok(IssuedTorAccessTicket {
            id: record.id,
            credential_id,
            entry_onion,
            client_fingerprint,
            created_at: record.created_at,
            expires_at: record.expires_at,
            redeemed_at: None,
            redeemed_operational_onion: None,
            client_auth_public_key,
            client_auth_secret_path,
            attestation_session_id,
            client_auth_secret_redeem_token,
            attestation_nonce_digest,
            attestation_quote_hash,
            attested_at,
            tee_kind,
            tee_label,
            tee_policy,
            tls_pubkey_digest,
        })
    }

    pub async fn fetch_tor_ticket_for_verification(
        &self,
        client: &SecretBrokerClient,
        ticket_id: Uuid,
    ) -> DbResult<Option<TicketVerificationRecord>> {
        let record = sqlx::query_as::<_, TicketVerificationRow>(
            r#"SELECT id, credential_id, token_hash, client_fingerprint,
                     expires_at, redeemed_at, client_auth_public_key, client_auth_secret_path,
                     client_auth_secret_redeem_token,
                     attestation_session_id, attestation_nonce_digest, attestation_quote_hash,
                     attested_at, tee_kind, tee_label, tee_policy, tls_pubkey_digest
                FROM gateway_secrets.tor_access_tickets
                WHERE id = $1"#,
        )
        .bind(ticket_id)
        .fetch_optional(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;

        let Some(row) = record else {
            return Ok(None);
        };

        let client_auth_public_key = decrypt_aead_required(
            client,
            row.client_auth_public_key,
            record_bound_aad(
                "gateway_secrets.tor_access_tickets",
                "client_auth_public_key",
                row.id,
                TICKET_CLIENT_PUBLIC_KEY_AAD,
            ),
            "tor-ticket-client-auth-public-key",
            "client_auth_public_key",
        )
        .await?;
        let client_auth_secret_path = decrypt_aead_required(
            client,
            row.client_auth_secret_path,
            record_bound_aad(
                "gateway_secrets.tor_access_tickets",
                "client_auth_secret_path",
                row.id,
                TICKET_CLIENT_SECRET_PATH_AAD,
            ),
            "tor-ticket-client-auth-secret-path",
            "client_auth_secret_path",
        )
        .await?;
        let client_auth_secret_redeem_token = decrypt_aead_optional(
            client,
            row.client_auth_secret_redeem_token,
            &record_bound_aad(
                "gateway_secrets.tor_access_tickets",
                "client_auth_secret_redeem_token",
                row.id,
                TICKET_CLIENT_SECRET_REDEEM_TOKEN_AAD,
            ),
            "tor-ticket-client-auth-secret-redeem-token",
        )
        .await?;
        let attestation_nonce_digest = decrypt_aead_required(
            client,
            row.attestation_nonce_digest,
            record_bound_aad(
                "gateway_secrets.tor_access_tickets",
                "attestation_nonce_digest",
                row.id,
                TICKET_ATTESTATION_NONCE_AAD,
            ),
            "tor-ticket-attestation-nonce",
            "attestation_nonce_digest",
        )
        .await?;
        let attestation_quote_hash = decrypt_aead_required(
            client,
            row.attestation_quote_hash,
            record_bound_aad(
                "gateway_secrets.tor_access_tickets",
                "attestation_quote_hash",
                row.id,
                TICKET_ATTESTATION_QUOTE_AAD,
            ),
            "tor-ticket-attestation-quote",
            "attestation_quote_hash",
        )
        .await?;
        let tls_pubkey_digest = decrypt_aead_required(
            client,
            row.tls_pubkey_digest,
            record_bound_aad(
                "gateway_secrets.tor_access_tickets",
                "tls_pubkey_digest",
                row.id,
                TICKET_TLS_PUBKEY_DIGEST_AAD,
            ),
            "tor-ticket-tls-pubkey-digest",
            "tls_pubkey_digest",
        )
        .await?;

        Ok(Some(TicketVerificationRecord {
            id: row.id,
            credential_id: row.credential_id,
            token_hash: row.token_hash,
            client_fingerprint: row.client_fingerprint,
            expires_at: row.expires_at,
            redeemed_at: row.redeemed_at,
            client_auth_public_key,
            client_auth_secret_path,
            client_auth_secret_redeem_token,
            attestation_session_id: row.attestation_session_id,
            attestation_nonce_digest,
            attestation_quote_hash,
            attested_at: row.attested_at,
            tee_kind: row.tee_kind,
            tee_label: row.tee_label,
            tee_policy: row.tee_policy,
            tls_pubkey_digest,
        }))
    }

    pub async fn get_tor_ticket_status(
        &self,
        ticket_id: Uuid,
    ) -> DbResult<Option<TicketStatusRecord>> {
        let record = sqlx::query_as::<_, TicketStatusRow>(
            r#"SELECT id, credential_id, expires_at, redeemed_at
                FROM gateway_secrets.tor_access_tickets
                WHERE id = $1"#,
        )
        .bind(ticket_id)
        .fetch_optional(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;

        Ok(record.map(map_ticket_status_row))
    }

    pub async fn mark_tor_ticket_redeemed(
        &self,
        client: &SecretBrokerClient,
        ticket_id: Uuid,
        operational_onion: &str,
    ) -> DbResult<()> {
        let stored_onion = if is_aead_payload(operational_onion) {
            operational_onion.to_string()
        } else {
            {
                let redeemed_onion_aad = record_bound_aad(
                    "gateway_secrets.tor_access_tickets",
                    "redeemed_operational_onion",
                    ticket_id,
                    REDEEMED_ONION_AAD,
                );
                encrypt_with_new_aead(
                    client,
                    operational_onion.as_bytes(),
                    &redeemed_onion_aad,
                    "tor-ticket-redeemed-onion",
                )
                .await?
            }
        };

        sqlx::query!(
            r#"UPDATE gateway_secrets.tor_access_tickets
                SET redeemed_operational_onion = $2,
                    redeemed_at = NOW()
                WHERE id = $1"#,
            ticket_id,
            stored_onion
        )
        .execute(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;
        Ok(())
    }

    pub async fn expire_tor_ticket_now(&self, ticket_id: Uuid) -> DbResult<bool> {
        let result = sqlx::query!(
            r#"UPDATE gateway_secrets.tor_access_tickets
                   SET expires_at = NOW() - INTERVAL '1 second'
                 WHERE id = $1"#,
            ticket_id
        )
        .execute(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;

        Ok(result.rows_affected() > 0)
    }

    /// Phase 9d: Delete expired tickets older than `retention_days` days.
    /// Returns the number of rows deleted.
    pub async fn gc_expired_tickets(&self, retention_days: i32) -> DbResult<u64> {
        let result = sqlx::query(
            r#"DELETE FROM gateway_secrets.tor_access_tickets
                WHERE expires_at < NOW() - make_interval(days => $1)
                  AND (redeemed_at IS NOT NULL OR expires_at < NOW())"#,
        )
        .bind(retention_days)
        .execute(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;

        Ok(result.rows_affected())
    }

    /// Phase 9d: Count tickets issued for a credential in the last `window_seconds`.
    pub async fn count_recent_tickets(
        &self,
        credential_id: Uuid,
        window_seconds: i64,
    ) -> DbResult<i64> {
        let row: (i64,) = sqlx::query_as(
            r#"SELECT COUNT(*) FROM gateway_secrets.tor_access_tickets
                WHERE credential_id = $1
                  AND created_at > NOW() - make_interval(secs => $2)"#,
        )
        .bind(credential_id)
        .bind(window_seconds as f64)
        .fetch_one(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;

        Ok(row.0)
    }

    pub async fn fetch_tor_session(
        &self,
        client: &SecretBrokerClient,
        session_id: Uuid,
    ) -> DbResult<Option<TorSessionRecord>> {
        let row = sqlx::query_as!(
            TorSessionRow,
            r#"SELECT id, credential_id, circuit_id, fingerprint, guard_nodes, client_onion, expires_at
                FROM gateway_secrets.tor_auth_sessions
                WHERE id = $1"#,
            session_id
        )
        .fetch_optional(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;

        match row {
            Some(row) => Ok(Some(row.into_record(client).await?)),
            None => Ok(None),
        }
    }
}

#[derive(sqlx::FromRow)]
struct TorSessionRow {
    id: Uuid,
    credential_id: Uuid,
    circuit_id: Option<String>,
    fingerprint: Option<String>,
    guard_nodes: Option<Vec<String>>,
    client_onion: Option<String>,
    expires_at: Option<DateTime<Utc>>,
}

impl TorSessionRow {
    async fn into_record(self, client: &SecretBrokerClient) -> DbResult<TorSessionRecord> {
        let client_onion_aad = record_bound_aad(
            "gateway_secrets.tor_auth_sessions",
            "client_onion",
            self.id,
            CLIENT_ONION_AAD,
        );
        let decrypted_onion = decrypt_aead_optional(
            client,
            self.client_onion,
            &client_onion_aad,
            "tor-session-client-onion",
        )
        .await?;
        Ok(TorSessionRecord {
            id: self.id,
            credential_id: self.credential_id,
            circuit_id: self.circuit_id,
            fingerprint: self.fingerprint,
            guard_nodes: self.guard_nodes.unwrap_or_default(),
            client_onion: decrypted_onion,
            expires_at: self.expires_at,
        })
    }
}

fn map_ticket_status_row(row: TicketStatusRow) -> TicketStatusRecord {
    TicketStatusRecord {
        id: row.id,
        credential_id: row.credential_id,
        expires_at: row.expires_at,
        redeemed_at: row.redeemed_at,
    }
}

async fn decrypt_aead_required(
    client: &SecretBrokerClient,
    value: String,
    aad: Vec<u8>,
    label: &'static str,
    field: &'static str,
) -> DbResult<String> {
    decrypt_aead_optional(client, Some(value), &aad, label)
        .await?
        .ok_or_else(|| DatabaseError::Encryption(format!("{field} missing from tor ticket")))
}

fn record_bound_aad(table: &str, field: &str, row_id: Uuid, purpose: &[u8]) -> Vec<u8> {
    let mut aad = format!("schema:v2\0table:{table}\0field:{field}\0row:{row_id}\0").into_bytes();
    aad.extend_from_slice(purpose);
    aad
}

async fn ensure_aead_encrypted(
    client: &SecretBrokerClient,
    value: Option<&str>,
    aad: &[u8],
    label: &'static str,
) -> DbResult<Option<String>> {
    match value {
        Some(existing) if is_aead_payload_v2(existing) => Ok(Some(existing.to_string())),
        Some(existing) if is_aead_payload(existing) => Err(DatabaseError::Encryption(format!(
            "legacy AEAD payload in protected field {label}; canonical v2 required"
        ))),
        Some(existing) => Ok(Some(
            encrypt_with_new_aead(client, existing.as_bytes(), aad, label).await?,
        )),
        None => Ok(None),
    }
}

async fn ensure_aead_encrypted_required(
    client: &SecretBrokerClient,
    value: &str,
    aad: &[u8],
    label: &'static str,
    field: &str,
) -> DbResult<String> {
    ensure_aead_encrypted(client, Some(value), aad, label)
        .await?
        .ok_or_else(|| DatabaseError::Encryption(format!("{field} missing from tor ticket")))
}

/// Decrypt an optional AEAD-encrypted string value using the broker client.
/// Returns `None` only for an absent database value. Present values must be
/// canonical v2 payloads; plaintext and legacy v1 payloads are corruption.
pub async fn decrypt_aead_optional(
    client: &SecretBrokerClient,
    value: Option<String>,
    aad: &[u8],
    label: &'static str,
) -> DbResult<Option<String>> {
    match value {
        Some(v) if is_aead_payload_v2(&v) => {
            Ok(Some(decrypt_with_broker(client, &v, aad, label).await?))
        }
        Some(v) if is_aead_payload(&v) => Err(DatabaseError::Encryption(format!(
            "legacy AEAD payload in protected field {label}; canonical v2 required"
        ))),
        Some(_) => Err(DatabaseError::Encryption(format!(
            "plaintext in protected field {label}"
        ))),
        None => Ok(None),
    }
}

async fn encrypt_with_new_aead(
    client: &SecretBrokerClient,
    plaintext: &[u8],
    aad: &[u8],
    label: &str,
) -> DbResult<String> {
    let label_str = label.to_string();
    metrics::counter!("secure_database_aead_encrypt_attempt_total", 1, "label" => label_str.clone());
    let label_string = label.to_string();
    let label_for_metric1 = label_string.clone();
    let label_for_metric2 = label_string.clone();

    let lease = client
        .mint_aead_key_v2(MintAeadKeyV2Params {
            ttl_seconds: Some(AEAD_KEY_TTL_SECONDS),
            label: Some(label_string.clone()),
            tenant_id: None,
            provider: None,
            threshold: None,
            num_shares: None,
            lifecycle: Some(SecretLifecycle::RenewableLease),
            initial_lease_seconds: Some(AEAD_KEY_TTL_SECONDS),
            unwrap_principal_id: None,
            custodian_ids: None,
        })
        .await
        .map_err(|err| {
            metrics::counter!("secure_database_aead_encrypt_failure_total", 1, "label" => label_for_metric1);
            DatabaseError::Encryption(err.to_string())
        })?;
    let mut key = lease.key;
    let redeem_token = lease.redeem_token.clone().ok_or_else(|| {
        metrics::counter!("secure_database_aead_encrypt_failure_total", 1, "label" => label_for_metric2.clone());
        DatabaseError::Encryption("broker v2 AEAD lease missing redeem token".into())
    })?;
    let ciphertext = aes_encrypt_with_aad(&key, plaintext, aad).map_err(|err| {
        metrics::counter!("secure_database_aead_encrypt_failure_total", 1, "label" => label_for_metric2);
        err
    })?;
    key.zeroize();
    metrics::counter!("secure_database_aead_encrypt_success_total", 1, "label" => label_str);
    Ok(encode_aead_payload(
        &lease.handle,
        &redeem_token,
        &ciphertext,
    ))
}

pub async fn decrypt_with_broker(
    client: &SecretBrokerClient,
    encoded: &str,
    aad: &[u8],
    label: &'static str,
) -> DbResult<String> {
    let (handle, redeem_token_b64, ciphertext) = decode_aead_payload(encoded).map_err(|err| {
        metrics::counter!("secure_database_aead_decrypt_failure_total", 1, "label" => label);
        err
    })?;
    let redeem_token_b64 = redeem_token_b64.ok_or_else(|| {
        metrics::counter!("secure_database_aead_decrypt_failure_total", 1, "label" => label);
        DatabaseError::Encryption(
            "legacy AEAD v1 payload encountered during decrypt; backfill to canonical v2 first"
                .into(),
        )
    })?;
    let mut key = client
        .unwrap_secret_v2_with_token(&handle, &redeem_token_b64)
        .await
        .map_err(|err| {
            metrics::counter!("secure_database_aead_decrypt_failure_total", 1, "label" => label);
            DatabaseError::Encryption(err.to_string())
        })?;
    let _ = client.renew_lease(&handle, AEAD_KEY_TTL_SECONDS).await;
    let plaintext = aes_decrypt_with_aad(&key, &ciphertext, aad).map_err(|err| {
        metrics::counter!("secure_database_aead_decrypt_failure_total", 1, "label" => label);
        err
    })?;
    key.zeroize();
    let plaintext_str = String::from_utf8(plaintext).map_err(|_| {
        metrics::counter!("secure_database_aead_decrypt_failure_total", 1, "label" => label);
        DatabaseError::Encryption("decrypted AEAD payload is not valid UTF-8".into())
    })?;
    metrics::counter!("secure_database_aead_decrypt_success_total", 1, "label" => label);
    Ok(plaintext_str)
}
