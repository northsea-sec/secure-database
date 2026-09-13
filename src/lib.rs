//! Hardened PostgreSQL access with attested credential rotation.
//!
//! This crate exposes a Postgres-first interface with strong defaults: TLS-only
//! connectivity, automatic migrations, optional Citus/Timescale extensions,
//! observability wiring, and cryptographic helpers that mirror the
//! security posture enforced by the attested secret-broker.

mod error;
mod ra_tls;
pub use error::DatabaseError;

mod attestation;
mod guard;
pub use guard::{GuardHealthSnapshot, GuardSuccessUpdate};

#[cfg(feature = "tee-dstack")]
pub mod tee;
#[cfg(feature = "tee-dstack")]
pub use tee::{TeeAttestation, TeeClient, TeeEndpointConfig};

pub mod secret_broker_client;
pub use secret_broker_client::SecretBrokerClient;

#[cfg(feature = "zk-halo2")]
pub mod zk;

/// Default ZK security parameter (k) for Halo2 circuits.
/// k=14 provides 2^14 = 16384 rows, balancing security and performance.
pub const DEFAULT_ZK_SECURITY: u32 = 14;
#[cfg(feature = "zk-halo2")]
pub use zk::{
    derive_execution_commitment, derive_log_chain_commitment, derive_relay_commitment,
    ZkProofBundle, ZkProofVerification, ZkProver, ZkVerificationContext,
};

pub mod tor_auth;
pub use tor_auth::{
    decrypt_aead_optional, IssuedTorAccessTicket, NewTorAccessTicket, TicketVerificationRecord,
    TorCredential, TorSessionRecord, TICKET_ATTESTATION_NONCE_AAD, TICKET_ATTESTATION_QUOTE_AAD,
    TICKET_CLIENT_PUBLIC_KEY_AAD, TICKET_CLIENT_SECRET_PATH_AAD,
    TICKET_CLIENT_SECRET_REDEEM_TOKEN_AAD, TICKET_TLS_PUBKEY_DIGEST_AAD,
};

use std::{env, sync::Arc, time::Duration};

use anyhow::anyhow;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use hmac::Mac;
#[cfg(feature = "otel")]
use opentelemetry_jaeger::new_agent_pipeline;
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use sha2::{Digest, Sha256};
use sqlx::Row;

use sqlx::{
    migrate::Migrator,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
    Pool, Postgres,
};
use tokio::time::sleep;
use tracing::{info, warn};
use tracing_subscriber::prelude::*;

use uuid::Uuid;

use crate::secret_broker_client::{PostgresCredentialLease, PostgresCredentialRequest};

/// Type alias used throughout the crate.
pub type DbResult<T> = std::result::Result<T, DatabaseError>;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Authentication tag length emitted by [`aes_encrypt`].
const TAG_LENGTH: usize = 16;
const AEAD_PREFIX_V1: &str = "aead:v1:";
const AEAD_PREFIX_V2: &str = "aead:v2:";
const AEAD_SEPARATOR: char = ':';

const LEASE_REFRESH_GRACE_SECS: i64 = 60;
const LEASE_REFRESH_RETRY_SECS: u64 = 15;

struct PoolContext<'a> {
    application_name: &'a str,
    pool_label: &'a str,
    max_connections: u32,
    min_connections: u32,
    connect_timeout_seconds: u64,
    idle_timeout_seconds: u64,
}

struct PoolInit {
    pool: ReloadablePool,
    worker: Option<BrokerLeaseWorker>,
}
#[derive(Clone)]
struct BrokerLeaseWorker {
    pool: ReloadablePool,
    client: Arc<SecretBrokerClient>,
    credential: BrokerCredentialConfig,
    application_name: String,
    pool_label: String,
    max_connections: u32,
    min_connections: u32,
    connect_timeout_seconds: u64,
    idle_timeout_seconds: u64,
    next_expiry: Option<DateTime<Utc>>,
}

impl BrokerLeaseWorker {
    fn new(
        pool: ReloadablePool,
        client: Arc<SecretBrokerClient>,
        credential: BrokerCredentialConfig,
        application_name: String,
        pool_label: String,
        max_connections: u32,
        min_connections: u32,
        connect_timeout_seconds: u64,
        idle_timeout_seconds: u64,
        next_expiry: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            pool,
            client,
            credential,
            application_name,
            pool_label,
            max_connections,
            min_connections,
            connect_timeout_seconds,
            idle_timeout_seconds,
            next_expiry,
        }
    }

    fn spawn(self) {
        if self.next_expiry.is_none() {
            info!(
                pool = self.pool_label.as_str(),
                "broker lease has no expiration; rotation disabled"
            );
            return;
        }

        tokio::spawn(async move {
            if let Err(err) = self.run().await {
                warn!(error = %err, "broker lease rotation task exited unexpectedly");
            }
        });
    }

    async fn run(mut self) -> DbResult<()> {
        loop {
            let expiry = match self.next_expiry {
                Some(expiry) => expiry,
                None => {
                    info!(
                        pool = self.pool_label.as_str(),
                        "broker lease rotation halted due to missing expiration"
                    );
                    return Ok(());
                }
            };

            let refresh_at = expiry - ChronoDuration::seconds(LEASE_REFRESH_GRACE_SECS);
            let now = Utc::now();
            let wait_duration = if refresh_at > now {
                refresh_at
                    .signed_duration_since(now)
                    .to_std()
                    .unwrap_or_else(|_| Duration::from_secs(0))
            } else {
                Duration::from_secs(0)
            };

            if !wait_duration.is_zero() {
                sleep(wait_duration).await;
            }

            match self.refresh_once().await {
                Ok(next) => {
                    self.next_expiry = next;
                    if self.next_expiry.is_none() {
                        info!(
                            pool = self.pool_label.as_str(),
                            "broker provided non-expiring credentials; stopping rotation"
                        );
                        return Ok(());
                    }
                }
                Err(err) => {
                    warn!(
                        pool = self.pool_label.as_str(),
                        error = %err,
                        "failed to refresh broker-issued credentials; retrying in {LEASE_REFRESH_RETRY_SECS}s"
                    );
                    sleep(Duration::from_secs(LEASE_REFRESH_RETRY_SECS)).await;
                }
            }
        }
    }

    async fn refresh_once(&self) -> DbResult<Option<DateTime<Utc>>> {
        let lease = obtain_broker_lease(
            self.client.as_ref(),
            &self.credential,
            &self.application_name,
        )
        .await?;

        record_lease_metrics(lease.expires_at, &self.pool_label);
        let options = connect_options_from_lease(&lease, &self.application_name, &self.pool_label)?;
        let pool = instantiate_pool(
            options,
            self.max_connections,
            self.min_connections,
            self.connect_timeout_seconds,
            self.idle_timeout_seconds,
        )
        .await?;

        let old_pool = self.pool.replace(pool);
        old_pool.close().await;

        Ok(lease.expires_at)
    }
}

#[derive(Clone)]
struct ReloadablePool {
    inner: Arc<ArcSwap<Pool<Postgres>>>,
}

impl ReloadablePool {
    fn new(pool: Pool<Postgres>) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(pool)),
        }
    }

    fn load(&self) -> Arc<Pool<Postgres>> {
        self.inner.load_full()
    }

    fn replace(&self, pool: Pool<Postgres>) -> Arc<Pool<Postgres>> {
        self.inner.swap(Arc::new(pool))
    }
}

/// Wrapper around a `sqlx::Pool<Postgres>` with security helpers.
#[derive(Clone)]
pub struct PgPool {
    data: ReloadablePool,
    secrets: ReloadablePool,
}

/// Public entry-points for consumers.
pub struct SecureDatabase;

impl SecureDatabase {
    /// Establish a TLS-protected Postgres connection pool using environment configuration.
    pub async fn connect_native() -> Result<PgPool, anyhow::Error> {
        let cfg = load_native_config()?;
        connect_postgres(cfg).await.map_err(anyhow::Error::new)
    }
}

impl PgPool {
    fn new(data: ReloadablePool, secrets: ReloadablePool) -> Self {
        Self { data, secrets }
    }

    /// Internal accessor for the underlying sqlx pool.
    pub fn inner(&self) -> Arc<Pool<Postgres>> {
        self.data.load()
    }

    /// Internal accessor for the secrets Postgres pool.
    pub fn secrets(&self) -> Arc<Pool<Postgres>> {
        self.secrets.load()
    }

    /// Record a Tor connection audit entry.
    pub async fn audit_tor_connect(&self, user_id: Uuid) -> DbResult<()> {
        let pool = self.inner();
        sqlx::query(
            "INSERT INTO gateway_data.tor_connect_audits (user_id, occurred_at) VALUES ($1, NOW())",
        )
        .bind(user_id)
        .execute(pool.as_ref())
        .await
        .map_err(DatabaseError::from)?;
        Ok(())
    }

    /// Persist a zero-knowledge proof bundle when the `zk-halo2` feature is enabled.
    #[cfg(feature = "zk-halo2")]
    pub async fn store_zk_proof(&self, bundle: &ZkProofBundle) -> DbResult<()> {
        let pool = self.secrets();
        sqlx::query(
            "INSERT INTO gateway_secrets.zk_proofs (
                id, user_id, protocol, circuit, circuit_security, expected_hash, public_inputs, proof, created_at, verified, verified_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,false,NULL)
            ON CONFLICT (id, user_id) DO UPDATE SET
                expected_hash = EXCLUDED.expected_hash,
                public_inputs = EXCLUDED.public_inputs,
                proof = EXCLUDED.proof,
                circuit_security = EXCLUDED.circuit_security,
                created_at = EXCLUDED.created_at,
                verified = false,
                verified_at = NULL",
        )
        .bind(bundle.proof_id)
        .bind(bundle.user_id)
        .bind(&bundle.protocol)
        .bind(&bundle.circuit)
        .bind(bundle.circuit_security as i16)
        .bind(&bundle.expected_hash)
        .bind(&bundle.public_inputs)
        .bind(&bundle.proof)
        .bind(bundle.created_at)
        .execute(pool.as_ref())
        .await
        .map_err(DatabaseError::from)?;
        Ok(())
    }

    /// Verify a stored ZK proof and update verification metadata.
    #[cfg(feature = "zk-halo2")]
    pub async fn verify_zk_proof(&self, verification: &ZkProofVerification) -> DbResult<bool> {
        let pool = self.secrets();
        let row = sqlx::query(
            "SELECT protocol, circuit, circuit_security, expected_hash, public_inputs, proof, verified
             FROM gateway_secrets.zk_proofs WHERE id = $1 AND user_id = $2",
        )
        .bind(verification.proof_id)
        .bind(verification.user_id)
        .fetch_optional(pool.as_ref())
        .await
        .map_err(DatabaseError::from)?
        .ok_or_else(|| DatabaseError::Query("proof not found".into()))?;

        let protocol: String = row.try_get("protocol")?;
        let circuit: String = row.try_get("circuit")?;
        let k: i16 = row.try_get("circuit_security")?;
        let expected_hash: String = row.try_get("expected_hash")?;
        let public_inputs = row.try_get("public_inputs")?;
        let proof: Vec<u8> = row.try_get("proof")?;
        let already_verified: bool = row.try_get("verified")?;

        if already_verified {
            return Ok(true);
        }

        let bundle = ZkProofBundle {
            proof_id: verification.proof_id,
            user_id: verification.user_id,
            protocol,
            circuit,
            circuit_security: k as u32,
            expected_hash,
            public_inputs,
            proof,
            created_at: Utc::now(),
        };

        zk::verify_proof(&bundle, verification.context())?;

        sqlx::query("UPDATE gateway_secrets.zk_proofs SET verified = TRUE, verified_at = NOW() WHERE id = $1")
            .bind(verification.proof_id)
            .execute(pool.as_ref())
            .await
            .map_err(DatabaseError::from)?;
        Ok(true)
    }

    /// Record a TEE attestation emitted by the configured runtime.
    #[cfg(feature = "tee-dstack")]
    pub async fn record_tee_attestation(
        &self,
        user_id: Uuid,
        attestation: &TeeAttestation,
    ) -> DbResult<()> {
        let pool = self.secrets();
        sqlx::query(
            "INSERT INTO gateway_secrets.tee_attestations (
                user_id, app_id, instance_id, device_id, compose_hash, key_provider_info, quote, rtmr, event_log, recorded_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(user_id)
        .bind(&attestation.app_id)
        .bind(&attestation.instance_id)
        .bind(&attestation.device_id)
        .bind(&attestation.compose_hash)
        .bind(&attestation.key_provider_info)
        .bind(&attestation.quote)
        .bind(&attestation.rtmr)
        .bind(&attestation.event_log)
        .bind(attestation.recorded_at)
        .execute(pool.as_ref())
        .await
        .map_err(DatabaseError::from)?;
        Ok(())
    }

    /// Retrieve recent TEE attestations for one user.
    #[cfg(feature = "tee-dstack")]
    pub async fn recent_tee_attestations(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> DbResult<Vec<TeeAttestation>> {
        if limit <= 0 {
            return Err(DatabaseError::Configuration(
                "attestation query limit must be greater than zero".into(),
            ));
        }
        let pool = self.secrets();
        let rows = sqlx::query(
            "SELECT app_id, instance_id, device_id, compose_hash, key_provider_info, quote, rtmr, event_log, recorded_at
             FROM gateway_secrets.tee_attestations WHERE user_id = $1 ORDER BY recorded_at DESC LIMIT $2",
        )
        .bind(user_id)
        .bind(limit.min(1_000))
        .fetch_all(pool.as_ref())
        .await
        .map_err(DatabaseError::from)?;

        rows.into_iter()
            .map(|row| {
                Ok(TeeAttestation {
                    app_id: row.try_get("app_id")?,
                    instance_id: row.try_get("instance_id")?,
                    device_id: row.try_get("device_id")?,
                    compose_hash: row.try_get("compose_hash")?,
                    key_provider_info: row.try_get("key_provider_info")?,
                    quote: row.try_get("quote")?,
                    rtmr: row.try_get("rtmr")?,
                    event_log: row.try_get("event_log")?,
                    recorded_at: row.try_get("recorded_at")?,
                })
            })
            .collect()
    }
}

/// Secure query extension trait used by dependant services for audit logging.
#[async_trait]
pub trait SecureQuery {
    async fn audit_operation(&self, user_id: Uuid, operation: &str, payload: &[u8])
        -> DbResult<()>;
}

#[async_trait]
impl SecureQuery for PgPool {
    async fn audit_operation(
        &self,
        user_id: Uuid,
        operation: &str,
        payload: &[u8],
    ) -> DbResult<()> {
        let digest = hex::encode(Sha256::digest(payload));
        let pool = self.secrets();
        sqlx::query(
            "INSERT INTO gateway_secrets.audit_logs (user_id, operation, payload_hash, created_at)
             VALUES ($1, $2, $3, NOW())",
        )
        .bind(user_id)
        .bind(operation)
        .bind(digest)
        .execute(pool.as_ref())
        .await
        .map_err(DatabaseError::from)?;
        Ok(())
    }
}

#[derive(Debug)]
struct NativeConfig {
    data_auth: NativeAuthConfig,
    secrets_auth: Option<NativeAuthConfig>,
    max_connections: u32,
    min_connections: u32,
    connect_timeout_seconds: u64,
    idle_timeout_seconds: u64,
    application_name: String,
}

#[derive(Debug)]
enum NativeAuthConfig {
    StaticUrl { database_url: String },
    Broker(BrokerCredentialConfig),
}

#[derive(Debug, Clone)]
struct BrokerCredentialConfig {
    audience: String,
    scope: Vec<String>,
    ttl_seconds: u64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum PoolKind {
    Data,
    Secrets,
}

fn parse_scope_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .filter_map(|entry| {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect()
}

fn load_native_config() -> Result<NativeConfig, anyhow::Error> {
    let credential_source = env::var("SECURE_DB_CREDENTIAL_SOURCE")
        .unwrap_or_else(|_| "broker".to_string())
        .to_ascii_lowercase();

    let data_auth = match credential_source.as_str() {
        "broker" => {
            let audience = required_env("SECURE_DB_BROKER_AUDIENCE")?;
            let scope = env::var("SECURE_DB_BROKER_SCOPE")
                .ok()
                .map(|raw| parse_scope_list(&raw))
                .unwrap_or_default();
            let ttl_seconds = parse_u64_env("SECURE_DB_BROKER_TTL_SECONDS", 900)?;
            if ttl_seconds == 0 {
                return Err(anyhow!(
                    "SECURE_DB_BROKER_TTL_SECONDS must be greater than zero"
                ));
            }
            NativeAuthConfig::Broker(BrokerCredentialConfig {
                audience,
                scope,
                ttl_seconds,
            })
        }
        "static" => {
            if !env_flag("SECURE_DB_ALLOW_STATIC").map_err(anyhow::Error::new)? {
                return Err(anyhow!(
                    "SECURE_DB_CREDENTIAL_SOURCE=static requires SECURE_DB_ALLOW_STATIC=true"
                ));
            }
            NativeAuthConfig::StaticUrl {
                database_url: required_env("SECURE_DB_URL")?,
            }
        }
        other => {
            return Err(anyhow!(
                "SECURE_DB_CREDENTIAL_SOURCE must be 'broker' or 'static', got {other:?}"
            ));
        }
    };

    let secrets_auth = match &data_auth {
        NativeAuthConfig::Broker(data_broker) => {
            match env::var("SECURE_DB_SECRETS_BROKER_AUDIENCE").ok() {
                Some(audience) if !audience.trim().is_empty() => {
                    let scope = env::var("SECURE_DB_SECRETS_BROKER_SCOPE")
                        .ok()
                        .map(|raw| parse_scope_list(&raw))
                        .unwrap_or_else(|| data_broker.scope.clone());
                    let ttl_seconds = parse_u64_env(
                        "SECURE_DB_SECRETS_BROKER_TTL_SECONDS",
                        data_broker.ttl_seconds,
                    )?;
                    if ttl_seconds == 0 {
                        return Err(anyhow!(
                            "SECURE_DB_SECRETS_BROKER_TTL_SECONDS must be greater than zero"
                        ));
                    }
                    Some(NativeAuthConfig::Broker(BrokerCredentialConfig {
                        audience,
                        scope,
                        ttl_seconds,
                    }))
                }
                Some(_) => {
                    return Err(anyhow!(
                        "SECURE_DB_SECRETS_BROKER_AUDIENCE must not be empty"
                    ));
                }
                None => {
                    if env::var_os("SECURE_DB_SECRETS_BROKER_SCOPE").is_some()
                        || env::var_os("SECURE_DB_SECRETS_BROKER_TTL_SECONDS").is_some()
                    {
                        return Err(anyhow!(
                            "SECURE_DB_SECRETS_BROKER_AUDIENCE is required when secret-pool broker overrides are set"
                        ));
                    }
                    None
                }
            }
        }
        NativeAuthConfig::StaticUrl { .. } => env::var("SECURE_DB_SECRETS_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|database_url| NativeAuthConfig::StaticUrl { database_url }),
    };

    let max_connections = parse_u32_env("SECURE_DB_POOL_MAX", 20)?;
    let min_connections = parse_u32_env("SECURE_DB_POOL_MIN", 5)?;
    if max_connections == 0 || min_connections > max_connections {
        return Err(anyhow!(
            "SECURE_DB_POOL_MAX must be positive and SECURE_DB_POOL_MIN must not exceed it"
        ));
    }

    let connect_timeout_seconds = parse_u64_env("SECURE_DB_CONNECT_TIMEOUT", 10)?;
    let idle_timeout_seconds = parse_u64_env("SECURE_DB_IDLE_TIMEOUT", 300)?;
    if connect_timeout_seconds == 0 || idle_timeout_seconds == 0 {
        return Err(anyhow!("database timeout values must be greater than zero"));
    }

    let application_name =
        env::var("SECURE_DB_APP_NAME").unwrap_or_else(|_| "secure-database".into());
    if application_name.trim().is_empty() {
        return Err(anyhow!("SECURE_DB_APP_NAME must not be empty"));
    }

    Ok(NativeConfig {
        data_auth,
        secrets_auth,
        max_connections,
        min_connections,
        connect_timeout_seconds,
        idle_timeout_seconds,
        application_name,
    })
}

fn required_env(key: &str) -> Result<String, anyhow::Error> {
    let value = env::var(key).map_err(|_| anyhow!("{key} is required"))?;
    if value.trim().is_empty() {
        return Err(anyhow!("{key} must not be empty"));
    }
    Ok(value)
}

fn parse_u32_env(key: &str, default: u32) -> Result<u32, anyhow::Error> {
    match env::var(key) {
        Ok(raw) => raw
            .parse::<u32>()
            .map_err(|error| anyhow!("invalid {key} value {raw:?}: {error}")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(anyhow!("failed to read {key}: {error}")),
    }
}

fn parse_u64_env(key: &str, default: u64) -> Result<u64, anyhow::Error> {
    match env::var(key) {
        Ok(raw) => raw
            .parse::<u64>()
            .map_err(|error| anyhow!("invalid {key} value {raw:?}: {error}")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(anyhow!("failed to read {key}: {error}")),
    }
}

fn env_flag(key: &str) -> DbResult<bool> {
    match env::var(key) {
        Err(env::VarError::NotPresent) => Ok(false),
        Err(error) => Err(DatabaseError::Configuration(format!(
            "failed to read {key}: {error}"
        ))),
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(DatabaseError::Configuration(format!(
                "{key} must be a boolean value"
            ))),
        },
    }
}

async fn connect_postgres(cfg: NativeConfig) -> DbResult<PgPool> {
    let NativeConfig {
        data_auth,
        secrets_auth,
        max_connections,
        min_connections,
        connect_timeout_seconds,
        idle_timeout_seconds,
        application_name,
    } = cfg;

    let data_context = PoolContext {
        application_name: &application_name,
        pool_label: "data",
        max_connections,
        min_connections,
        connect_timeout_seconds,
        idle_timeout_seconds,
    };

    let PoolInit {
        pool: data_pool,
        worker: data_worker,
    } = create_pool(&data_auth, &data_context).await?;

    {
        let pool = data_pool.load();
        run_migrations(pool.as_ref()).await?;
        ensure_postgres_extensions(pool.as_ref(), PoolKind::Data).await?;
    }

    let (secrets_pool, secrets_worker) = if let Some(auth) = secrets_auth {
        let secrets_context = PoolContext {
            application_name: &application_name,
            pool_label: "secrets",
            max_connections,
            min_connections,
            connect_timeout_seconds,
            idle_timeout_seconds,
        };

        let PoolInit { pool, worker } = create_pool(&auth, &secrets_context).await?;

        {
            let pool_arc = pool.load();
            run_migrations(pool_arc.as_ref()).await?;
            ensure_postgres_extensions(pool_arc.as_ref(), PoolKind::Secrets).await?;
        }

        (pool, worker)
    } else {
        info!("no dedicated Postgres-S endpoint configured; gateway_secrets schema will share the primary pool");
        (data_pool.clone(), None)
    };

    if let Some(worker) = data_worker {
        worker.spawn();
    }
    if let Some(worker) = secrets_worker {
        worker.spawn();
    }

    Ok(PgPool::new(data_pool, secrets_pool))
}

async fn obtain_broker_lease(
    client: &SecretBrokerClient,
    credential: &BrokerCredentialConfig,
    application_name: &str,
) -> DbResult<PostgresCredentialLease> {
    let request = PostgresCredentialRequest {
        audience: credential.audience.clone(),
        scope: credential.scope.clone(),
        ttl_seconds: credential.ttl_seconds,
        application_name: Some(application_name.to_string()),
    };

    client
        .issue_postgres_credentials(request)
        .await
        .map_err(|e| {
            DatabaseError::Configuration(format!(
                "failed to obtain PostgreSQL credentials from secret broker: {e}"
            ))
        })
}

fn record_lease_metrics(expires_at: Option<DateTime<Utc>>, pool_label: &str) {
    if let Some(expiry) = expires_at {
        let ttl_seconds = (expiry - Utc::now()).num_seconds().max(0);
        metrics::gauge!(
            "secure_database_lease_ttl_seconds",
            ttl_seconds as f64,
            "pool" => pool_label.to_string()
        );
    }
}

fn connect_options_from_lease(
    lease: &PostgresCredentialLease,
    application_name: &str,
    pool_label: &str,
) -> DbResult<PgConnectOptions> {
    let mut options = lease
        .database_url
        .parse::<PgConnectOptions>()
        .map_err(|e| {
            DatabaseError::Configuration(format!(
                "invalid database_url from secret broker lease for {pool_label}: {e}"
            ))
        })?;

    options = options
        .ssl_mode(PgSslMode::Require)
        .application_name(application_name);

    if let Some(username) = &lease.username {
        options = options.username(username);
    }

    if let Some(password) = &lease.password {
        options = options.password(password);
    }

    Ok(options)
}

async fn instantiate_pool(
    options: PgConnectOptions,
    max_connections: u32,
    min_connections: u32,
    connect_timeout_seconds: u64,
    idle_timeout_seconds: u64,
) -> DbResult<Pool<Postgres>> {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(min_connections)
        .acquire_timeout(Duration::from_secs(connect_timeout_seconds))
        .idle_timeout(Duration::from_secs(idle_timeout_seconds))
        .connect_with(options)
        .await
        .map_err(|e| {
            DatabaseError::Configuration(format!("failed to instantiate connection pool: {e}"))
        })
}

async fn create_pool(auth: &NativeAuthConfig, context: &PoolContext<'_>) -> DbResult<PoolInit> {
    match auth {
        NativeAuthConfig::StaticUrl { database_url } => {
            // Enforce PgBouncer DSN (host pgbouncer or port 6432) unless SECURE_DB_RATLS_MODE=disabled
            {
                let ratls_mode = std::env::var("SECURE_DB_RATLS_MODE")
                    .unwrap_or_else(|_| String::from("enforced"));
                let skip_pgbouncer_check = ratls_mode.eq_ignore_ascii_case("disabled")
                    || env_flag("SECURE_DB_ALLOW_DIRECT_BOOTSTRAP")?;

                if !skip_pgbouncer_check {
                    fn ensure_pgbouncer_dsn(url: &str) -> DbResult<()> {
                        let lower = url.to_lowercase();
                        let has_host =
                            lower.contains("@pgbouncer:") || lower.contains("//pgbouncer:");
                        let has_port = lower.contains(":6432/")
                            || lower.ends_with(":6432")
                            || lower.contains(":6432?");
                        if has_host || has_port {
                            Ok(())
                        } else {
                            Err(DatabaseError::Configuration(format!(
                                "PgBouncer DSN required (port 6432 or host pgbouncer): {url}. Set SECURE_DB_ALLOW_DIRECT_BOOTSTRAP=1 for admin bootstrap or SECURE_DB_RATLS_MODE=disabled for development."
                            )))
                        }
                    }
                    ensure_pgbouncer_dsn(database_url)?;
                }
            }
            let mut options = database_url
                .parse::<PgConnectOptions>()
                .map_err(|e| DatabaseError::Configuration(format!("invalid DATABASE_URL: {e}")))?;
            // Use Prefer for dev mode (SECURE_DB_RATLS_MODE=disabled), Require otherwise
            let ratls_mode =
                std::env::var("SECURE_DB_RATLS_MODE").unwrap_or_else(|_| String::from("enforced"));
            let ssl_mode = if ratls_mode.eq_ignore_ascii_case("disabled") {
                PgSslMode::Prefer
            } else {
                PgSslMode::Require
            };
            options = options
                .ssl_mode(ssl_mode)
                .application_name(context.application_name);

            let pool = instantiate_pool(
                options,
                context.max_connections,
                context.min_connections,
                context.connect_timeout_seconds,
                context.idle_timeout_seconds,
            )
            .await?;

            Ok(PoolInit {
                pool: ReloadablePool::new(pool),
                worker: None,
            })
        }
        NativeAuthConfig::Broker(broker) => {
            let client = Arc::new(SecretBrokerClient::from_env().await.map_err(|err| {
                DatabaseError::Configuration(format!(
                    "failed to initialise secret-broker client for Postgres credentials: {err}"
                ))
            })?);

            let lease =
                obtain_broker_lease(client.as_ref(), broker, context.application_name).await?;
            record_lease_metrics(lease.expires_at, context.pool_label);

            let options =
                connect_options_from_lease(&lease, context.application_name, context.pool_label)?;

            let pool = instantiate_pool(
                options,
                context.max_connections,
                context.min_connections,
                context.connect_timeout_seconds,
                context.idle_timeout_seconds,
            )
            .await?;

            let reloadable = ReloadablePool::new(pool);

            let worker = BrokerLeaseWorker::new(
                reloadable.clone(),
                client,
                broker.clone(),
                context.application_name.to_string(),
                context.pool_label.to_string(),
                context.max_connections,
                context.min_connections,
                context.connect_timeout_seconds,
                context.idle_timeout_seconds,
                lease.expires_at,
            );

            Ok(PoolInit {
                pool: reloadable,
                worker: Some(worker),
            })
        }
    }
}

async fn run_migrations(pool: &Pool<Postgres>) -> DbResult<()> {
    // Allow skipping migrations when they've already been applied externally (e.g., via sqlx-cli)
    if env_flag("SECURE_DB_SKIP_MIGRATIONS")? {
        info!("SECURE_DB_SKIP_MIGRATIONS set; skipping embedded migrations");
        return Ok(());
    }
    MIGRATOR
        .run(pool)
        .await
        .map_err(|e| DatabaseError::Migration(e.to_string()))
}

async fn ensure_postgres_extensions(pool: &Pool<Postgres>, kind: PoolKind) -> DbResult<()> {
    upsert_extension_allowlist(pool, "pgcrypto").await?;
    #[cfg(feature = "pgaudit")]
    {
        sqlx::query("CREATE EXTENSION IF NOT EXISTS pgaudit;")
            .execute(pool)
            .await
            .map_err(DatabaseError::from)?;
        upsert_extension_allowlist(pool, "pgaudit").await?;
    }
    #[cfg(feature = "pg-stat-statements")]
    {
        sqlx::query("CREATE EXTENSION IF NOT EXISTS pg_stat_statements;")
            .execute(pool)
            .await
            .map_err(DatabaseError::from)?;
        upsert_extension_allowlist(pool, "pg_stat_statements").await?;
    }

    if matches!(kind, PoolKind::Data) {
        #[cfg(feature = "timescaledb")]
        {
            ensure_timescaledb(pool).await?;
            upsert_extension_allowlist(pool, "timescaledb").await?;
        }
        #[cfg(feature = "citus")]
        {
            ensure_citus(pool).await?;
            upsert_extension_allowlist(pool, "citus").await?;
        }
    }

    enforce_extension_allowlist(pool).await?;
    Ok(())
}

async fn upsert_extension_allowlist(pool: &Pool<Postgres>, extension: &str) -> DbResult<()> {
    sqlx::query(
        "INSERT INTO database_extensions.extension_allowlist (name) VALUES ($1) ON CONFLICT DO NOTHING",
    )
    .bind(extension)
    .execute(pool)
    .await
    .map_err(DatabaseError::from)?;
    Ok(())
}

async fn enforce_extension_allowlist(pool: &Pool<Postgres>) -> DbResult<()> {
    if env_flag("SECURE_DB_ALLOW_UNLISTED_EXTENSIONS")? {
        return Ok(());
    }

    let unauthorized = sqlx::query_scalar::<_, String>(
        "SELECT extname FROM pg_extension WHERE extname NOT IN (SELECT name FROM database_extensions.extension_allowlist)",
    )
    .fetch_all(pool)
    .await
    .map_err(DatabaseError::from)?;

    if unauthorized.is_empty() {
        return Ok(());
    }

    Err(DatabaseError::Configuration(format!(
        "found disallowed extensions: {} (set SECURE_DB_ALLOW_UNLISTED_EXTENSIONS=1 to override)",
        unauthorized.join(", ")
    )))
}

#[cfg(feature = "timescaledb")]
async fn ensure_timescaledb(pool: &Pool<Postgres>) -> DbResult<()> {
    sqlx::query("CREATE EXTENSION IF NOT EXISTS timescaledb;")
        .execute(pool)
        .await
        .map_err(DatabaseError::from)?;
    sqlx::query(
        "SELECT create_hypertable('gateway_data.tor_connect_audits', 'occurred_at', if_not_exists => TRUE);",
    )
    .execute(pool)
    .await
    .map_err(DatabaseError::from)?;
    Ok(())
}

#[cfg(feature = "citus")]
async fn ensure_citus(pool: &Pool<Postgres>) -> DbResult<()> {
    sqlx::query("CREATE EXTENSION IF NOT EXISTS citus;")
        .execute(pool)
        .await
        .map_err(DatabaseError::from)?;
    sqlx::query(
        "SELECT create_distributed_table('gateway_secrets.zk_proofs', 'user_id', if_not_exists => TRUE);",
    )
    .execute(pool)
    .await
    .map_err(DatabaseError::from)?;
    sqlx::query(
        "SELECT create_distributed_table('gateway_secrets.tee_attestations', 'user_id', if_not_exists => TRUE);",
    )
    .execute(pool)
    .await
    .map_err(DatabaseError::from)?;
    Ok(())
}

/// Compute an HMAC-SHA256 tag for the supplied payload.
pub fn hmac_sign(key: &[u8], payload: &[u8]) -> DbResult<Vec<u8>> {
    type HmacSha256 = hmac::Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| DatabaseError::Encryption("invalid HMAC key".into()))?;
    mac.update(payload);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Encrypt plaintext with AES-256-GCM, returning nonce||ciphertext||tag.
pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> DbResult<Vec<u8>> {
    aes_encrypt_with_aad(key, plaintext, &[])
}

/// Encrypt plaintext with AES-256-GCM and caller-supplied associated data.
pub fn aes_encrypt_with_aad(key: &[u8], plaintext: &[u8], aad: &[u8]) -> DbResult<Vec<u8>> {
    let mut nonce_bytes = [0u8; aead::NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|e| DatabaseError::Encryption(format!("rng failure: {e}")))?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let unbound = UnboundKey::new(&aead::AES_256_GCM, key)?;
    let less_safe = LessSafeKey::new(unbound);
    let mut in_out = plaintext.to_vec();
    less_safe
        .seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
        .map_err(|e| DatabaseError::Encryption(e.to_string()))?;

    let mut output = nonce_bytes.to_vec();
    output.extend_from_slice(&in_out);
    Ok(output)
}

/// Decrypt bytes produced by [`aes_encrypt`].
pub fn aes_decrypt(key: &[u8], ciphertext: &[u8]) -> DbResult<Vec<u8>> {
    aes_decrypt_with_aad(key, ciphertext, &[])
}

/// Decrypt bytes produced by [`aes_encrypt_with_aad`], validating the same associated data.
pub fn aes_decrypt_with_aad(key: &[u8], ciphertext: &[u8], aad: &[u8]) -> DbResult<Vec<u8>> {
    if ciphertext.len() < aead::NONCE_LEN + TAG_LENGTH {
        return Err(DatabaseError::Encryption("ciphertext too short".into()));
    }

    let (nonce_bytes, body) = ciphertext.split_at(aead::NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| DatabaseError::Encryption("invalid nonce".into()))?;

    let unbound = UnboundKey::new(&aead::AES_256_GCM, key)?;
    let less_safe = LessSafeKey::new(unbound);
    let mut in_out = body.to_vec();
    less_safe
        .open_in_place(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| DatabaseError::Encryption("decryption failed".into()))
        .map(|plaintext| plaintext.to_vec())
}

/// Encode an AEAD ciphertext together with its backing broker handle and
/// canonical v2 redeem token.
pub fn encode_aead_payload(handle: &str, redeem_token_b64: &str, ciphertext: &[u8]) -> String {
    let handle_b64 = BASE64.encode(handle.as_bytes());
    let redeem_token_b64 = BASE64.encode(redeem_token_b64.as_bytes());
    let ciphertext_b64 = BASE64.encode(ciphertext);
    format!(
        "{AEAD_PREFIX_V2}{handle_b64}{AEAD_SEPARATOR}{redeem_token_b64}{AEAD_SEPARATOR}{ciphertext_b64}"
    )
}

/// Decode an encoded AEAD payload into the broker handle, optional redeem
/// token, and ciphertext bytes. v1 payloads decode with `None` redeem token so
/// callers can force explicit migration to the canonical v2 format.
pub fn decode_aead_payload(encoded: &str) -> DbResult<(String, Option<String>, Vec<u8>)> {
    let (remainder, version) = if let Some(remainder) = encoded.strip_prefix(AEAD_PREFIX_V2) {
        (remainder, 2u8)
    } else if let Some(remainder) = encoded.strip_prefix(AEAD_PREFIX_V1) {
        (remainder, 1u8)
    } else {
        return Err(DatabaseError::Encryption(
            "value missing aead:v1/v2 prefix".into(),
        ));
    };

    let (handle_b64, redeem_token_b64, ciphertext_b64) = if version == 2 {
        let mut parts = remainder.splitn(3, AEAD_SEPARATOR);
        let handle_b64 = parts
            .next()
            .ok_or_else(|| DatabaseError::Encryption("invalid AEAD v2 payload format".into()))?;
        let redeem_token_b64 = parts
            .next()
            .ok_or_else(|| DatabaseError::Encryption("invalid AEAD v2 payload format".into()))?;
        let ciphertext_b64 = parts
            .next()
            .ok_or_else(|| DatabaseError::Encryption("invalid AEAD v2 payload format".into()))?;
        (handle_b64, Some(redeem_token_b64), ciphertext_b64)
    } else {
        let (handle_b64, ciphertext_b64) = remainder
            .split_once(AEAD_SEPARATOR)
            .ok_or_else(|| DatabaseError::Encryption("invalid AEAD v1 payload format".into()))?;
        (handle_b64, None, ciphertext_b64)
    };

    let handle_bytes = BASE64
        .decode(handle_b64.as_bytes())
        .map_err(|_| DatabaseError::Encryption("invalid AEAD handle encoding".into()))?;
    let redeem_token = match redeem_token_b64 {
        Some(token_b64) => {
            let token_bytes = BASE64.decode(token_b64.as_bytes()).map_err(|_| {
                DatabaseError::Encryption("invalid AEAD redeem token encoding".into())
            })?;
            Some(String::from_utf8(token_bytes).map_err(|_| {
                DatabaseError::Encryption("AEAD redeem token is not valid UTF-8".into())
            })?)
        }
        None => None,
    };
    let ciphertext = BASE64
        .decode(ciphertext_b64.as_bytes())
        .map_err(|_| DatabaseError::Encryption("invalid AEAD ciphertext encoding".into()))?;

    let handle = String::from_utf8(handle_bytes)
        .map_err(|_| DatabaseError::Encryption("AEAD handle is not valid UTF-8".into()))?;

    Ok((handle, redeem_token, ciphertext))
}

/// Returns true if the provided value appears to be an encoded AEAD payload.
pub fn is_aead_payload(value: &str) -> bool {
    value.starts_with(AEAD_PREFIX_V1) || value.starts_with(AEAD_PREFIX_V2)
}

pub fn is_aead_payload_v2(value: &str) -> bool {
    value.starts_with(AEAD_PREFIX_V2)
}

#[cfg(feature = "otel")]
pub fn install_jaeger_tracing() -> DbResult<()> {
    let env_filter = tracing_subscriber::EnvFilter::from_default_env();
    let tracer = new_agent_pipeline()
        .with_service_name("secure-database")
        .install_simple()
        .map_err(|error| {
            DatabaseError::Configuration(format!(
                "failed to initialise OpenTelemetry exporter: {error}"
            ))
        })?;
    let subscriber = tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .with(tracing_subscriber::fmt::layer());
    tracing::subscriber::set_global_default(subscriber).map_err(|error| {
        DatabaseError::Configuration(format!("failed to install tracing subscriber: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "zk-halo2")]
    use super::zk::verify_scalar_equality;

    #[test]
    fn aes_round_trip() {
        let key = [0u8; 32];
        let plaintext = b"secure-database-roundtrip";
        let ciphertext = aes_encrypt(&key, plaintext).expect("encrypt");
        let recovered = aes_decrypt(&key, &ciphertext).expect("decrypt");
        assert_eq!(plaintext, recovered.as_slice());
    }

    #[test]
    fn hmac_produces_deterministic_tag() {
        let key = [0u8; 16];
        let payload = b"audit";
        let tag1 = hmac_sign(&key, payload).expect("first tag");
        let tag2 = hmac_sign(&key, payload).expect("second tag");
        assert_eq!(tag1, tag2);
    }

    #[cfg(feature = "zk-halo2")]
    #[test]
    fn halo2_digest_equality_proof_round_trips() {
        if std::env::var_os("CI").is_none() {
            println!("skipping halo2_digest_equality_proof_round_trips to avoid long proving time");
            return;
        }
        let prover = ZkProver::default();
        let user_id = Uuid::new_v4();
        let digest = Sha256::digest(b"halo2-proof");

        let bundle = prover
            .prove_digest_equality(user_id, &digest, &digest)
            .expect("prove digest equality");
        assert_eq!(bundle.protocol.as_str(), "halo2-scalar-equality-v1");
        assert_eq!(bundle.circuit.as_str(), "scalar_equality");

        let verification =
            ZkProofVerification::scalar_digest(bundle.proof_id, user_id, digest.to_vec());
        if let ZkVerificationContext::ScalarDigest { expected_digest } = verification.context() {
            assert_eq!(expected_digest.as_slice(), digest.as_slice());
        } else {
            panic!("unexpected verification context");
        }

        verify_scalar_equality(&bundle, &digest).expect("proof should verify");

        let mismatch = Sha256::digest(b"halo2-mismatch");
        let err = verify_scalar_equality(&bundle, &mismatch).expect_err("verification must fail");
        assert!(matches!(err, DatabaseError::Integrity(_)));
    }
}
