use std::{
    collections::HashSet, env, fs, io::Cursor, path::Path, sync::Arc, time::Duration as StdDuration,
};

use crate::ra_tls::attestation::{Attestation, VerifiedAttestation};
use crate::ra_tls::qvl::quote::Report;
use anyhow::{anyhow, bail, Context, Result};
use broker_protocol_client::{
    AttenuateHandleV2Params, MintAeadKeyV2Lease, MintAeadKeyV2Params,
    PostgresCredentialLease as GrpcPostgresCredentialLease, PostgresCredentialParams,
    RenewLeaseResult, RevokeResult, RotateParams, RotateResult, SecretBrokerGrpcAdapter,
    SecretBrokerGrpcAdapterConfig, ThresholdShareMaterial, UnwrapSecretV2Params, WrapResponse,
    WrapV2Params,
};
use chrono::{DateTime, Utc};
use hex::encode as hex_encode;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;
use rustls::Error as RustlsError;
use rustls::{ClientConfig, RootCertStore, SignatureScheme};
use rustls_pemfile::{certs, read_all, Item};
use serde_json::Value;
use spiffe::workload_api::client::WorkloadApiClient;
use tokio::runtime::Handle;
use tracing::warn;
use url::Url;
use x509_parser::prelude::{FromDer, X509Certificate};

const UNSAFE_FLAG_ENV: &str = "SECURE_DB_ALLOW_UNSAFE_BROKER";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationMode {
    Enforced,
    Disabled,
    Spiffe,
    Local,
}

impl AttestationMode {
    pub fn from_env_var(key: &str, default: &str) -> Result<Self> {
        let raw = env::var(key).unwrap_or_else(|_| default.to_string());
        match raw.trim().to_ascii_lowercase().as_str() {
            "disabled" => Ok(AttestationMode::Disabled),
            "spiffe" => Ok(AttestationMode::Spiffe),
            "local" => Ok(AttestationMode::Local),
            "enforced" => Ok(AttestationMode::Enforced),
            _ => bail!("{key} must be one of enforced, spiffe, local, or disabled; got {raw:?}"),
        }
    }

    pub fn is_enforced(self) -> bool {
        matches!(self, AttestationMode::Enforced)
    }
}

#[derive(Debug, Clone)]
pub struct MeasurementPolicy {
    allowed_mrtd: HashSet<String>,
    allowed_mrenclave: HashSet<String>,
    allowed_mrsigner: HashSet<String>,
    min_isvsvn: Option<u16>,
    expected_compose_hash: Option<String>,
}

impl MeasurementPolicy {
    pub fn allow_all() -> Self {
        Self {
            allowed_mrtd: HashSet::new(),
            allowed_mrenclave: HashSet::new(),
            allowed_mrsigner: HashSet::new(),
            min_isvsvn: None,
            expected_compose_hash: None,
        }
    }

    pub fn allows_tdx_mrtd(&self, mrtd: &str) -> bool {
        self.allowed_mrtd.is_empty() || self.allowed_mrtd.contains(&mrtd.to_lowercase())
    }

    pub fn allows_sgx_measurements(&self, mrenclave: &str, mrsigner: &str, isvsvn: u16) -> bool {
        let mrenclave_ok = self.allowed_mrenclave.is_empty()
            || self.allowed_mrenclave.contains(&mrenclave.to_lowercase());
        let mrsigner_ok = self.allowed_mrsigner.is_empty()
            || self.allowed_mrsigner.contains(&mrsigner.to_lowercase());
        let isvsvn_ok = match self.min_isvsvn {
            Some(min) => isvsvn >= min,
            None => true,
        };
        mrenclave_ok && mrsigner_ok && isvsvn_ok
    }

    pub fn allows_compose_hash(&self, compose_hash: &str) -> bool {
        match &self.expected_compose_hash {
            Some(expected) => expected == &compose_hash.to_lowercase(),
            None => true,
        }
    }

    pub fn expects_compose_hash(&self) -> bool {
        self.expected_compose_hash.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct ClientPolicy {
    pub policy_name: String,
    pub measurement: MeasurementPolicy,
}

impl ClientPolicy {
    pub fn from_env(mode: AttestationMode) -> Result<Self> {
        match env::var("SECRET_BROKER_CLIENT_POLICY_FILE") {
            Ok(path) => Self::from_file(path),
            Err(_) if !mode.is_enforced() => Ok(ClientPolicy::transport_only()),
            Err(error) => Err(anyhow!(
                "SECRET_BROKER_CLIENT_POLICY_FILE must be set when attestation is enforced: {error}"
            )),
        }
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let raw = fs::read_to_string(path.as_ref()).with_context(|| {
            format!(
                "failed to read client policy file: {}",
                path.as_ref().display()
            )
        })?;
        let value: Value =
            serde_json::from_str(&raw).context("failed to parse policy file (expected JSON)")?;

        let measurement = MeasurementPolicy {
            allowed_mrtd: Self::string_set(value.get("allowed_mrtd")),
            allowed_mrenclave: Self::string_set(value.get("allowed_mrenclave")),
            allowed_mrsigner: Self::string_set(value.get("allowed_mrsigner")),
            min_isvsvn: value
                .get("min_isvsvn")
                .and_then(|v| v.as_u64())
                .map(|v| v as u16),
            expected_compose_hash: value
                .get("expected_compose_hash")
                .and_then(|v| v.as_str())
                .map(|s| s.to_lowercase()),
        };

        if measurement.allowed_mrtd.is_empty()
            && measurement.allowed_mrenclave.is_empty()
            && measurement.allowed_mrsigner.is_empty()
            && measurement.expected_compose_hash.is_none()
        {
            bail!("attestation policy must restrict at least one measurement or compose hash");
        }

        Ok(Self {
            policy_name: value
                .get("policy_name")
                .and_then(|v| v.as_str())
                .unwrap_or("default")
                .to_string(),
            measurement,
        })
    }

    fn string_set(value: Option<&Value>) -> HashSet<String> {
        value
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| item.as_str())
                    .map(|s| s.to_lowercase())
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default()
    }

    fn transport_only() -> Self {
        Self {
            policy_name: "transport-only".to_string(),
            measurement: MeasurementPolicy::allow_all(),
        }
    }
}

#[derive(Debug)]
pub struct SecretBrokerClientConfig {
    pub endpoint: Url,
    pub attestation_mode: AttestationMode,
    pub policy: ClientPolicy,
    pub pccs_url: Option<String>,
    pub subject_allowlist: Option<HashSet<String>>,
    pub client_cert_chain: Option<Vec<CertificateDer<'static>>>,
    pub client_key: Option<PrivateKeyDer<'static>>,
    pub client_identity_pem: Option<Vec<u8>>,
    pub timeout: StdDuration,
    pub spiffe_socket_path: Option<String>,
    /// Client's own SPIFFE ID for SVID selection when multiple match
    pub my_spiffe_id: Option<String>,
}

impl SecretBrokerClientConfig {
    pub fn from_env() -> Result<Self> {
        let endpoint = env::var("SECRET_BROKER_ENDPOINT")
            .map_err(|_| anyhow!("SECRET_BROKER_ENDPOINT is required"))?
            .parse::<Url>()
            .context("invalid SECRET_BROKER_ENDPOINT")?;

        let attestation_mode =
            AttestationMode::from_env_var("SECRET_BROKER_CLIENT_MODE", "enforced")?;
        if matches!(
            attestation_mode,
            AttestationMode::Local | AttestationMode::Disabled
        ) && !secret_broker_endpoint_is_loopback(&endpoint)
        {
            return Err(anyhow!(
                "SECRET_BROKER_CLIENT_MODE={:?} requires a loopback SECRET_BROKER_ENDPOINT",
                attestation_mode
            ));
        }
        if !matches!(attestation_mode, AttestationMode::Disabled) && endpoint.scheme() != "https" {
            return Err(anyhow!(
                "SECRET_BROKER_ENDPOINT must use https unless client mode is disabled"
            ));
        }
        ensure_attestation_mode(attestation_mode)?;
        let policy = ClientPolicy::from_env(attestation_mode)?;

        let subject_allowlist = env::var("SECRET_BROKER_CLIENT_SUBJECTS")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .filter_map(|entry| {
                        let trimmed = entry.trim().to_lowercase();
                        if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed)
                        }
                    })
                    .collect::<HashSet<_>>()
            })
            .filter(|set| !set.is_empty());

        if subject_allowlist.is_none() && attestation_mode.is_enforced() {
            return Err(anyhow!(
                "SECRET_BROKER_CLIENT_SUBJECTS must be set when attestation is enforced"
            ));
        }

        let pccs_url = env::var("SECRET_BROKER_PCCS_URL").ok();

        let (client_cert_chain, client_key, client_identity_pem) =
            Self::load_client_identity(attestation_mode)?;

        let timeout_seconds = match env::var("SECRET_BROKER_CLIENT_TIMEOUT_SECS") {
            Ok(raw) => raw.parse::<u64>().with_context(|| {
                format!("invalid SECRET_BROKER_CLIENT_TIMEOUT_SECS value {raw:?}")
            })?,
            Err(env::VarError::NotPresent) => 10,
            Err(error) => return Err(anyhow!("failed to read broker timeout: {error}")),
        };
        if timeout_seconds == 0 {
            bail!("SECRET_BROKER_CLIENT_TIMEOUT_SECS must be greater than zero");
        }
        let timeout = StdDuration::from_secs(timeout_seconds);

        let spiffe_socket_path = env::var("SECRET_BROKER_SPIFFE_SOCKET").ok().or_else(|| {
            if matches!(attestation_mode, AttestationMode::Spiffe) {
                Some("/var/run/spire/agent.sock".to_string())
            } else {
                None
            }
        });

        let my_spiffe_id = env::var("SECRET_BROKER_CLIENT_SPIFFE_ID").ok();

        Ok(Self {
            endpoint,
            attestation_mode,
            policy,
            pccs_url,
            subject_allowlist,
            client_cert_chain,
            client_key,
            client_identity_pem,
            timeout,
            spiffe_socket_path,
            my_spiffe_id,
        })
    }

    fn load_client_identity(
        attestation_mode: AttestationMode,
    ) -> Result<(
        Option<Vec<CertificateDer<'static>>>,
        Option<PrivateKeyDer<'static>>,
        Option<Vec<u8>>,
    )> {
        let cert_path = env::var("SECRET_BROKER_CLIENT_CERT").ok();
        let key_path = env::var("SECRET_BROKER_CLIENT_KEY").ok();

        let (client_cert_chain, client_key, client_identity_pem) = match (cert_path, key_path) {
            (Some(cert), Some(key)) => {
                let cert_bytes = fs::read(&cert)
                    .with_context(|| format!("failed to read client cert {cert}"))?;
                let key_bytes = fs::read(&key)
                    .with_context(|| format!("failed to read client key {key}"))?;

                let certs = parse_cert_chain(&cert_bytes)
                    .context("failed to parse client certificate chain")?;
                let key = parse_private_key(&key_bytes)
                    .context("failed to parse client private key")?;

                let mut pem_bundle = cert_bytes;
                pem_bundle.extend_from_slice(&key_bytes);

                (Some(certs), Some(key), Some(pem_bundle))
            }
            (None, None) => (None, None, None),
            _ => bail!(
                "SECRET_BROKER_CLIENT_CERT and SECRET_BROKER_CLIENT_KEY must both be set or both unset"
            ),
        };

        if attestation_mode.is_enforced() && client_cert_chain.is_none() {
            bail!(
                "client attestation mode is enforced but SECRET_BROKER_CLIENT_CERT/KEY are not configured"
            );
        }

        Ok((client_cert_chain, client_key, client_identity_pem))
    }
}

#[derive(Clone, Debug)]
pub struct SecretBrokerClient {
    adapter: SecretBrokerGrpcAdapter,
}

unsafe impl Send for SecretBrokerClient {}
unsafe impl Sync for SecretBrokerClient {}

const _: () = {
    fn assert_impl<T: Send + Sync>() {}
    #[allow(dead_code)]
    fn check() {
        assert_impl::<SecretBrokerClient>();
    }
};

#[derive(Debug, Clone)]
pub struct PostgresCredentialRequest {
    pub audience: String,
    pub scope: Vec<String>,
    pub ttl_seconds: u64,
    pub application_name: Option<String>,
}

pub type PostgresCredentialLease = GrpcPostgresCredentialLease;

impl SecretBrokerClient {
    /// Constructs a SecretBrokerClient from an existing SecretBrokerGrpcAdapter.
    ///
    /// Used when a caller already owns a configured protocol adapter.
    pub fn from_inner(adapter: SecretBrokerGrpcAdapter) -> Self {
        Self { adapter }
    }

    /// Returns a reference to the underlying gRPC adapter.
    pub fn inner(&self) -> &SecretBrokerGrpcAdapter {
        &self.adapter
    }

    pub async fn from_env() -> Result<Self> {
        let config = SecretBrokerClientConfig::from_env()?;
        Self::new(config).await
    }

    pub async fn new(config: SecretBrokerClientConfig) -> Result<Self> {
        let tls = build_tls_config(&config)?;
        let lazy = matches!(config.attestation_mode, AttestationMode::Disabled);

        // Build channel: TLS connector or plain, lazy or eager
        let channel = build_channel(&config.endpoint, config.timeout, tls, lazy)
            .await
            .context("failed to establish secret-broker gRPC channel")?;

        let adapter_config = SecretBrokerGrpcAdapterConfig::new(config.endpoint.clone(), channel);
        let adapter = SecretBrokerGrpcAdapter::new(adapter_config);

        Ok(Self { adapter })
    }

    pub async fn issue_postgres_credentials(
        &self,
        request: PostgresCredentialRequest,
    ) -> Result<PostgresCredentialLease> {
        let PostgresCredentialRequest {
            audience,
            scope,
            ttl_seconds,
            application_name,
        } = request;

        metrics::counter!("secure_database_broker_lease_attempt_total", 1);

        let params = PostgresCredentialParams {
            audience: audience.trim().to_string(),
            scope,
            ttl_seconds: if ttl_seconds == 0 {
                None
            } else {
                Some(ttl_seconds)
            },
            application_name,
        };

        match self.adapter.issue_postgres_credentials(params).await {
            Ok(lease) => {
                metrics::counter!("secure_database_broker_lease_success_total", 1);
                Ok(lease)
            }
            Err(err) => {
                metrics::counter!("secure_database_broker_lease_failure_total", 1);
                Err(err)
            }
        }
    }

    pub async fn mint_aead_key_v2(
        &self,
        params: MintAeadKeyV2Params,
    ) -> Result<MintAeadKeyV2Lease> {
        metrics::counter!("secure_database_broker_aead_v2_request_total", 1);
        match self.adapter.mint_aead_key_v2(params).await {
            Ok(lease) => {
                metrics::counter!("secure_database_broker_aead_v2_success_total", 1);
                Ok(lease)
            }
            Err(err) => {
                metrics::counter!("secure_database_broker_aead_v2_failure_total", 1);
                Err(err)
            }
        }
    }

    pub async fn wrap_secret_v2(
        &self,
        plaintext: &[u8],
        params: WrapV2Params,
    ) -> Result<WrapResponse> {
        metrics::counter!("secure_database_broker_wrap_v2_attempt_total", 1);
        match self.adapter.wrap_bytes_v2(plaintext, params).await {
            Ok(response) => {
                metrics::counter!("secure_database_broker_wrap_v2_success_total", 1);
                Ok(response)
            }
            Err(err) => {
                metrics::counter!("secure_database_broker_wrap_v2_failure_total", 1);
                Err(err)
            }
        }
    }

    pub fn preload_redeem_token(
        &self,
        handle: impl Into<String>,
        token: impl Into<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        self.adapter.preload_redeem_token(handle, token, expires_at)
    }

    pub fn preload_redeem_shares(
        &self,
        handle: impl Into<String>,
        shares: Vec<ThresholdShareMaterial>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        self.adapter
            .preload_redeem_shares(handle, shares, expires_at)
    }

    pub async fn unwrap_secret_v2(&self, params: UnwrapSecretV2Params) -> Result<Vec<u8>> {
        metrics::counter!("secure_database_broker_unwrap_v2_attempt_total", 1);
        match self.adapter.unwrap_secret_v2(params).await {
            Ok(bytes) => {
                metrics::counter!("secure_database_broker_unwrap_v2_success_total", 1);
                Ok(bytes)
            }
            Err(err) => {
                metrics::counter!("secure_database_broker_unwrap_v2_failure_total", 1);
                Err(err)
            }
        }
    }

    pub async fn unwrap_secret_v2_with_token(
        &self,
        handle: &str,
        redeem_token_b64: &str,
    ) -> Result<Vec<u8>> {
        self.unwrap_secret_v2(UnwrapSecretV2Params {
            handle: handle.trim().to_string(),
            redeem_token: Some(redeem_token_b64.trim().to_string()),
            redeem_shares: vec![],
            tenant_id: None,
            provider: None,
            circuit_id: None,
            node_id: None,
            discharges: vec![],
        })
        .await
    }

    /// Renew the lease on a RenewableLease secret.
    pub async fn renew_lease(
        &self,
        handle: &str,
        lease_duration_seconds: u64,
    ) -> Result<RenewLeaseResult> {
        self.adapter
            .renew_lease(handle, lease_duration_seconds)
            .await
    }

    /// Explicitly revoke a secret, making it permanently inaccessible.
    pub async fn revoke_secret(&self, handle: &str, reason: Option<&str>) -> Result<RevokeResult> {
        self.adapter.revoke_secret(handle, reason).await
    }

    /// Atomically wrap a new secret and revoke an old one (key rotation).
    pub async fn rotate_secret(
        &self,
        old_handle: &str,
        new_plaintext: &[u8],
        params: RotateParams,
    ) -> Result<RotateResult> {
        self.adapter
            .rotate_secret(old_handle, new_plaintext, params)
            .await
    }

    /// Add further first-party caveats to an existing v2 macaroon handle.
    pub async fn attenuate_handle_v2(&self, params: AttenuateHandleV2Params) -> Result<String> {
        self.adapter
            .attenuate_handle_v2(params)
            .await
            .map(|result| result.handle)
    }
}

#[derive(Clone, Debug)]
struct RaTlsServerVerifier {
    policy: ClientPolicy,
    subject_allowlist: Option<HashSet<String>>,
    pccs_url: Option<String>,
}

impl RaTlsServerVerifier {
    fn new(
        policy: ClientPolicy,
        subject_allowlist: Option<HashSet<String>>,
        pccs_url: Option<String>,
    ) -> Self {
        Self {
            policy,
            subject_allowlist,
            pccs_url,
        }
    }
}

// Normalize SPIFFE ID: lowercase trust domain, preserve path
fn normalize_spiffe_id(uri: &str) -> Option<String> {
    if !uri.starts_with("spiffe://") {
        return None;
    }
    let rest = &uri[9..];
    let slash = rest.find('/')?;
    let td = &rest[..slash];
    let path = &rest[slash..];
    if td.is_empty() || !path.starts_with('/') {
        return None;
    }
    Some(format!("spiffe://{}{}", td.to_ascii_lowercase(), path))
}

// SPIFFE server certificate verifier using WebPki delegation
#[derive(Debug)]
struct SpiffeServerVerifier {
    inner: Arc<WebPkiServerVerifier>,
    allowed: String,
}

impl SpiffeServerVerifier {
    fn new(root_store: Arc<RootCertStore>, allowed_spiffe_id: String) -> Result<Self, RustlsError> {
        let inner = WebPkiServerVerifier::builder(root_store)
            .build()
            .map_err(|e| {
                RustlsError::General(format!("failed to build WebPkiServerVerifier: {}", e))
            })?;
        let allowed = normalize_spiffe_id(&allowed_spiffe_id).ok_or_else(|| {
            RustlsError::General(format!("invalid target SPIFFE ID: {}", allowed_spiffe_id))
        })?;
        Ok(Self { inner, allowed })
    }
}

impl ServerCertVerifier for SpiffeServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // First, delegate to WebPkiServerVerifier for standard chain validation
        let _ = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)?;

        // Then enforce exactly one URI SAN matching the allowed SPIFFE ID
        let (_rem, cert) = x509_parser::parse_x509_certificate(end_entity.as_ref())
            .map_err(|_| RustlsError::General("failed to parse server cert".into()))?;

        let mut uris: Vec<&str> = Vec::new();
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for gn in san.value.general_names.iter() {
                if let x509_parser::extensions::GeneralName::URI(uri) = gn {
                    uris.push(*uri);
                }
            }
        }

        if uris.len() != 1 {
            return Err(RustlsError::General(
                "SPIFFE server cert must have exactly one URI SAN".into(),
            ));
        }

        let presented = uris[0];
        let presented_norm = normalize_spiffe_id(presented).ok_or_else(|| {
            RustlsError::General("presented SAN URI is not a valid SPIFFE ID".into())
        })?;

        if presented_norm != self.allowed {
            return Err(RustlsError::General(
                "server SPIFFE ID not authorised".into(),
            ));
        }

        tracing::debug!(spiffe_id = %presented, "SPIFFE server certificate verified");
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ServerCertVerifier for RaTlsServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let certificate = CertificateDer::from(end_entity.as_ref().to_vec());
        let policy = self.policy.clone();
        let allowlist = self.subject_allowlist.clone();
        let pccs_url = self.pccs_url.clone();

        let handle = Handle::try_current().map_err(|err| {
            RustlsError::General(format!("RA-TLS verification requires Tokio runtime: {err}"))
        })?;

        let future = verify_peer_certificate_async(certificate, policy, allowlist, pccs_url);
        let result = tokio::task::block_in_place(|| handle.block_on(future));

        match result {
            Ok(()) => Ok(ServerCertVerified::assertion()),
            Err(err) => {
                warn!(error = %err, "RA-TLS server verification failed");
                Err(RustlsError::General(format!(
                    "RA-TLS verification failed: {err}"
                )))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn build_tls_config(config: &SecretBrokerClientConfig) -> Result<Option<Arc<ClientConfig>>> {
    if matches!(config.attestation_mode, AttestationMode::Local) {
        let cert_chain = match &config.client_cert_chain {
            Some(certs) => certs.clone(),
            None => load_local_client_cert_chain()?,
        };
        let private_key = match &config.client_key {
            Some(key) => key.clone_key(),
            None => load_local_client_private_key()?,
        };
        return build_local_loopback_client_config(cert_chain, private_key).map(Some);
    }

    // Disabled mode is restricted to loopback debug builds by configuration validation.
    if matches!(config.attestation_mode, AttestationMode::Disabled) {
        return Ok(None);
    }

    // SPIFFE mode: fetch identity from SPIRE Workload API
    if matches!(config.attestation_mode, AttestationMode::Spiffe) {
        let socket_path = config
            .spiffe_socket_path
            .as_deref()
            .unwrap_or("/var/run/spire/agent.sock");

        // We need to block on async SPIFFE operations
        let handle = Handle::try_current().context("SPIFFE TLS config requires Tokio runtime")?;

        let tls_config = tokio::task::block_in_place(|| {
            handle.block_on(async {
                let socket_endpoint = format!("unix:{}", socket_path);
                let mut client = WorkloadApiClient::new_from_path(&socket_endpoint)
                    .await
                    .context("failed to connect to SPIRE Workload API")?;

                // Fetch X.509 SVID for client identity
                let svid = client
                    .fetch_x509_svid()
                    .await
                    .context("failed to fetch X509 SVID from SPIRE")?;

                // Fetch trust bundles for server verification
                let bundles = client
                    .fetch_x509_bundles()
                    .await
                    .context("failed to fetch X509 bundles from SPIRE")?;

                // Get trust domain from SVID for bundle lookup
                let spiffe_id = svid.spiffe_id();
                let trust_domain = spiffe_id.trust_domain();

                // Build root cert store from trust bundles
                let mut root_store = RootCertStore::empty();
                if let Some(bundle) = bundles.get_bundle(&trust_domain) {
                    for authority in bundle.authorities() {
                        let cert_der = CertificateDer::from(authority.content().to_vec());
                        root_store.add(cert_der).map_err(|_| {
                            anyhow!("failed to add SPIFFE authority cert to root store")
                        })?;
                    }
                } else {
                    return Err(anyhow!(
                        "no SPIFFE bundle found for trust domain: {}",
                        trust_domain
                    ));
                }

                // Get client cert chain and key from SVID
                let client_certs: Vec<CertificateDer<'static>> = svid
                    .cert_chain()
                    .iter()
                    .map(|c| CertificateDer::from(c.content().to_vec()))
                    .collect();

                let client_key = PrivateKeyDer::try_from(svid.private_key().content().to_vec())
                    .map_err(|_| anyhow!("failed to parse SVID private key"))?;

                // Build TLS config with SPIFFE server certificate verification
                let mut tls_config = ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::aws_lc_rs::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .context("failed to configure TLS protocol versions")?
                .with_root_certificates(root_store.clone())
                .with_client_auth_cert(client_certs, client_key)
                .context("failed to configure SPIFFE client certificate")?;

                tls_config.alpn_protocols = vec![b"h2".to_vec()];

                // Use custom SPIFFE verifier that validates URI SANs
                let target_spiffe_id =
                    std::env::var("SECRET_BROKER_TARGET_SPIFFE_ID").map_err(|_| {
                        anyhow!("SECRET_BROKER_TARGET_SPIFFE_ID is required in SPIFFE mode")
                    })?;
                let verifier = Arc::new(
                    SpiffeServerVerifier::new(Arc::new(root_store), target_spiffe_id)
                        .map_err(|e| anyhow::anyhow!("failed to create SPIFFE verifier: {}", e))?,
                );
                tls_config.dangerous().set_certificate_verifier(verifier);

                Ok::<_, anyhow::Error>(Arc::new(tls_config))
            })
        })?;

        return Ok(Some(tls_config));
    }

    // Verified mTLS modes (enforced/local): use the custom verifier.
    let builder = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("failed to configure TLS protocol versions")?
    .with_root_certificates(RootCertStore::empty());

    let mut tls_config =
        if let (Some(certs), Some(key)) = (&config.client_cert_chain, &config.client_key) {
            builder
                .with_client_auth_cert(certs.clone(), key.clone_key())
                .context("failed to configure client certificate for secret-broker")?
        } else {
            builder.with_no_client_auth()
        };

    tls_config.alpn_protocols = vec![b"h2".to_vec()];

    let verifier = Arc::new(RaTlsServerVerifier::new(
        config.policy.clone(),
        config.subject_allowlist.clone(),
        config.pccs_url.clone(),
    ));
    tls_config.dangerous().set_certificate_verifier(verifier);

    Ok(Some(Arc::new(tls_config)))
}

fn build_local_loopback_client_config(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<Arc<ClientConfig>> {
    let ca_path = local_loopback_ca_cert_path()?;
    let ca_bytes = fs::read(&ca_path).with_context(|| {
        format!(
            "failed to read local loopback CA cert from {}",
            ca_path.display()
        )
    })?;
    let mut root_store = RootCertStore::empty();
    let ca_certs = certs(&mut Cursor::new(ca_bytes))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to parse local loopback CA cert bundle")?;
    if ca_certs.is_empty() {
        bail!("local loopback CA bundle did not contain any certificates");
    }
    for cert in ca_certs {
        root_store
            .add(cert)
            .map_err(|err| anyhow!("failed to add local loopback CA certificate: {err}"))?;
    }

    let mut tls_config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("failed to configure TLS protocol versions")?
    .with_root_certificates(root_store)
    .with_client_auth_cert(cert_chain, private_key)
    .context("failed to configure local loopback client certificate")?;
    tls_config.alpn_protocols = vec![b"h2".to_vec()];

    Ok(Arc::new(tls_config))
}

fn parse_cert_chain(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut cursor = Cursor::new(bytes);
    let mut certs = Vec::new();
    for item in read_all(&mut cursor) {
        match item? {
            Item::X509Certificate(cert) => certs.push(cert.into_owned()),
            _ => {}
        }
    }
    if certs.is_empty() {
        bail!("no certificates found in client bundle");
    }
    Ok(certs)
}

fn parse_private_key(bytes: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut cursor = Cursor::new(bytes);
    for item in read_all(&mut cursor) {
        match item? {
            Item::Pkcs8Key(key) => return Ok(PrivateKeyDer::from(key.clone_key())),
            Item::Pkcs1Key(key) => return Ok(PrivateKeyDer::from(key.clone_key())),
            Item::Sec1Key(key) => return Ok(PrivateKeyDer::from(key.clone_key())),
            _ => {}
        }
    }
    bail!("no private key found in bundle")
}

fn local_loopback_ca_cert_path() -> Result<std::path::PathBuf> {
    env::var("SECRET_BROKER_TLS_CA_CERT")
        .map(std::path::PathBuf::from)
        .map_err(|_| anyhow!("SECRET_BROKER_TLS_CA_CERT is required in local mode"))
}

fn local_loopback_client_cert_path() -> Result<std::path::PathBuf> {
    env::var("SECRET_BROKER_CLIENT_CERT")
        .map(std::path::PathBuf::from)
        .map_err(|_| anyhow!("SECRET_BROKER_CLIENT_CERT is required in local mode"))
}

fn local_loopback_client_key_path() -> Result<std::path::PathBuf> {
    env::var("SECRET_BROKER_CLIENT_KEY")
        .map(std::path::PathBuf::from)
        .map_err(|_| anyhow!("SECRET_BROKER_CLIENT_KEY is required in local mode"))
}

fn load_local_client_cert_chain() -> Result<Vec<CertificateDer<'static>>> {
    let cert_path = local_loopback_client_cert_path()?;
    let cert_bytes = fs::read(&cert_path).with_context(|| {
        format!(
            "failed to read local loopback client cert from {}",
            cert_path.display()
        )
    })?;
    parse_cert_chain(&cert_bytes)
}

fn load_local_client_private_key() -> Result<PrivateKeyDer<'static>> {
    let key_path = local_loopback_client_key_path()?;
    let key_bytes = fs::read(&key_path).with_context(|| {
        format!(
            "failed to read local loopback client key from {}",
            key_path.display()
        )
    })?;
    parse_private_key(&key_bytes)
}

fn ensure_attestation_mode(mode: AttestationMode) -> Result<()> {
    // Enforced, SPIFFE, and local pinned-mTLS modes always verify peer identity.
    if mode.is_enforced() || matches!(mode, AttestationMode::Spiffe | AttestationMode::Local) {
        return Ok(());
    }

    let debug_build = cfg!(debug_assertions);

    if debug_build {
        if env::var(UNSAFE_FLAG_ENV)
            .ok()
            .map(|raw| matches!(raw.trim().to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false)
        {
            warn!(
                mode = ?mode,
                flag = UNSAFE_FLAG_ENV,
                "secret-broker client running with relaxed attestation in debug build"
            );
            return Ok(());
        }

        return Err(anyhow!(
            "secret-broker attestation mode {mode:?} requires {UNSAFE_FLAG_ENV}=1 and a debug build"
        ));
    }

    Err(anyhow!(
        "secret-broker attestation mode {mode:?} is forbidden in release builds"
    ))
}

fn secret_broker_endpoint_is_loopback(endpoint: &Url) -> bool {
    let Some(host) = endpoint.host_str() else {
        return false;
    };

    let normalized = host.trim().to_ascii_lowercase();
    if normalized == "localhost" || normalized.ends_with(".localhost") {
        return true;
    }

    normalized
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

async fn verify_peer_certificate_async(
    certificate: CertificateDer<'static>,
    policy: ClientPolicy,
    subject_allowlist: Option<HashSet<String>>,
    pccs_url: Option<String>,
) -> Result<()> {
    let (_, cert) = X509Certificate::from_der(certificate.as_ref())
        .map_err(|err| anyhow!("failed to parse X.509 certificate: {err}"))?;

    let subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string());

    if let Some(allowlist) = &subject_allowlist {
        let subject = subject_cn
            .as_deref()
            .ok_or_else(|| anyhow!("server certificate has no common name"))?;
        let lower = subject.trim().to_lowercase();
        if !allowlist.contains(&lower) {
            bail!("server subject {subject} not in allowlist");
        }
    }

    let attestation = Attestation::from_der(certificate.as_ref())
        .context("failed to parse RA-TLS attestation")?
        .ok_or_else(|| anyhow!("certificate does not contain RA-TLS attestation"))?;

    let pubkey = cert.public_key().subject_public_key.data.to_vec();

    let verified = attestation
        .verify_with_ra_pubkey(&pubkey, pccs_url.as_deref())
        .await
        .context("RA-TLS attestation verification failed")?;

    let compose_hash = verified
        .decode_compose_hash()
        .ok()
        .filter(|h| !h.is_empty());

    if policy.measurement.expects_compose_hash() {
        let compose_hash = compose_hash
            .as_deref()
            .ok_or_else(|| anyhow!("attestation missing compose hash while policy requires it"))?;
        if !policy.measurement.allows_compose_hash(compose_hash) {
            bail!("compose hash {compose_hash} rejected by policy");
        }
    } else if let Some(hash) = compose_hash.as_deref() {
        if !policy.measurement.allows_compose_hash(hash) {
            bail!("compose hash {hash} rejected by policy");
        }
    }

    enforce_measurement_policy(&policy.measurement, &verified)
}

fn enforce_measurement_policy(
    policy: &MeasurementPolicy,
    verified: &VerifiedAttestation,
) -> Result<()> {
    match &verified.report.report {
        Report::TD10(td10) => {
            let mrtd = hex_encode(td10.mr_td);
            if !policy.allows_tdx_mrtd(&mrtd) {
                bail!("TDX MR_TD {mrtd} rejected by policy");
            }
        }
        Report::TD15(td15) => {
            let mrtd = hex_encode(td15.base.mr_td);
            if !policy.allows_tdx_mrtd(&mrtd) {
                bail!("TDX (TD15) MR_TD {mrtd} rejected by policy");
            }
        }
        Report::SgxEnclave(enclave) => {
            let mrenclave = hex_encode(enclave.mr_enclave);
            let mrsigner = hex_encode(enclave.mr_signer);
            if !policy.allows_sgx_measurements(&mrenclave, &mrsigner, enclave.isv_svn) {
                bail!(
                    "SGX measurements rejected (mrenclave={mrenclave}, mrsigner={mrsigner}, isv_svn={})",
                    enclave.isv_svn
                );
            }
        }
    }
    Ok(())
}

/// Build a gRPC channel with optional TLS. Lazy connect defers TCP to first RPC call.
async fn build_channel(
    endpoint: &Url,
    timeout: StdDuration,
    tls_config: Option<Arc<ClientConfig>>,
    lazy: bool,
) -> Result<tonic::transport::Channel> {
    use tonic::transport::{ClientTlsConfig, Endpoint};

    if let Some(client_config) = tls_config {
        // TLS mode: use connect_with_connector to apply our custom rustls config
        let mut canonical = endpoint.clone();
        let _ = canonical.set_scheme("http");
        let endpoint_str = canonical.to_string();
        let ep = Endpoint::from_shared(endpoint_str)
            .context("invalid secret broker endpoint")?
            .connect_timeout(timeout);

        let connector_state = ConnectorState {
            config: client_config,
            timeout: Some(timeout),
        };
        let connector = tower::service_fn(move |uri: tonic::transport::Uri| {
            let s = connector_state.clone();
            async move {
                let host = uri.host().unwrap_or("localhost").to_owned();
                let port = uri.port_u16().unwrap_or(443);
                let addr = format!("{host}:{port}");

                let tcp = tokio::time::timeout(
                    s.timeout.unwrap_or(StdDuration::from_secs(10)),
                    tokio::net::TcpStream::connect(&addr),
                )
                .await
                .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
                    format!("TCP connect {addr} timed out").into()
                })?
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    format!("TCP connect {addr}: {e}").into()
                })?;
                tcp.set_nodelay(true).ok();

                let server_name = match host.parse::<std::net::IpAddr>() {
                    Ok(ip) => rustls::pki_types::ServerName::IpAddress(ip.into()),
                    Err(_) => rustls::pki_types::ServerName::try_from(host.clone()).map_err(
                        |e| -> Box<dyn std::error::Error + Send + Sync> {
                            format!("bad DNS name {host}: {e}").into()
                        },
                    )?,
                };

                let tls = tokio_rustls::TlsConnector::from(s.config.clone())
                    .connect(server_name, tcp)
                    .await
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                        format!("TLS handshake {addr}: {e}").into()
                    })?;

                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(hyper_util::rt::TokioIo::new(tls))
            }
        });

        if lazy {
            return Ok(ep.connect_with_connector_lazy(connector));
        }
        return ep
            .connect_with_connector(connector)
            .await
            .map_err(|e| anyhow!("connect: {e}"));
    }

    // Non-TLS mode
    let endpoint_str = endpoint.to_string();
    let ep = Endpoint::from_shared(endpoint_str)
        .context("invalid secret broker endpoint")?
        .connect_timeout(timeout);

    let ep = if endpoint.scheme() == "https" {
        ep.tls_config(ClientTlsConfig::new().with_enabled_roots())?
    } else {
        ep
    };

    if lazy {
        return Ok(ep.connect_lazy());
    }
    ep.connect()
        .await
        .context("failed to connect to secret-broker gRPC endpoint")
}

#[derive(Clone)]
struct ConnectorState {
    config: Arc<ClientConfig>,
    timeout: Option<StdDuration>,
}
