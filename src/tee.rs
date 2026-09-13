//! Trusted Execution Environment utilities built on top of the dstack (Phala) SDK.
//!
//! This module wraps the low-level dstack/tappd clients and exposes helpers for
//! fetching remote attestation data,
//! deriving TLS keys, and emitting structured audit events.

use crate::{error::DatabaseError, DbResult};
use anyhow;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use dstack_sdk::{
    dstack_client::{DstackClient, GetKeyResponse, GetTlsKeyResponse, InfoResponse, TlsKeyConfig},
    tappd_client::TappdClient,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use std::env;
use tracing::instrument;

/// Configuration for instantiating a [`TeeClient`].
#[derive(Clone, Debug, Default)]
pub struct TeeEndpointConfig {
    /// Optional override for the dstack endpoint (unix socket path or HTTP URL).
    pub dstack_endpoint: Option<String>,
    /// Optional override for the tappd endpoint (unix socket path or HTTP URL).
    pub tappd_endpoint: Option<String>,
    /// Optional 64-byte report data supplied to attestation requests.
    report_data: Option<Vec<u8>>,
}

impl TeeEndpointConfig {
    /// Load configuration from `SECURE_DB_DSTACK_ENDPOINT`,
    /// `SECURE_DB_TAPPD_ENDPOINT`, and `SECURE_DB_TEE_REPORT_DATA`.
    pub fn from_env() -> DbResult<Self> {
        let dstack_endpoint = env::var("SECURE_DB_DSTACK_ENDPOINT").ok();
        let tappd_endpoint = env::var("SECURE_DB_TAPPD_ENDPOINT").ok();
        let report_data = env::var("SECURE_DB_TEE_REPORT_DATA")
            .ok()
            .map(|raw| decode_report_data(&raw))
            .transpose()
            .map_err(|error| DatabaseError::Configuration(error.to_string()))?;

        Ok(Self {
            dstack_endpoint,
            tappd_endpoint,
            report_data,
        })
    }

    /// Report data supplied to the quote endpoint (defaults to 64 zero bytes).
    pub fn report_data(&self) -> Vec<u8> {
        if let Some(data) = &self.report_data {
            return data.clone();
        }
        vec![0u8; 64]
    }
}

fn decode_report_data(raw: &str) -> Result<Vec<u8>, anyhow::Error> {
    if let Ok(bytes) = hex::decode(raw) {
        if bytes.len() == 64 {
            return Ok(bytes);
        }
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(raw) {
        if bytes.len() == 64 {
            return Ok(bytes);
        }
    }
    anyhow::bail!("report data must be 64 bytes hex or base64 encoded")
}

/// High-level wrapper around the dstack/tappd clients.
pub struct TeeClient {
    dstack: DstackClient,
    tappd: TappdClient,
    report_data: Vec<u8>,
}

impl TeeClient {
    /// Build a new client from the provided configuration.
    pub fn new(config: TeeEndpointConfig) -> Self {
        Self {
            dstack: DstackClient::new(config.dstack_endpoint.as_deref()),
            tappd: TappdClient::new(config.tappd_endpoint.as_deref()),
            report_data: config.report_data(),
        }
    }

    /// Retrieve the current attestation information and event log from the TEE.
    #[instrument(name = "tee.attest", skip(self))]
    pub async fn attest(&self) -> DbResult<TeeAttestation> {
        let info = self
            .dstack
            .info()
            .await
            .map_err(|e| DatabaseError::Attestation(e.to_string()))?;
        let quote = self
            .dstack
            .get_quote(self.report_data.clone())
            .await
            .map_err(|e| DatabaseError::Attestation(e.to_string()))?;

        let rtmr = quote
            .replay_rtmrs()
            .map_err(|e| DatabaseError::Attestation(e.to_string()))?;
        let rtmr_json =
            serde_json::to_value(rtmr).map_err(|e| DatabaseError::Attestation(e.to_string()))?;
        let event_log_json: JsonValue = serde_json::from_str(&quote.event_log)
            .map_err(|e| DatabaseError::Attestation(e.to_string()))?;
        let quote_bytes = quote
            .decode_quote()
            .map_err(|e| DatabaseError::Attestation(e.to_string()))?;

        Ok(TeeAttestation {
            app_id: info.app_id,
            instance_id: info.instance_id,
            device_id: info.device_id,
            compose_hash: info.compose_hash,
            key_provider_info: info.key_provider_info,
            quote: quote_bytes,
            rtmr: rtmr_json,
            event_log: event_log_json,
            recorded_at: Utc::now(),
        })
    }

    /// Emit an authenticated audit event to the dstack runtime.
    #[instrument(name = "tee.emit_event", skip(self, payload))]
    pub async fn emit_event(&self, event: &str, payload: &[u8]) -> DbResult<()> {
        self.dstack
            .emit_event(event.to_string(), payload.to_vec())
            .await
            .map_err(|e| DatabaseError::Attestation(e.to_string()))
    }

    /// Retrieve a sealed key from the TEE key manager.
    pub async fn get_key(&self, path: &str) -> DbResult<GetKeyResponse> {
        self.dstack
            .get_key(Some(path.to_string()), None)
            .await
            .map_err(|e| DatabaseError::Attestation(e.to_string()))
    }

    /// Derive a TLS key using the provided configuration.
    pub async fn derive_tls_key(&self, config: TlsKeyConfig) -> DbResult<GetTlsKeyResponse> {
        self.dstack
            .get_tls_key(config)
            .await
            .map_err(|e| DatabaseError::Attestation(e.to_string()))
    }

    /// Fetch information about the dstack instance.
    pub async fn info(&self) -> DbResult<InfoResponse> {
        self.dstack
            .info()
            .await
            .map_err(|e| DatabaseError::Attestation(e.to_string()))
    }

    /// Expose the underlying tappd client for advanced flows.
    pub fn tappd(&self) -> &TappdClient {
        &self.tappd
    }
}

/// Materialised attestation data ready for persistence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeAttestation {
    pub app_id: String,
    pub instance_id: String,
    pub device_id: String,
    pub compose_hash: String,
    pub key_provider_info: String,
    pub quote: Vec<u8>,
    pub rtmr: JsonValue,
    pub event_log: JsonValue,
    pub recorded_at: DateTime<Utc>,
}

impl TeeAttestation {
    /// Provide a JSON payload suitable for audit logging.
    pub fn as_audit_payload(&self) -> JsonValue {
        json!({
            "app_id": self.app_id,
            "instance_id": self.instance_id,
            "device_id": self.device_id,
            "compose_hash": self.compose_hash,
            "recorded_at": self.recorded_at,
        })
    }
}
