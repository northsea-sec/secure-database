use crate::{DatabaseError, DbResult, PgPool};
use chrono::{DateTime, Utc};
use hex::FromHex;
use serde_json::Value;

impl PgPool {
    /// Register a freshly observed attestation nonce. Returns `true` if the nonce was new
    /// and inserted, or `false` if it had already been seen (replay attempt).
    pub async fn register_attestation_nonce(
        &self,
        nonce_digest: &[u8],
        enclave_id: &str,
        ttl_seconds: i64,
    ) -> DbResult<bool> {
        let ttl = ttl_seconds.max(0);

        // Best-effort pruning of stale entries to keep the nonce window bounded.
        sqlx::query!(
            "DELETE FROM gateway_secrets.ra_nonce_log WHERE seen_at < NOW() - ($1::bigint * INTERVAL '1 second')",
            ttl
        )
        .execute(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;

        let result = sqlx::query!(
            "INSERT INTO gateway_secrets.ra_nonce_log (nonce_digest, enclave_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            nonce_digest,
            enclave_id
        )
        .execute(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;

        Ok(result.rows_affected() > 0)
    }

    /// Persist the attestation decision for a recently verified quote so operators
    /// can audit outcomes and short-circuit duplicate verifications inside a small window.
    pub async fn cache_attestation_decision(
        &self,
        quote_hash: &[u8],
        tee: &str,
        expires_at: DateTime<Utc>,
        decision: Value,
    ) -> DbResult<()> {
        sqlx::query!("DELETE FROM gateway_secrets.ra_attestation_cache WHERE expires_at < NOW()")
            .execute(self.secrets().as_ref())
            .await
            .map_err(DatabaseError::from)?;

        sqlx::query!(
            r#"INSERT INTO gateway_secrets.ra_attestation_cache (quote_hash, tee, decision, expires_at)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (quote_hash) DO UPDATE
               SET tee = EXCLUDED.tee,
                   decision = EXCLUDED.decision,
                   expires_at = EXCLUDED.expires_at"#,
            quote_hash,
            tee,
            decision,
            expires_at
        )
        .execute(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;

        Ok(())
    }

    pub async fn invalidate_attestation_artifacts(
        &self,
        quote_hash_hex: &str,
        nonce_digest_hex: Option<&str>,
    ) -> DbResult<()> {
        let quote_hash_bytes = Vec::from_hex(quote_hash_hex.trim()).map_err(|_| {
            DatabaseError::Integrity(
                "invalid quote hash provided for attestation invalidation".into(),
            )
        })?;

        sqlx::query!(
            "DELETE FROM gateway_secrets.ra_attestation_cache WHERE quote_hash = $1",
            quote_hash_bytes
        )
        .execute(self.secrets().as_ref())
        .await
        .map_err(DatabaseError::from)?;

        if let Some(nonce_hex) = nonce_digest_hex {
            if !nonce_hex.trim().is_empty() {
                let nonce_bytes = Vec::from_hex(nonce_hex.trim()).map_err(|_| {
                    DatabaseError::Integrity(
                        "invalid nonce digest provided for attestation invalidation".into(),
                    )
                })?;

                sqlx::query!(
                    "DELETE FROM gateway_secrets.ra_nonce_log WHERE nonce_digest = $1",
                    nonce_bytes
                )
                .execute(self.secrets().as_ref())
                .await
                .map_err(DatabaseError::from)?;
            }
        }

        Ok(())
    }
}
