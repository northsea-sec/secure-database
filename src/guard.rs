use crate::{DatabaseError, DbResult, PgPool};
use chrono::{DateTime, Utc};

#[derive(Debug, Default, Clone, Copy)]
pub struct GuardSuccessUpdate {
    pub uptime_ratio: Option<f64>,
    pub asn: Option<i64>,
    pub rpki_valid: Option<bool>,
    pub pow_score: Option<f64>,
    pub rtt_p50_ms: Option<f64>,
    pub rtt_p95_ms: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct GuardHealthSnapshot {
    pub guard_fpr: String,
    pub first_seen: DateTime<Utc>,
    pub last_ok: DateTime<Utc>,
    pub fail_count: i32,
    pub uptime_ratio: Option<f64>,
    pub asn: Option<i64>,
    pub rpki_valid: Option<bool>,
    pub pow_score: Option<f64>,
    pub rtt_p50_ms: Option<f64>,
    pub rtt_p95_ms: Option<f64>,
    pub tee_capable: bool,
    pub tee_label: Option<String>,
    pub tee_policy: Option<String>,
    pub tee_verified_at: Option<DateTime<Utc>>,
}

impl PgPool {
    /// Record a successful guard observation and refresh the associated telemetry.
    pub async fn note_guard_success(
        &self,
        guard_fpr: &str,
        update: GuardSuccessUpdate,
    ) -> DbResult<()> {
        let pool = self.inner();
        sqlx::query!(
            r#"
            INSERT INTO gateway_data.guard_health (
                guard_fpr, first_seen, last_ok, fail_count, uptime_ratio,
                asn, rpki_valid, pow_score, rtt_p50_ms, rtt_p95_ms
            ) VALUES ($1, NOW(), NOW(), 0, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (guard_fpr) DO UPDATE SET
                last_ok = NOW(),
                uptime_ratio = COALESCE($2, guard_health.uptime_ratio),
                asn = COALESCE($3, guard_health.asn),
                rpki_valid = COALESCE($4, guard_health.rpki_valid),
                pow_score = COALESCE($5, guard_health.pow_score),
                rtt_p50_ms = COALESCE($6, guard_health.rtt_p50_ms),
                rtt_p95_ms = COALESCE($7, guard_health.rtt_p95_ms)
            "#,
            guard_fpr,
            update.uptime_ratio,
            update.asn,
            update.rpki_valid,
            update.pow_score,
            update.rtt_p50_ms,
            update.rtt_p95_ms
        )
        .execute(pool.as_ref())
        .await
        .map_err(DatabaseError::from)?;

        Ok(())
    }

    /// Increment the failure counter for a guard fingerprint.
    pub async fn note_guard_failure(&self, guard_fpr: &str) -> DbResult<i64> {
        let record = sqlx::query!(
            r#"
            INSERT INTO gateway_data.guard_health (guard_fpr, first_seen, last_ok, fail_count)
            VALUES ($1, NOW(), NOW(), 1)
            ON CONFLICT (guard_fpr) DO UPDATE SET
                fail_count = guard_health.fail_count + 1
            RETURNING fail_count
            "#,
            guard_fpr
        )
        .fetch_one(self.inner().as_ref())
        .await
        .map_err(DatabaseError::from)?;

        Ok(record.fail_count as i64)
    }

    /// Retrieve the most recent guard health rows, ordered by last success time.
    pub async fn list_guard_health(&self, limit: i64) -> DbResult<Vec<GuardHealthSnapshot>> {
        let records = sqlx::query_as!(
            GuardHealthRow,
            r#"
            SELECT guard_fpr, first_seen, last_ok, fail_count, uptime_ratio,
                   asn, rpki_valid, pow_score, rtt_p50_ms, rtt_p95_ms,
                   tee_capable, tee_label, tee_policy, tee_verified_at
            FROM gateway_data.guard_health
            ORDER BY last_ok DESC
            LIMIT $1
            "#,
            limit
        )
        .fetch_all(self.inner().as_ref())
        .await
        .map_err(DatabaseError::from)?;

        Ok(records.into_iter().map(Into::into).collect())
    }

    /// Set the TEE capability metadata for a guard relay.
    pub async fn set_guard_tee_status(
        &self,
        guard_fpr: &str,
        tee_capable: bool,
        tee_label: Option<&str>,
        tee_policy: Option<&str>,
    ) -> DbResult<()> {
        sqlx::query!(
            r#"
            INSERT INTO gateway_data.guard_health (
                guard_fpr, first_seen, last_ok, fail_count, tee_capable, tee_label, tee_policy, tee_verified_at
            ) VALUES ($1, NOW(), NOW(), 0, $2, $3, $4, NOW())
            ON CONFLICT (guard_fpr) DO UPDATE SET
                tee_capable = EXCLUDED.tee_capable,
                tee_label = EXCLUDED.tee_label,
                tee_policy = EXCLUDED.tee_policy,
                tee_verified_at = NOW()
            "#,
            guard_fpr,
            tee_capable,
            tee_label,
            tee_policy
        )
        .execute(self.inner().as_ref())
        .await
        .map_err(DatabaseError::from)?;

        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct GuardHealthRow {
    guard_fpr: String,
    first_seen: DateTime<Utc>,
    last_ok: DateTime<Utc>,
    fail_count: i32,
    uptime_ratio: Option<f64>,
    asn: Option<i64>,
    rpki_valid: Option<bool>,
    pow_score: Option<f64>,
    rtt_p50_ms: Option<f64>,
    rtt_p95_ms: Option<f64>,
    tee_capable: bool,
    tee_label: Option<String>,
    tee_policy: Option<String>,
    tee_verified_at: Option<DateTime<Utc>>,
}

impl From<GuardHealthRow> for GuardHealthSnapshot {
    fn from(row: GuardHealthRow) -> Self {
        Self {
            guard_fpr: row.guard_fpr,
            first_seen: row.first_seen,
            last_ok: row.last_ok,
            fail_count: row.fail_count,
            uptime_ratio: row.uptime_ratio,
            asn: row.asn,
            rpki_valid: row.rpki_valid,
            pow_score: row.pow_score,
            rtt_p50_ms: row.rtt_p50_ms,
            rtt_p95_ms: row.rtt_p95_ms,
            tee_capable: row.tee_capable,
            tee_label: row.tee_label,
            tee_policy: row.tee_policy,
            tee_verified_at: row.tee_verified_at,
        }
    }
}
