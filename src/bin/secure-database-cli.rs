use std::{collections::HashSet, env};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use sqlx::postgres::PgPoolOptions;
use tracing::info;
use url::Url;

use secure_database::{SecretBrokerClient, SecureDatabase};

#[derive(Parser, Debug)]
#[command(
    name = "secure-database-cli",
    version,
    about = "Operational helper for secure database migrations and sealed secrets"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run PostgreSQL migrations and extension checks using TLS-enforced settings.
    MigratePostgres {
        /// Database URL (postgres://) with TLS; otherwise SECURE_DB_URL is required.
        #[arg(long)]
        database_url: Option<String>,
        /// Maximum number of pooled connections (defaults to 20).
        #[arg(long)]
        pool_max: Option<u32>,
        /// Minimum number of pooled connections (defaults to 5).
        #[arg(long)]
        pool_min: Option<u32>,
        /// Connection timeout in seconds (defaults to 10).
        #[arg(long)]
        connect_timeout: Option<u64>,
        /// Idle timeout in seconds (defaults to 300).
        #[arg(long)]
        idle_timeout: Option<u64>,
        /// Custom application name recorded in pg_stat_activity (defaults to secure-database).
        #[arg(long)]
        application_name: Option<String>,
        /// Stable owner role that should own schema objects after bootstrap.
        #[arg(long)]
        owner_role: Option<String>,
        /// Lease audience whose ephemeral roles should be reassigned back to the stable owner.
        #[arg(long = "repair-lease-audience")]
        repair_lease_audiences: Vec<String>,
    },
    /// Wrap plaintext from an environment variable into a canonical broker:v2 sealed-config JSON file.
    WrapSecretV2 {
        /// Environment variable containing the plaintext payload to wrap.
        #[arg(long)]
        plaintext_env: String,
        /// Output path for the canonical sealed-config JSON file.
        #[arg(long)]
        output_file: String,
        /// Secret lifecycle: single_use_unwrap, renewable_lease, or service_bootstrap.
        #[arg(long, default_value = "service_bootstrap")]
        lifecycle: String,
        /// Optional label recorded with the wrapped secret.
        #[arg(long)]
        label: Option<String>,
        /// Optional explicit unwrap principal ID.
        #[arg(long)]
        unwrap_principal_id: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging()?;
    let cli = Cli::parse();

    match cli.command {
        Command::MigratePostgres {
            database_url,
            pool_max,
            pool_min,
            connect_timeout,
            idle_timeout,
            application_name,
            owner_role,
            repair_lease_audiences,
        } => {
            migrate_postgres(
                database_url,
                pool_max,
                pool_min,
                connect_timeout,
                idle_timeout,
                application_name,
                owner_role,
                repair_lease_audiences,
            )
            .await?;
        }
        Command::WrapSecretV2 {
            plaintext_env,
            output_file,
            lifecycle,
            label,
            unwrap_principal_id,
        } => {
            wrap_secret_v2_to_file(
                plaintext_env,
                output_file,
                lifecycle,
                label,
                unwrap_principal_id,
            )
            .await?;
        }
    }

    Ok(())
}

async fn migrate_postgres(
    database_url: Option<String>,
    pool_max: Option<u32>,
    pool_min: Option<u32>,
    connect_timeout: Option<u64>,
    idle_timeout: Option<u64>,
    application_name: Option<String>,
    owner_role: Option<String>,
    repair_lease_audiences: Vec<String>,
) -> Result<()> {
    let resolved_database_url = resolve_database_url(database_url)?;
    let owner_role = owner_role
        .or_else(|| owner_role_from_database_url(&resolved_database_url))
        .ok_or_else(|| anyhow!("--owner-role is required when the database URL has no username"))?;

    env::set_var("SECURE_DB_ALLOW_STATIC", "1");
    env::set_var("SECURE_DB_ALLOW_DIRECT_BOOTSTRAP", "1");
    env::set_var("SECURE_DB_CREDENTIAL_SOURCE", "static");
    env::set_var("SECURE_DB_URL", &resolved_database_url);
    if let Some(max) = pool_max {
        env::set_var("SECURE_DB_POOL_MAX", max.to_string());
    }
    if let Some(min) = pool_min {
        env::set_var("SECURE_DB_POOL_MIN", min.to_string());
    }
    if let Some(timeout) = connect_timeout {
        env::set_var("SECURE_DB_CONNECT_TIMEOUT", timeout.to_string());
    }
    if let Some(timeout) = idle_timeout {
        env::set_var("SECURE_DB_IDLE_TIMEOUT", timeout.to_string());
    }
    if let Some(name) = application_name {
        env::set_var("SECURE_DB_APP_NAME", name);
    }

    repair_postgres_lease_ownership(&resolved_database_url, &owner_role, &repair_lease_audiences)
        .await
        .context("failed to normalize leased Postgres ownership before migrations")?;

    SecureDatabase::connect_native()
        .await
        .context("failed to run PostgreSQL migrations")?;

    info!(
        "migrations" = "postgres",
        "status" = "ok",
        "message" = "PostgreSQL migrations and extension checks completed"
    );
    Ok(())
}

fn resolve_database_url(explicit_database_url: Option<String>) -> Result<String> {
    explicit_database_url
        .or_else(|| env::var("SECURE_DB_URL").ok())
        .filter(|url| !url.trim().is_empty())
        .ok_or_else(|| anyhow!("database URL is required via --database-url or SECURE_DB_URL"))
}

fn owner_role_from_database_url(database_url: &str) -> Option<String> {
    let parsed = Url::parse(database_url).ok()?;
    let username = parsed.username().trim();
    if username.is_empty() {
        None
    } else {
        Some(username.to_string())
    }
}

async fn repair_postgres_lease_ownership(
    database_url: &str,
    owner_role: &str,
    repair_lease_audiences: &[String],
) -> Result<()> {
    if repair_lease_audiences.is_empty() {
        return Ok(());
    }

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .context("failed to connect to Postgres for lease ownership repair")?;

    let owner_exists =
        sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
            .bind(owner_role)
            .fetch_one(&pool)
            .await?;

    if !owner_exists {
        return Err(anyhow!(
            "stable Postgres owner role '{}' does not exist",
            owner_role
        ));
    }

    let mut audience_prefixes = HashSet::new();
    let mut repaired_roles = Vec::new();

    for audience in repair_lease_audiences {
        let Some(prefix) = sanitize_identifier(audience) else {
            continue;
        };
        if !audience_prefixes.insert(prefix.clone()) {
            continue;
        }

        let role_like_pattern = format!("{}\\_%", prefix);
        let lease_roles = sqlx::query_scalar::<_, String>(
            "SELECT rolname
             FROM pg_roles
             WHERE rolname LIKE $1 ESCAPE '\\'
               AND rolname <> $2
             ORDER BY rolname",
        )
        .bind(role_like_pattern)
        .bind(owner_role)
        .fetch_all(&pool)
        .await?;

        for lease_role in lease_roles {
            let reassign_sql = format!(
                "REASSIGN OWNED BY {} TO {}",
                quote_identifier(&lease_role),
                quote_identifier(owner_role)
            );
            sqlx::query(&reassign_sql).execute(&pool).await?;

            let drop_owned_sql = format!("DROP OWNED BY {}", quote_identifier(&lease_role));
            sqlx::query(&drop_owned_sql).execute(&pool).await?;

            let drop_role_sql = format!("DROP ROLE IF EXISTS {}", quote_identifier(&lease_role));
            sqlx::query(&drop_role_sql).execute(&pool).await?;

            repaired_roles.push(lease_role);
        }
    }

    if repaired_roles.is_empty() {
        info!(
            owner_role = owner_role,
            "no leased Postgres roles required ownership repair"
        );
    } else {
        info!(
            owner_role = owner_role,
            repaired_roles = ?repaired_roles,
            "reassigned leased Postgres objects to the stable owner role"
        );
    }

    Ok(())
}

fn sanitize_identifier(input: &str) -> Option<String> {
    let sanitized: String = input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    if sanitized.is_empty() {
        None
    } else {
        Some(sanitized.to_lowercase())
    }
}

fn quote_identifier(input: &str) -> String {
    format!("\"{}\"", input.replace('"', "\"\""))
}

fn init_logging() -> Result<()> {
    tracing_subscriber::fmt()
        .try_init()
        .map_err(|error| anyhow!("failed to initialise logging: {error}"))
}

fn parse_wrap_lifecycle(raw: &str) -> Result<broker_protocol_client::SecretLifecycle> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "single_use_unwrap" | "single-use-unwrap" | "singleuseunwrap" => Ok(
            broker_protocol_client::SecretLifecycle::SingleUseUnwrap,
        ),
        "renewable_lease" | "renewable-lease" | "renewablelease" => Ok(
            broker_protocol_client::SecretLifecycle::RenewableLease,
        ),
        "service_bootstrap" | "service-bootstrap" | "servicebootstrap" => Ok(
            broker_protocol_client::SecretLifecycle::ServiceBootstrap,
        ),
        other => Err(anyhow!(
            "unsupported lifecycle '{}' ; expected single_use_unwrap, renewable_lease, or service_bootstrap",
            other
        )),
    }
}

async fn wrap_secret_v2_to_file(
    plaintext_env: String,
    output_file: String,
    lifecycle: String,
    label: Option<String>,
    unwrap_principal_id: Option<String>,
) -> Result<()> {
    let plaintext =
        env::var(&plaintext_env).with_context(|| format!("{} is required", plaintext_env))?;
    if plaintext.trim().is_empty() {
        return Err(anyhow!("{} must not be empty", plaintext_env));
    }

    let lifecycle = parse_wrap_lifecycle(&lifecycle)?;
    let client = SecretBrokerClient::from_env()
        .await
        .context("failed to create secret-broker client")?;
    let wrapped = client
        .wrap_secret_v2(
            plaintext.as_bytes(),
            broker_protocol_client::WrapV2Params {
                lifecycle: Some(lifecycle),
                label: label
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty()),
                unwrap_principal_id: unwrap_principal_id
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty()),
                ..Default::default()
            },
        )
        .await
        .context("failed to wrap secret via broker")?;

    let output_path = std::path::PathBuf::from(output_file);
    let parent = output_path
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    std::fs::create_dir_all(&parent)
        .with_context(|| format!("failed to create output directory {}", parent.display()))?;

    let payload = serde_json::json!({
        "handle": wrapped.handle,
        "redeem_token": wrapped.redeem_token,
        "issued_at": wrapped.created_at.to_rfc3339(),
    });
    let serialized = serde_json::to_string_pretty(&payload)
        .context("failed to serialize wrapped secret config")?;

    let tmp_path = output_path.with_extension("tmp");
    std::fs::write(&tmp_path, format!("{}\n", serialized))
        .with_context(|| format!("failed to write temporary output {}", tmp_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to chmod {}", tmp_path.display()))?;
    }
    std::fs::rename(&tmp_path, &output_path).with_context(|| {
        format!(
            "failed to rename {} to {}",
            tmp_path.display(),
            output_path.display()
        )
    })?;

    info!(
        plaintext_env = plaintext_env.as_str(),
        output_file = %output_path.display(),
        lifecycle = ?lifecycle,
        "wrapped canonical broker config"
    );
    Ok(())
}
