use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use axum::{
    extract::FromRequestParts,
    http::{HeaderMap, HeaderValue, header, request::Parts},
};
use chrono::{Duration, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{AppState, models::ApiError};

pub const SESSION_COOKIE_NAME: &str = "andesshield_session";

pub fn hash_password(password: &str) -> Result<String, ApiError> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| ApiError::internal(format!("Argon2 hash error: {e}")))
}

pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

pub fn generate_session_token() -> (String, String) {
    let mut raw = [0u8; 32];
    rand::rng().fill_bytes(&mut raw);
    let token = hex::encode(raw);
    let token_hash = hash_token(&token);
    (token, token_hash)
}

pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn extract_session_cookie(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let trimmed = part.trim();
        if let Some(val) = trimmed.strip_prefix(&format!("{SESSION_COOKIE_NAME}=")) {
            if !val.is_empty() && val.len() <= 128 {
                return Some(val.to_string());
            }
        }
    }
    None
}

pub fn build_session_cookie(token: &str, max_age_secs: i64, secure: bool) -> HeaderValue {
    let secure_flag = if secure { "; Secure" } else { "" };
    let val = format!(
        "{SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age_secs}{secure_flag}"
    );
    HeaderValue::from_str(&val).unwrap_or_else(|_| {
        HeaderValue::from_static("andesshield_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
    })
}

pub fn clear_session_cookie(secure: bool) -> HeaderValue {
    build_session_cookie("", 0, secure)
}

pub fn extract_ip_from_headers(headers: &HeaderMap) -> String {
    if let Some(cf) = headers.get("cf-connecting-ip").and_then(|v| v.to_str().ok()) {
        return cf.trim().chars().take(64).collect();
    }
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            return first.trim().chars().take(64).collect();
        }
    }
    "local".to_string()
}

pub fn extract_user_agent(headers: &HeaderMap) -> String {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().chars().take(250).collect())
        .unwrap_or_else(|| "unknown".to_string())
}

pub async fn create_session(
    pool: &PgPool,
    user_id: Uuid,
    ttl_hours: i64,
    ip: &str,
    user_agent: &str,
) -> Result<String, ApiError> {
    let (token, token_hash) = generate_session_token();
    let expires_at = Utc::now() + Duration::hours(ttl_hours);

    // Opportunistic cleanup of expired sessions for this user
    sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND expires_at < NOW()")
        .bind(user_id)
        .execute(pool)
        .await?;

    sqlx::query(
        r#"
        INSERT INTO sessions (user_id, token_hash, ip_address, user_agent, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(user_id)
    .bind(&token_hash)
    .bind(ip)
    .bind(user_agent)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(token)
}

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub id: Uuid,
    pub session_id: Uuid,
    pub full_name: String,
    pub email: String,
    pub ip_address: String,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_session_cookie(&parts.headers)
            .ok_or_else(|| ApiError::unauthorized("Sesión requerida. Inicia sesión para continuar."))?;

        let token_hash = hash_token(&token);
        let row: Option<(Uuid, Uuid, String, String)> = sqlx::query_as(
            r#"
            SELECT u.id, s.id, u.full_name, u.email
            FROM sessions s
            INNER JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = $1 AND s.expires_at > NOW()
            "#,
        )
        .bind(&token_hash)
        .fetch_optional(&state.pool)
        .await?;

        let (id, session_id, full_name, email) =
            row.ok_or_else(|| ApiError::unauthorized("Tu sesión expiró o es inválida."))?;

        Ok(AuthUser {
            id,
            session_id,
            full_name,
            email,
            ip_address: extract_ip_from_headers(&parts.headers),
        })
    }
}

pub async fn require_org_role(
    pool: &PgPool,
    org_id: Uuid,
    user_id: Uuid,
    allowed_roles: &[&str],
) -> Result<String, ApiError> {
    let role: Option<(String,)> = sqlx::query_as(
        "SELECT role FROM memberships WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    let role = role
        .map(|r| r.0)
        .ok_or_else(|| ApiError::forbidden("No tienes acceso a esta organización."))?;

    if !allowed_roles.contains(&role.as_str()) {
        return Err(ApiError::forbidden(
            "Tu rol no tiene permisos suficientes para realizar esta acción.",
        ));
    }
    Ok(role)
}

pub async fn write_audit(
    pool: &PgPool,
    org_id: Option<Uuid>,
    actor_id: Option<Uuid>,
    actor_email: Option<&str>,
    action: &str,
    entity_type: &str,
    entity_id: Option<&str>,
    ip_address: Option<&str>,
    details: serde_json::Value,
) {
    let res = sqlx::query(
        r#"
        INSERT INTO audit_logs
          (organization_id, actor_user_id, actor_email, action, entity_type, entity_id, ip_address, details)
        VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(org_id)
    .bind(actor_id)
    .bind(actor_email)
    .bind(action)
    .bind(entity_type)
    .bind(entity_id)
    .bind(ip_address)
    .bind(details)
    .execute(pool)
    .await;

    if let Err(err) = res {
        tracing::warn!("Error escribiendo auditoría ({action}): {err}");
    }
}
