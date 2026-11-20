use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

pub const MAX_RISKS_PER_ORG: i64 = 500;
pub const MAX_ORGS_PER_USER: i64 = 30;
pub const ALLOWED_ENVS: &[&str] = &["Cloud", "On-Premise", "Híbrido"];

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::BAD_REQUEST, message: msg.into() }
    }
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::UNAUTHORIZED, message: msg.into() }
    }
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::FORBIDDEN, message: msg.into() }
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::NOT_FOUND, message: msg.into() }
    }
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::CONFLICT, message: msg.into() }
    }
    pub fn internal(err: impl std::fmt::Display) -> Self {
        tracing::error!("Internal server error: {err}");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "Error interno del servidor.".to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(json!({ "error": self.message }));
        (self.status, body).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        if let sqlx::Error::Database(db_err) = &err {
            if db_err.code().as_deref() == Some("23505") {
                return Self::conflict("El registro ya existe (identificador o correo duplicado).");
            }
        }
        Self::internal(err)
    }
}

pub fn clean_text(raw: &str, max_len: usize) -> String {
    raw.chars()
        .filter(|&c| !c.is_control() || c == '\n' || c == '\t')
        .collect::<String>()
        .trim()
        .chars()
        .take(max_len)
        .collect()
}

pub fn validate_score(val: i16, field: &str) -> Result<i16, ApiError> {
    if !(1..=5).contains(&val) {
        return Err(ApiError::bad_request(format!(
            "El campo '{field}' debe ser un entero entre 1 y 5."
        )));
    }
    Ok(val)
}

#[derive(Debug, Clone, Serialize)]
pub struct RiskClassification {
    pub score: i16,
    pub level: &'static str,
    pub action: &'static str,
}

pub fn classify_risk(p: i16, i: i16) -> RiskClassification {
    let score = p * i;
    match score {
        1..=5 => RiskClassification { score, level: "Bajo", action: "Monitorear" },
        6..=9 => RiskClassification { score, level: "Medio", action: "Mejorar controles" },
        10..=16 => RiskClassification { score, level: "Alto", action: "Intervenir pronto" },
        _ => RiskClassification { score, level: "Crítico", action: "Intervenir ya" },
    }
}

#[derive(Debug, Serialize)]
pub struct UserDto {
    pub id: Uuid,
    pub full_name: String,
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct OrgDto {
    pub id: Uuid,
    pub name: String,
    pub sector: String,
    pub is_default: bool,
    pub role: String,
    pub risk_count: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct RiskRow {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub code: String,
    pub asset: String,
    pub env: String,
    pub threat: String,
    pub vuln: String,
    pub p: i16,
    pub i: i16,
    pub source: String,
    pub control: String,
    pub pr: i16,
    pub ir: i16,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct RiskDto {
    pub id: String,
    pub asset: String,
    pub env: String,
    pub threat: String,
    pub vuln: String,
    pub p: i16,
    pub i: i16,
    pub source: String,
    pub control: String,
    pub pr: i16,
    pub ir: i16,
    pub inherent: RiskClassification,
    pub residual: RiskClassification,
    pub updated_at: DateTime<Utc>,
}

impl From<RiskRow> for RiskDto {
    fn from(r: RiskRow) -> Self {
        let inherent = classify_risk(r.p, r.i);
        let residual = classify_risk(r.pr, r.ir);
        Self {
            id: r.code,
            asset: r.asset,
            env: r.env,
            threat: r.threat,
            vuln: r.vuln,
            p: r.p,
            i: r.i,
            source: r.source,
            control: r.control,
            pr: r.pr,
            ir: r.ir,
            inherent,
            residual,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub full_name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub full_name: String,
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub struct SessionDto {
    pub id: Uuid,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub is_current: bool,
}

#[derive(Debug, Deserialize)]
pub struct OrgRequest {
    pub name: String,
    #[serde(default)]
    pub sector: String,
}

#[derive(Debug, Deserialize)]
pub struct RiskUpsertRequest {
    pub id: String,
    pub asset: String,
    #[serde(default = "default_env")]
    pub env: String,
    pub threat: String,
    pub vuln: String,
    pub p: i16,
    pub i: i16,
    pub source: String,
    pub control: String,
    pub pr: i16,
    pub ir: i16,
}

fn default_env() -> String {
    "Cloud".to_string()
}

pub struct ValidatedRisk {
    pub code: String,
    pub asset: String,
    pub env: String,
    pub threat: String,
    pub vuln: String,
    pub p: i16,
    pub i: i16,
    pub source: String,
    pub control: String,
    pub pr: i16,
    pub ir: i16,
}

impl RiskUpsertRequest {
    pub fn validate(self) -> Result<ValidatedRisk, ApiError> {
        let code = clean_text(&self.id, 16).to_uppercase();
        let asset = clean_text(&self.asset, 160);
        let env = clean_text(&self.env, 20);
        let threat = clean_text(&self.threat, 300);
        let vuln = clean_text(&self.vuln, 300);
        let source = clean_text(&self.source, 300);
        let control = clean_text(&self.control, 600);

        if code.is_empty() {
            return Err(ApiError::bad_request("El ID del riesgo es obligatorio."));
        }
        if asset.is_empty() {
            return Err(ApiError::bad_request("El campo Activo es obligatorio."));
        }
        if !ALLOWED_ENVS.contains(&env.as_str()) {
            return Err(ApiError::bad_request("Entorno inválido. Usa Cloud, On-Premise o Híbrido."));
        }
        if threat.is_empty() || vuln.is_empty() {
            return Err(ApiError::bad_request("Amenaza y Vulnerabilidad son obligatorias."));
        }
        if source.is_empty() {
            return Err(ApiError::bad_request("La Fuente del dato es obligatoria."));
        }
        if control.is_empty() {
            return Err(ApiError::bad_request("El Control propuesto es obligatorio."));
        }

        Ok(ValidatedRisk {
            code,
            asset,
            env,
            threat,
            vuln,
            p: validate_score(self.p, "p")?,
            i: validate_score(self.i, "i")?,
            source,
            control,
            pr: validate_score(self.pr, "pr")?,
            ir: validate_score(self.ir, "ir")?,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct ImportOrgPayload {
    pub organization: Option<ImportOrgMeta>,
    pub risks: Vec<RiskUpsertRequest>,
}

#[derive(Debug, Deserialize)]
pub struct ImportOrgMeta {
    pub name: Option<String>,
    pub sector: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct AuditLogDto {
    pub id: i64,
    pub actor_email: Option<String>,
    pub action: String,
    pub entity_type: String,
    pub entity_id: Option<String>,
    pub ip_address: Option<String>,
    pub details: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_official_qa_risk_scale() {
        let c1 = classify_risk(4, 5);
        assert_eq!((c1.score, c1.level), (20, "Crítico"));

        let c2 = classify_risk(2, 3);
        assert_eq!((c2.score, c2.level), (6, "Medio"));

        let c3 = classify_risk(3, 5);
        assert_eq!((c3.score, c3.level), (15, "Alto"));

        let c4 = classify_risk(4, 4);
        assert_eq!((c4.score, c4.level), (16, "Alto"));

        let c5 = classify_risk(1, 5);
        assert_eq!((c5.score, c5.level), (5, "Bajo"));
    }
}
