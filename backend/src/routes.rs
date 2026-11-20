use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use chrono::{DateTime, Utc};
use serde_json::json;
use uuid::Uuid;

use crate::{
    AppState,
    auth::{
        AuthUser, build_session_cookie, clear_session_cookie, create_session,
        extract_ip_from_headers, extract_session_cookie, extract_user_agent, hash_password,
        hash_token, require_org_role, verify_password, write_audit,
    },
    models::{
        ApiError, AuditLogDto, ChangePasswordRequest, ImportOrgPayload, LoginRequest,
        MAX_ORGS_PER_USER, MAX_RISKS_PER_ORG, OrgDto, OrgRequest, RegisterRequest, RiskDto,
        RiskRow, RiskUpsertRequest, SessionDto, UpdateProfileRequest, UserDto, clean_text,
    },
    seed::insert_coopandes_risks,
};

pub async fn health(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(json!({
        "status": "ok",
        "service": "AndesShield Rust API",
        "version": env!("CARGO_PKG_VERSION"),
        "engine": "Rust + Axum 0.8 + PostgreSQL 18",
        "auth": "Argon2id + HttpOnly Sessions + RBAC"
    })))
}

async fn fetch_user_orgs(state: &AppState, user_id: Uuid) -> Result<Vec<OrgDto>, ApiError> {
    let rows: Vec<(Uuid, String, String, bool, String, i64)> = sqlx::query_as(
        r#"
        SELECT
            o.id,
            o.name,
            o.sector,
            o.is_default,
            m.role,
            COUNT(r.id) AS risk_count
        FROM organizations o
        INNER JOIN memberships m ON m.organization_id = o.id
        LEFT JOIN risks r ON r.organization_id = o.id
        WHERE m.user_id = $1
        GROUP BY o.id, m.role
        ORDER BY o.is_default DESC, o.created_at ASC
        "#,
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(id, name, sector, is_default, role, risk_count)| OrgDto {
            id,
            name,
            sector,
            is_default,
            role,
            risk_count,
        })
        .collect())
}

pub async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RegisterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let full_name = clean_text(&payload.full_name, 120);
    let email = clean_text(&payload.email, 255).to_lowercase();
    let password = payload.password;

    if full_name.len() < 2 {
        return Err(ApiError::bad_request("Ingresa tu nombre completo (mínimo 2 caracteres)."));
    }
    if !email.contains('@') || !email.contains('.') || email.len() < 5 {
        return Err(ApiError::bad_request("Ingresa un correo electrónico válido."));
    }
    if password.len() < 10 || password.len() > 128 {
        return Err(ApiError::bad_request(
            "La contraseña debe tener entre 10 y 128 caracteres.",
        ));
    }

    let pw_hash = hash_password(&password)?;
    let ip = extract_ip_from_headers(&headers);
    let ua = extract_user_agent(&headers);

    let user_id: (Uuid,) = sqlx::query_as(
        "INSERT INTO users (full_name, email, password_hash) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(&full_name)
    .bind(&email)
    .bind(&pw_hash)
    .fetch_one(&state.pool)
    .await?;

    // Create starter isolated organization; seed CoopAndes Digital if this is the first org in DB
    let existing_orgs: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM organizations")
        .fetch_one(&state.pool)
        .await?;
    let is_first_org = existing_orgs.0 == 0;

    let org_id: (Uuid,) = sqlx::query_as(
        "INSERT INTO organizations (name, sector, is_default, created_by) VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(if is_first_org { "CoopAndes Digital" } else { "Mi Organización" })
    .bind(if is_first_org { "Cooperativa / Financiero" } else { "General" })
    .bind(is_first_org)
    .bind(user_id.0)
    .fetch_one(&state.pool)
    .await?;

    sqlx::query("INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, 'admin')")
        .bind(org_id.0)
        .bind(user_id.0)
        .execute(&state.pool)
        .await?;

    if is_first_org {
        insert_coopandes_risks(&state.pool, org_id.0, Some(user_id.0)).await?;
    }

    let token = create_session(&state.pool, user_id.0, state.session_ttl_hours, &ip, &ua).await?;
    write_audit(
        &state.pool,
        Some(org_id.0),
        Some(user_id.0),
        Some(&email),
        "USER_REGISTER",
        "user",
        Some(&user_id.0.to_string()),
        Some(&ip),
        json!({ "full_name": full_name }),
    )
    .await;

    let orgs = fetch_user_orgs(&state, user_id.0).await?;
    let cookie = build_session_cookie(&token, state.session_ttl_hours * 3600, state.cookie_secure);

    let mut res_headers = HeaderMap::new();
    res_headers.insert(header::SET_COOKIE, cookie);

    Ok((
        StatusCode::CREATED,
        res_headers,
        Json(json!({
            "user": UserDto { id: user_id.0, full_name, email },
            "organizations": orgs
        })),
    ))
}

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let email = clean_text(&payload.email, 255).to_lowercase();
    let ip = extract_ip_from_headers(&headers);
    let ua = extract_user_agent(&headers);

    let row: Option<(Uuid, String, String, String)> = sqlx::query_as(
        "SELECT id, full_name, email, password_hash FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await?;

    let Some((user_id, full_name, db_email, pw_hash)) = row else {
        // Perform dummy Argon2 verification to mitigate user-enumeration timing attacks
        let _ = verify_password(
            &payload.password,
            "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        return Err(ApiError::unauthorized("Correo o contraseña incorrectos."));
    };

    if !verify_password(&payload.password, &pw_hash) {
        write_audit(
            &state.pool,
            None,
            Some(user_id),
            Some(&db_email),
            "LOGIN_FAILED",
            "session",
            None,
            Some(&ip),
            json!({ "reason": "invalid_password" }),
        )
        .await;
        return Err(ApiError::unauthorized("Correo o contraseña incorrectos."));
    }

    let token = create_session(&state.pool, user_id, state.session_ttl_hours, &ip, &ua).await?;
    let orgs = fetch_user_orgs(&state, user_id).await?;
    let first_org = orgs.first().map(|o| o.id);

    write_audit(
        &state.pool,
        first_org,
        Some(user_id),
        Some(&db_email),
        "LOGIN_SUCCESS",
        "session",
        None,
        Some(&ip),
        json!({}),
    )
    .await;

    let cookie = build_session_cookie(&token, state.session_ttl_hours * 3600, state.cookie_secure);
    let mut res_headers = HeaderMap::new();
    res_headers.insert(header::SET_COOKIE, cookie);

    Ok((
        StatusCode::OK,
        res_headers,
        Json(json!({
            "user": UserDto { id: user_id, full_name, email: db_email },
            "organizations": orgs
        })),
    ))
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(token) = extract_session_cookie(&headers) {
        let token_hash = hash_token(&token);
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(&token_hash)
            .execute(&state.pool)
            .await?;
    }

    let mut res_headers = HeaderMap::new();
    res_headers.insert(header::SET_COOKIE, clear_session_cookie(state.cookie_secure));
    Ok((StatusCode::OK, res_headers, Json(json!({ "ok": true }))))
}

pub async fn me(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<impl IntoResponse, ApiError> {
    let orgs = fetch_user_orgs(&state, user.id).await?;
    Ok(Json(json!({
        "user": UserDto { id: user.id, full_name: user.full_name, email: user.email },
        "organizations": orgs
    })))
}

pub async fn update_profile(
    State(state): State<AppState>,
    user: AuthUser,
    Json(payload): Json<UpdateProfileRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let full_name = clean_text(&payload.full_name, 120);
    let email = clean_text(&payload.email, 255).to_lowercase();

    if full_name.len() < 2 {
        return Err(ApiError::bad_request(
            "Ingresa tu nombre completo (mínimo 2 caracteres).",
        ));
    }
    if !email.contains('@') || !email.contains('.') || email.len() < 5 {
        return Err(ApiError::bad_request("Ingresa un correo electrónico válido."));
    }

    sqlx::query(
        "UPDATE users SET full_name = $1, email = $2, updated_at = NOW() WHERE id = $3",
    )
    .bind(&full_name)
    .bind(&email)
    .bind(user.id)
    .execute(&state.pool)
    .await?;

    let orgs = fetch_user_orgs(&state, user.id).await?;
    write_audit(
        &state.pool,
        orgs.first().map(|o| o.id),
        Some(user.id),
        Some(&email),
        "PROFILE_UPDATE",
        "user",
        Some(&user.id.to_string()),
        Some(&user.ip_address),
        json!({ "full_name": full_name, "email": email }),
    )
    .await;

    Ok(Json(json!({
        "user": UserDto { id: user.id, full_name, email }
    })))
}

pub async fn change_password(
    State(state): State<AppState>,
    user: AuthUser,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if payload.new_password.len() < 10 || payload.new_password.len() > 128 {
        return Err(ApiError::bad_request(
            "La nueva contraseña debe tener entre 10 y 128 caracteres.",
        ));
    }
    if payload.current_password == payload.new_password {
        return Err(ApiError::bad_request(
            "La nueva contraseña debe ser distinta a la contraseña actual.",
        ));
    }

    let row: (String,) = sqlx::query_as("SELECT password_hash FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&state.pool)
        .await?;

    if !verify_password(&payload.current_password, &row.0) {
        let orgs = fetch_user_orgs(&state, user.id).await?;
        write_audit(
            &state.pool,
            orgs.first().map(|o| o.id),
            Some(user.id),
            Some(&user.email),
            "PASSWORD_CHANGE_FAILED",
            "user",
            Some(&user.id.to_string()),
            Some(&user.ip_address),
            json!({ "reason": "invalid_current_password" }),
        )
        .await;
        return Err(ApiError::unauthorized("La contraseña actual es incorrecta."));
    }

    let new_hash = hash_password(&payload.new_password)?;
    sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
        .bind(&new_hash)
        .bind(user.id)
        .execute(&state.pool)
        .await?;

    // Revoke all other sessions for security when password changes
    let revoked = sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND id != $2")
        .bind(user.id)
        .bind(user.session_id)
        .execute(&state.pool)
        .await?
        .rows_affected();

    let orgs = fetch_user_orgs(&state, user.id).await?;
    write_audit(
        &state.pool,
        orgs.first().map(|o| o.id),
        Some(user.id),
        Some(&user.email),
        "PASSWORD_CHANGE",
        "user",
        Some(&user.id.to_string()),
        Some(&user.ip_address),
        json!({ "revoked_other_sessions": revoked }),
    )
    .await;

    Ok(Json(json!({
        "ok": true,
        "revoked_other_sessions": revoked
    })))
}

pub async fn list_sessions(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<impl IntoResponse, ApiError> {
    let rows: Vec<(Uuid, Option<String>, Option<String>, DateTime<Utc>, DateTime<Utc>)> =
        sqlx::query_as(
            r#"
            SELECT id, ip_address, user_agent, created_at, expires_at
            FROM sessions
            WHERE user_id = $1 AND expires_at > NOW()
            ORDER BY created_at DESC
            "#,
        )
        .bind(user.id)
        .fetch_all(&state.pool)
        .await?;

    let dtos: Vec<SessionDto> = rows
        .into_iter()
        .map(|(id, ip_address, user_agent, created_at, expires_at)| SessionDto {
            id,
            ip_address,
            user_agent,
            created_at,
            expires_at,
            is_current: id == user.session_id,
        })
        .collect();

    Ok(Json(dtos))
}

pub async fn revoke_session(
    State(state): State<AppState>,
    user: AuthUser,
    Path(session_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    if session_id == user.session_id {
        return Err(ApiError::bad_request(
            "Para cerrar tu sesión actual utiliza la opción Cerrar Sesión.",
        ));
    }

    let res = sqlx::query("DELETE FROM sessions WHERE id = $1 AND user_id = $2")
        .bind(session_id)
        .bind(user.id)
        .execute(&state.pool)
        .await?;

    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("Sesión no encontrada."));
    }

    let orgs = fetch_user_orgs(&state, user.id).await?;
    write_audit(
        &state.pool,
        orgs.first().map(|o| o.id),
        Some(user.id),
        Some(&user.email),
        "SESSION_REVOKE",
        "session",
        Some(&session_id.to_string()),
        Some(&user.ip_address),
        json!({}),
    )
    .await;

    Ok(Json(json!({ "ok": true })))
}

pub async fn revoke_other_sessions(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<impl IntoResponse, ApiError> {
    let revoked = sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND id != $2")
        .bind(user.id)
        .bind(user.session_id)
        .execute(&state.pool)
        .await?
        .rows_affected();

    let orgs = fetch_user_orgs(&state, user.id).await?;
    write_audit(
        &state.pool,
        orgs.first().map(|o| o.id),
        Some(user.id),
        Some(&user.email),
        "SESSIONS_REVOKE_OTHERS",
        "session",
        None,
        Some(&user.ip_address),
        json!({ "revoked_count": revoked }),
    )
    .await;

    Ok(Json(json!({ "ok": true, "revoked": revoked })))
}

pub async fn list_orgs(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<impl IntoResponse, ApiError> {
    let orgs = fetch_user_orgs(&state, user.id).await?;
    Ok(Json(orgs))
}

pub async fn create_org(
    State(state): State<AppState>,
    user: AuthUser,
    Json(payload): Json<OrgRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let name = clean_text(&payload.name, 60);
    let sector = {
        let s = clean_text(&payload.sector, 60);
        if s.is_empty() { "General".to_string() } else { s }
    };

    if name.is_empty() {
        return Err(ApiError::bad_request("El nombre de la organización es obligatorio."));
    }

    let current_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM memberships WHERE user_id = $1")
            .bind(user.id)
            .fetch_one(&state.pool)
            .await?;

    if current_count.0 >= MAX_ORGS_PER_USER {
        return Err(ApiError::bad_request(format!(
            "Se alcanzó el límite máximo de {MAX_ORGS_PER_USER} organizaciones."
        )));
    }

    let org_id: (Uuid,) = sqlx::query_as(
        "INSERT INTO organizations (name, sector, is_default, created_by) VALUES ($1, $2, FALSE, $3) RETURNING id",
    )
    .bind(&name)
    .bind(&sector)
    .bind(user.id)
    .fetch_one(&state.pool)
    .await?;

    sqlx::query("INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, 'admin')")
        .bind(org_id.0)
        .bind(user.id)
        .execute(&state.pool)
        .await?;

    write_audit(
        &state.pool,
        Some(org_id.0),
        Some(user.id),
        Some(&user.email),
        "ORG_CREATE",
        "organization",
        Some(&org_id.0.to_string()),
        Some(&user.ip_address),
        json!({ "name": name, "sector": sector }),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(OrgDto {
            id: org_id.0,
            name,
            sector,
            is_default: false,
            role: "admin".to_string(),
            risk_count: 0,
        }),
    ))
}

pub async fn update_org(
    State(state): State<AppState>,
    user: AuthUser,
    Path(org_id): Path<Uuid>,
    Json(payload): Json<OrgRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_org_role(&state.pool, org_id, user.id, &["admin"]).await?;

    let name = clean_text(&payload.name, 60);
    let sector = {
        let s = clean_text(&payload.sector, 60);
        if s.is_empty() { "General".to_string() } else { s }
    };
    if name.is_empty() {
        return Err(ApiError::bad_request("El nombre de la organización es obligatorio."));
    }

    sqlx::query("UPDATE organizations SET name = $1, sector = $2, updated_at = NOW() WHERE id = $3")
        .bind(&name)
        .bind(&sector)
        .bind(org_id)
        .execute(&state.pool)
        .await?;

    write_audit(
        &state.pool,
        Some(org_id),
        Some(user.id),
        Some(&user.email),
        "ORG_UPDATE",
        "organization",
        Some(&org_id.to_string()),
        Some(&user.ip_address),
        json!({ "name": name, "sector": sector }),
    )
    .await;

    Ok(Json(json!({ "id": org_id, "name": name, "sector": sector })))
}

pub async fn delete_org(
    State(state): State<AppState>,
    user: AuthUser,
    Path(org_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    require_org_role(&state.pool, org_id, user.id, &["admin"]).await?;

    let row: Option<(String, bool)> =
        sqlx::query_as("SELECT name, is_default FROM organizations WHERE id = $1")
            .bind(org_id)
            .fetch_optional(&state.pool)
            .await?;

    let Some((org_name, is_default)) = row else {
        return Err(ApiError::not_found("Organización no encontrada."));
    };

    if is_default {
        return Err(ApiError::bad_request(
            "La organización demostrativa base no puede eliminarse; usa Restaurar Caso.",
        ));
    }

    sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(org_id)
        .execute(&state.pool)
        .await?;

    write_audit(
        &state.pool,
        None,
        Some(user.id),
        Some(&user.email),
        "ORG_DELETE",
        "organization",
        Some(&org_id.to_string()),
        Some(&user.ip_address),
        json!({ "name": org_name }),
    )
    .await;

    Ok(Json(json!({ "ok": true })))
}

pub async fn list_risks(
    State(state): State<AppState>,
    user: AuthUser,
    Path(org_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    require_org_role(&state.pool, org_id, user.id, &["admin", "analyst", "viewer"]).await?;

    let rows: Vec<RiskRow> = sqlx::query_as(
        r#"
        SELECT id, organization_id, code, asset, env, threat, vuln, p, i, source, control, pr, ir, updated_at
        FROM risks
        WHERE organization_id = $1
        ORDER BY (p * i) DESC, i DESC, code ASC
        "#,
    )
    .bind(org_id)
    .fetch_all(&state.pool)
    .await?;

    let dtos: Vec<RiskDto> = rows.into_iter().map(RiskDto::from).collect();
    Ok(Json(dtos))
}

pub async fn create_risk(
    State(state): State<AppState>,
    user: AuthUser,
    Path(org_id): Path<Uuid>,
    Json(payload): Json<RiskUpsertRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_org_role(&state.pool, org_id, user.id, &["admin", "analyst"]).await?;
    let v = payload.validate()?;

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM risks WHERE organization_id = $1")
        .bind(org_id)
        .fetch_one(&state.pool)
        .await?;

    if count.0 >= MAX_RISKS_PER_ORG {
        return Err(ApiError::bad_request(format!(
            "Se alcanzó el límite máximo de {MAX_RISKS_PER_ORG} riesgos en esta organización."
        )));
    }

    let row: RiskRow = sqlx::query_as(
        r#"
        INSERT INTO risks
          (organization_id, code, asset, env, threat, vuln, p, i, source, control, pr, ir, created_by)
        VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        RETURNING id, organization_id, code, asset, env, threat, vuln, p, i, source, control, pr, ir, updated_at
        "#,
    )
    .bind(org_id)
    .bind(&v.code)
    .bind(&v.asset)
    .bind(&v.env)
    .bind(&v.threat)
    .bind(&v.vuln)
    .bind(v.p)
    .bind(v.i)
    .bind(&v.source)
    .bind(&v.control)
    .bind(v.pr)
    .bind(v.ir)
    .bind(user.id)
    .fetch_one(&state.pool)
    .await?;

    write_audit(
        &state.pool,
        Some(org_id),
        Some(user.id),
        Some(&user.email),
        "RISK_CREATE",
        "risk",
        Some(&row.code),
        Some(&user.ip_address),
        json!({ "asset": row.asset, "inherent": row.p * row.i, "residual": row.pr * row.ir }),
    )
    .await;

    Ok((StatusCode::CREATED, Json(RiskDto::from(row))))
}

pub async fn update_risk(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_id, code)): Path<(Uuid, String)>,
    Json(payload): Json<RiskUpsertRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_org_role(&state.pool, org_id, user.id, &["admin", "analyst"]).await?;
    let v = payload.validate()?;
    let target_code = clean_text(&code, 16).to_uppercase();

    let row: Option<RiskRow> = sqlx::query_as(
        r#"
        UPDATE risks
        SET asset = $1, env = $2, threat = $3, vuln = $4, p = $5, i = $6,
            source = $7, control = $8, pr = $9, ir = $10, updated_at = NOW()
        WHERE organization_id = $11 AND code = $12
        RETURNING id, organization_id, code, asset, env, threat, vuln, p, i, source, control, pr, ir, updated_at
        "#,
    )
    .bind(&v.asset)
    .bind(&v.env)
    .bind(&v.threat)
    .bind(&v.vuln)
    .bind(v.p)
    .bind(v.i)
    .bind(&v.source)
    .bind(&v.control)
    .bind(v.pr)
    .bind(v.ir)
    .bind(org_id)
    .bind(&target_code)
    .fetch_optional(&state.pool)
    .await?;

    let Some(row) = row else {
        return Err(ApiError::not_found("Riesgo no encontrado en esta organización."));
    };

    write_audit(
        &state.pool,
        Some(org_id),
        Some(user.id),
        Some(&user.email),
        "RISK_UPDATE",
        "risk",
        Some(&row.code),
        Some(&user.ip_address),
        json!({ "asset": row.asset, "inherent": row.p * row.i, "residual": row.pr * row.ir }),
    )
    .await;

    Ok(Json(RiskDto::from(row)))
}

pub async fn delete_risk(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_id, code)): Path<(Uuid, String)>,
) -> Result<impl IntoResponse, ApiError> {
    require_org_role(&state.pool, org_id, user.id, &["admin", "analyst"]).await?;
    let target_code = clean_text(&code, 16).to_uppercase();

    let res = sqlx::query("DELETE FROM risks WHERE organization_id = $1 AND code = $2")
        .bind(org_id)
        .bind(&target_code)
        .execute(&state.pool)
        .await?;

    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("Riesgo no encontrado."));
    }

    write_audit(
        &state.pool,
        Some(org_id),
        Some(user.id),
        Some(&user.email),
        "RISK_DELETE",
        "risk",
        Some(&target_code),
        Some(&user.ip_address),
        json!({}),
    )
    .await;

    Ok(Json(json!({ "ok": true })))
}

pub async fn reset_org(
    State(state): State<AppState>,
    user: AuthUser,
    Path(org_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    require_org_role(&state.pool, org_id, user.id, &["admin"]).await?;

    let row: Option<(bool,)> =
        sqlx::query_as("SELECT is_default FROM organizations WHERE id = $1")
            .bind(org_id)
            .fetch_optional(&state.pool)
            .await?;

    let Some((is_default,)) = row else {
        return Err(ApiError::not_found("Organización no encontrada."));
    };

    sqlx::query("DELETE FROM risks WHERE organization_id = $1")
        .bind(org_id)
        .execute(&state.pool)
        .await?;

    if is_default {
        insert_coopandes_risks(&state.pool, org_id, Some(user.id)).await?;
    }

    write_audit(
        &state.pool,
        Some(org_id),
        Some(user.id),
        Some(&user.email),
        if is_default { "ORG_RESTORE_DEFAULT" } else { "ORG_CLEAR_RISKS" },
        "organization",
        Some(&org_id.to_string()),
        Some(&user.ip_address),
        json!({}),
    )
    .await;

    list_risks(State(state), user, Path(org_id)).await
}

pub async fn import_org(
    State(state): State<AppState>,
    user: AuthUser,
    Json(payload): Json<ImportOrgPayload>,
) -> Result<impl IntoResponse, ApiError> {
    if payload.risks.len() as i64 > MAX_RISKS_PER_ORG {
        return Err(ApiError::bad_request(format!(
            "El archivo supera el límite de {MAX_RISKS_PER_ORG} hallazgos."
        )));
    }

    let current_orgs: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM memberships WHERE user_id = $1")
            .bind(user.id)
            .fetch_one(&state.pool)
            .await?;

    if current_orgs.0 >= MAX_ORGS_PER_USER {
        return Err(ApiError::bad_request(format!(
            "Se alcanzó el máximo de {MAX_ORGS_PER_USER} organizaciones."
        )));
    }

    let org_name = payload
        .organization
        .as_ref()
        .and_then(|o| o.name.as_deref())
        .map(|s| clean_text(s, 60))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Organización Importada".to_string());

    let org_sector = payload
        .organization
        .as_ref()
        .and_then(|o| o.sector.as_deref())
        .map(|s| clean_text(s, 60))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "General".to_string());

    let mut validated = Vec::with_capacity(payload.risks.len());
    for item in payload.risks {
        validated.push(item.validate()?);
    }

    let org_id: (Uuid,) = sqlx::query_as(
        "INSERT INTO organizations (name, sector, is_default, created_by) VALUES ($1, $2, FALSE, $3) RETURNING id",
    )
    .bind(&org_name)
    .bind(&org_sector)
    .bind(user.id)
    .fetch_one(&state.pool)
    .await?;

    sqlx::query("INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, 'admin')")
        .bind(org_id.0)
        .bind(user.id)
        .execute(&state.pool)
        .await?;

    for v in &validated {
        sqlx::query(
            r#"
            INSERT INTO risks
              (organization_id, code, asset, env, threat, vuln, p, i, source, control, pr, ir, created_by)
            VALUES
              ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            ON CONFLICT (organization_id, code) DO NOTHING
            "#,
        )
        .bind(org_id.0)
        .bind(&v.code)
        .bind(&v.asset)
        .bind(&v.env)
        .bind(&v.threat)
        .bind(&v.vuln)
        .bind(v.p)
        .bind(v.i)
        .bind(&v.source)
        .bind(&v.control)
        .bind(v.pr)
        .bind(v.ir)
        .bind(user.id)
        .execute(&state.pool)
        .await?;
    }

    write_audit(
        &state.pool,
        Some(org_id.0),
        Some(user.id),
        Some(&user.email),
        "ORG_IMPORT_JSON",
        "organization",
        Some(&org_id.0.to_string()),
        Some(&user.ip_address),
        json!({ "name": org_name, "imported_count": validated.len() }),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(OrgDto {
            id: org_id.0,
            name: org_name,
            sector: org_sector,
            is_default: false,
            role: "admin".to_string(),
            risk_count: validated.len() as i64,
        }),
    ))
}

pub async fn list_audit_logs(
    State(state): State<AppState>,
    user: AuthUser,
    Path(org_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    require_org_role(&state.pool, org_id, user.id, &["admin", "analyst", "viewer"]).await?;

    let logs: Vec<AuditLogDto> = sqlx::query_as(
        r#"
        SELECT id, actor_email, action, entity_type, entity_id, ip_address, details, created_at
        FROM audit_logs
        WHERE organization_id = $1
        ORDER BY created_at DESC
        LIMIT 100
        "#,
    )
    .bind(org_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(logs))
}
