#![forbid(unsafe_code)]

mod auth;
mod models;
mod rate_limit;
mod routes;
mod seed;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::DefaultBodyLimit,
    http::{HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, patch, post, put},
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{EnvFilter, fmt};

use crate::rate_limit::{RateLimiter, rate_limit_middleware};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub cookie_secure: bool,
    pub session_ttl_hours: i64,
    pub static_html: Arc<String>,
}

async fn security_headers_middleware(req: Request<Body>, next: Next) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
    );
    headers.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    res
}

async fn serve_index(axum::extract::State(state): axum::extract::State<AppState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-cache")],
        Html((*state.static_html).clone()),
    )
}

fn run_healthcheck() -> ! {
    let addr = std::env::var("HEALTHCHECK_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    match std::net::TcpStream::connect_timeout(
        &addr.parse().expect("Invalid HEALTHCHECK_ADDR"),
        Duration::from_secs(2),
    ) {
        Ok(_) => std::process::exit(0),
        Err(_) => std::process::exit(1),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().any(|a| a == "--healthcheck") {
        run_healthcheck();
    }

    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("andesshield_api=info,tower_http=info")),
        )
        .init();

    let database_url =
        std::env::var("DATABASE_URL").expect("La variable de entorno DATABASE_URL es obligatoria.");
    let bind_addr: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()?;
    let cookie_secure = std::env::var("COOKIE_SECURE")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);
    let session_ttl_hours = std::env::var("SESSION_TTL_HOURS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|&h| (1..=720).contains(&h))
        .unwrap_or(24);
    let static_index_path = std::env::var("STATIC_INDEX_PATH")
        .unwrap_or_else(|_| "/app/static/index.html".to_string());

    let static_html = std::fs::read_to_string(&static_index_path)
        .unwrap_or_else(|_| "<h1>AndesShield API Activa</h1>".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    seed::seed_initial_data(&pool).await?;

    let state = AppState {
        pool,
        cookie_secure,
        session_ttl_hours,
        static_html: Arc::new(static_html),
    };

    // Strict brute-force rate limit for auth endpoints (15 req / 60s per IP)
    let auth_limiter = RateLimiter::new(15, 60);
    // General API rate limit (180 req / 60s per IP)
    let api_limiter = RateLimiter::new(180, 60);

    let auth_routes = Router::new()
        .route("/register", post(routes::register))
        .route("/login", post(routes::login))
        .route("/logout", post(routes::logout))
        .route("/me", get(routes::me))
        .layer(middleware::from_fn_with_state(
            auth_limiter,
            rate_limit_middleware,
        ));

    let api_routes = Router::new()
        .route("/health", get(routes::health))
        .nest("/auth", auth_routes)
        .route("/orgs", get(routes::list_orgs).post(routes::create_org))
        .route("/orgs/import", post(routes::import_org))
        .route(
            "/orgs/{org_id}",
            patch(routes::update_org).delete(routes::delete_org),
        )
        .route("/orgs/{org_id}/reset", post(routes::reset_org))
        .route(
            "/orgs/{org_id}/risks",
            get(routes::list_risks).post(routes::create_risk),
        )
        .route(
            "/orgs/{org_id}/risks/{code}",
            put(routes::update_risk).delete(routes::delete_risk),
        )
        .route("/orgs/{org_id}/audit", get(routes::list_audit_logs))
        .layer(middleware::from_fn_with_state(
            api_limiter,
            rate_limit_middleware,
        ));

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/index.html", get(serve_index))
        .nest("/api/v1", api_routes)
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024)) // 2 MiB max payload
        .layer(middleware::from_fn(security_headers_middleware))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!("AndesShield Rust API escuchando en http://{bind_addr}");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            sig.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("Apagando AndesShield Rust API de forma ordenada...");
}
