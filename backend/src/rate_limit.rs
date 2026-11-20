use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Json,
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::net::SocketAddr;

#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
    window: Duration,
    max_requests: usize,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window_secs: u64) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            window: Duration::from_secs(window_secs),
            max_requests,
        }
    }

    pub fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut map = match self.buckets.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Periodic cleanup to avoid unbounded memory growth under IP spray
        if map.len() > 10_000 {
            let window = self.window;
            map.retain(|_, q| {
                while let Some(&front) = q.front() {
                    if now.duration_since(front) > window {
                        q.pop_front();
                    } else {
                        break;
                    }
                }
                !q.is_empty()
            });
        }

        let queue = map.entry(key.to_string()).or_default();
        while let Some(&front) = queue.front() {
            if now.duration_since(front) > self.window {
                queue.pop_front();
            } else {
                break;
            }
        }

        if queue.len() >= self.max_requests {
            return false;
        }
        queue.push_back(now);
        true
    }
}

pub fn extract_client_ip(req: &Request<Body>) -> String {
    if let Some(cf) = req.headers().get("cf-connecting-ip").and_then(|v| v.to_str().ok()) {
        return cf.trim().chars().take(64).collect();
    }
    if let Some(xff) = req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            return first.trim().chars().take(64).collect();
        }
    }
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub async fn rate_limit_middleware(
    State(limiter): State<RateLimiter>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let ip = extract_client_ip(&req);
    if !limiter.check(&ip) {
        let mut res = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "Demasiadas solicitudes. Intenta nuevamente en unos segundos." })),
        )
            .into_response();
        res.headers_mut()
            .insert("retry-after", HeaderValue::from_static("60"));
        return res;
    }
    next.run(req).await
}
