pub mod embed;

use crate::ipc::socket::DaemonState;
use crate::models::IpcRequest;
use anyhow::Result;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, Request, State,
    },
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;

const MAX_LOGIN_FAILURES: u32 = 5;
const LOGIN_LOCKOUT_SECS: i64 = 300;
const SESSION_TTL_HOURS: i64 = 12;
const MAX_ACTIVE_SESSIONS: usize = 64;

#[derive(Clone)]
struct WebAppState {
    daemon: DaemonState,
    sessions: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
    login_guard: Arc<RwLock<(u32, Option<DateTime<Utc>>)>>,
    bootstrap_token: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

#[derive(Deserialize)]
struct BanBody {
    ip: String,
    reason: Option<String>,
    duration_secs: Option<u64>,
}

#[derive(Deserialize)]
struct PauseBody {
    duration_secs: u64,
}

#[derive(Deserialize)]
struct WsAuthQuery {
    token: Option<String>,
}

pub async fn serve_web_gui(
    daemon: DaemonState,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> Result<()> {
    let bind_addr = daemon.config.web_gui.bind_address.clone();
    let bootstrap_token = Uuid::new_v4().to_string();

    if daemon.config.web_gui.password_hash.is_empty() && daemon.config.web_gui.api_token.is_empty() {
        warn!(
            "Web GUI has no password_hash or api_token configured. One-time session token: {}",
            bootstrap_token
        );
    }

    let app_state = WebAppState {
        daemon,
        sessions: Arc::new(RwLock::new(HashMap::new())),
        login_guard: Arc::new(RwLock::new((0, None))),
        bootstrap_token,
    };

    let app = Router::new()
        .route("/api/login", post(api_login))
        .route("/api/status", get(api_status))
        .route("/api/events", get(api_events))
        .route("/api/bans", get(api_bans).post(api_ban_ip))
        .route("/api/bans/:ip", delete(api_unban_ip))
        .route("/api/fim/pause", post(api_pause_fim))
        .route("/api/fim/resume", post(api_resume_fim))
        .route("/api/services/:name/reload", post(api_reload_service))
        .route("/ws", get(ws_handler))
        .fallback(embed::static_handler)
        .layer(middleware::from_fn(security_headers_middleware))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!("Embedded Web GUI listening on http://{}", bind_addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.recv().await;
        })
        .await?;

    Ok(())
}

async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    resp
}

async fn is_authorized(state: &WebAppState, headers: &HeaderMap) -> bool {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);

    let Some(tok) = token else {
        return false;
    };
    is_valid_token(state, tok).await
}

async fn is_valid_token(state: &WebAppState, tok: &str) -> bool {
    if !state.daemon.config.web_gui.api_token.is_empty()
        && tok == state.daemon.config.web_gui.api_token
    {
        return true;
    }
    if state.daemon.config.web_gui.password_hash.is_empty()
        && state.daemon.config.web_gui.api_token.is_empty()
        && tok == state.bootstrap_token
    {
        return true;
    }
    let sessions = state.sessions.read().await;
    sessions
        .get(tok)
        .map(|&exp| Utc::now() < exp)
        .unwrap_or(false)
}

async fn api_login(
    State(state): State<WebAppState>,
    Json(body): Json<LoginRequest>,
) -> impl IntoResponse {
    {
        let guard = state.login_guard.read().await;
        if let Some(locked_until) = guard.1 {
            if Utc::now() < locked_until {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many failed login attempts. Try again later.",
                )
                    .into_response();
            }
        }
    }

    let hash_str = &state.daemon.config.web_gui.password_hash;
    let api_tok = &state.daemon.config.web_gui.api_token;

    let ok = if !hash_str.is_empty() {
        PasswordHash::new(hash_str)
            .ok()
            .map(|parsed| {
                Argon2::default()
                    .verify_password(body.password.as_bytes(), &parsed)
                    .is_ok()
            })
            .unwrap_or(false)
    } else if !api_tok.is_empty() {
        body.password == *api_tok
    } else {
        body.password == state.bootstrap_token
    };

    if ok {
        {
            let mut guard = state.login_guard.write().await;
            *guard = (0, None);
        }
        let token = Uuid::new_v4().to_string();
        let mut sessions = state.sessions.write().await;
        let now = Utc::now();
        sessions.retain(|_, &mut exp| now < exp);
        if sessions.len() >= MAX_ACTIVE_SESSIONS {
            sessions.clear();
        }
        sessions.insert(token.clone(), now + Duration::hours(SESSION_TTL_HOURS));
        (StatusCode::OK, Json(LoginResponse { token })).into_response()
    } else {
        let mut guard = state.login_guard.write().await;
        guard.0 += 1;
        if guard.0 >= MAX_LOGIN_FAILURES {
            guard.1 = Some(Utc::now() + Duration::seconds(LOGIN_LOCKOUT_SECS));
            warn!("Web GUI login locked out for {LOGIN_LOCKOUT_SECS}s after {MAX_LOGIN_FAILURES} failures");
        }
        (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response()
    }
}

async fn api_status(State(state): State<WebAppState>, headers: HeaderMap) -> impl IntoResponse {
    if !is_authorized(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(state.daemon.build_status().await).into_response()
}

async fn api_events(State(state): State<WebAppState>, headers: HeaderMap) -> impl IntoResponse {
    if !is_authorized(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let resp = state
        .daemon
        .handle_request(IpcRequest::GetRecentEvents { limit: 100 })
        .await;
    Json(resp).into_response()
}

async fn api_bans(State(state): State<WebAppState>, headers: HeaderMap) -> impl IntoResponse {
    if !is_authorized(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let resp = state.daemon.handle_request(IpcRequest::GetBannedIps).await;
    Json(resp).into_response()
}

async fn api_ban_ip(
    State(state): State<WebAppState>,
    headers: HeaderMap,
    Json(body): Json<BanBody>,
) -> impl IntoResponse {
    if !is_authorized(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let resp = state
        .daemon
        .handle_request(IpcRequest::BanIp {
            ip: body.ip,
            reason: body.reason.unwrap_or_else(|| "Web GUI 1-Click Ban".into()),
            duration_secs: body.duration_secs,
        })
        .await;
    Json(resp).into_response()
}

async fn api_unban_ip(
    State(state): State<WebAppState>,
    headers: HeaderMap,
    Path(ip): Path<String>,
) -> impl IntoResponse {
    if !is_authorized(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let resp = state.daemon.handle_request(IpcRequest::UnbanIp { ip }).await;
    Json(resp).into_response()
}

async fn api_pause_fim(
    State(state): State<WebAppState>,
    headers: HeaderMap,
    Json(body): Json<PauseBody>,
) -> impl IntoResponse {
    if !is_authorized(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let resp = state
        .daemon
        .handle_request(IpcRequest::PauseFim {
            duration_secs: body.duration_secs,
        })
        .await;
    Json(resp).into_response()
}

async fn api_resume_fim(State(state): State<WebAppState>, headers: HeaderMap) -> impl IntoResponse {
    if !is_authorized(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let resp = state.daemon.handle_request(IpcRequest::ResumeFim).await;
    Json(resp).into_response()
}

async fn api_reload_service(
    State(state): State<WebAppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if !is_authorized(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let resp = state
        .daemon
        .handle_request(IpcRequest::ReloadWebServer { server: name })
        .await;
    Json(resp).into_response()
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsAuthQuery>,
    State(state): State<WebAppState>,
) -> impl IntoResponse {
    let tok = query.token.unwrap_or_default();
    if !is_valid_token(&state, &tok).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(mut socket: WebSocket, state: WebAppState) {
    let mut rx = state.daemon.event_tx.subscribe();
    loop {
        tokio::select! {
            Ok(evt) = rx.recv() => {
                if let Ok(json) = serde_json::to_string(&evt) {
                    if socket.send(Message::Text(json)).await.is_err() {
                        break;
                    }
                }
            }
            Some(msg) = socket.next() => {
                if msg.is_err() {
                    break;
                }
            }
            else => break,
        }
    }
}
