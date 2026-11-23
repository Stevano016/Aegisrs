use crate::actions::firewall::FirewallManager;
use crate::collectors::webserver::WebServerProvider;
use crate::config::Config;
use crate::models::{
    DaemonStatus, DockerContainerMetric, IpcRequest, IpcResponse, SecurityEvent, WebServerStatus,
};
use crate::storage::sqlite::{RingBuffer, SqliteStorage};
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info};

/// Shared daemon state accessed by IPC handlers, Web GUI, and collectors.
#[derive(Clone)]
pub struct DaemonState {
    pub config: Config,
    pub storage: SqliteStorage,
    pub firewall: FirewallManager,
    pub providers: Vec<Arc<dyn WebServerProvider>>,
    pub paused_until: Arc<RwLock<Option<DateTime<Utc>>>>,
    pub events_processed: Arc<AtomicU64>,
    pub start_time: DateTime<Utc>,
    pub live_events: Arc<RwLock<RingBuffer<SecurityEvent>>>,
    pub rps_history: Arc<RwLock<RingBuffer<u64>>>,
    pub docker_metrics: Arc<RwLock<Vec<DockerContainerMetric>>>,
    pub event_tx: broadcast::Sender<SecurityEvent>,
}

impl DaemonState {
    pub async fn build_status(&self) -> DaemonStatus {
        let uptime_secs = (Utc::now() - self.start_time).num_seconds().max(0) as u64;
        let paused_until = *self.paused_until.read().await;
        let alerts_total = self.storage.total_events().unwrap_or(0);
        let active_bans = self.storage.list_bans().map(|b| b.len()).unwrap_or(0);
        let docker_containers = self.docker_metrics.read().await.clone();
        let traffic_rps_history = self
            .rps_history
            .read()
            .await
            .recent(30)
            .into_iter()
            .rev()
            .collect();

        let web_servers = self
            .providers
            .iter()
            .map(|p| WebServerStatus {
                name: p.name().to_string(),
                installed: p.detect_installed(),
                running: p.detect_installed(),
                config_ok: if p.detect_installed() {
                    Some(p.test_config().is_ok())
                } else {
                    None
                },
                log_paths: p
                    .default_log_paths()
                    .into_iter()
                    .map(|pb| pb.display().to_string())
                    .collect(),
            })
            .collect();

        DaemonStatus {
            hostname: self.config.general.hostname.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs,
            paused_until,
            events_processed: self.events_processed.load(Ordering::Relaxed),
            alerts_total,
            active_bans,
            web_servers,
            docker_containers,
            traffic_rps_history,
        }
    }

    pub async fn handle_request(&self, req: IpcRequest) -> IpcResponse {
        match req {
            IpcRequest::GetStatus => IpcResponse::Status {
                status: self.build_status().await,
            },
            IpcRequest::GetRecentEvents { limit } => {
                let live = self.live_events.read().await.recent(limit);
                if !live.is_empty() {
                    IpcResponse::Events { events: live }
                } else {
                    match self.storage.recent_events(limit) {
                        Ok(events) => IpcResponse::Events { events },
                        Err(e) => IpcResponse::Error {
                            message: e.to_string(),
                        },
                    }
                }
            }
            IpcRequest::GetBannedIps => match self.storage.list_bans() {
                Ok(ips) => IpcResponse::BannedIps { ips },
                Err(e) => IpcResponse::Error {
                    message: e.to_string(),
                },
            },
            IpcRequest::BanIp {
                ip,
                reason,
                duration_secs,
            } => match self.firewall.ban_ip(&ip, &reason, duration_secs) {
                Ok(ban) => {
                    if let Err(e) = self.storage.upsert_ban(&ban) {
                        return IpcResponse::Error {
                            message: format!("Banned in firewall but DB save failed: {e}"),
                        };
                    }
                    IpcResponse::Ok {
                        message: format!("Banned IP {} ({})", ban.ip, ban.reason),
                    }
                }
                Err(e) => IpcResponse::Error {
                    message: e.to_string(),
                },
            },
            IpcRequest::UnbanIp { ip } => match self.firewall.unban_ip(&ip) {
                Ok(()) => {
                    let _ = self.storage.remove_ban(&ip);
                    IpcResponse::Ok {
                        message: format!("Unbanned IP {ip}"),
                    }
                }
                Err(e) => IpcResponse::Error {
                    message: e.to_string(),
                },
            },
            IpcRequest::PauseFim { duration_secs } => {
                let until = Utc::now() + Duration::seconds(duration_secs as i64);
                *self.paused_until.write().await = Some(until);
                info!("FIM maintenance window enabled until {until}");
                IpcResponse::Ok {
                    message: format!("FIM paused until {}", until.to_rfc3339()),
                }
            }
            IpcRequest::ResumeFim => {
                *self.paused_until.write().await = None;
                info!("FIM maintenance window resumed");
                IpcResponse::Ok {
                    message: "FIM resumed".to_string(),
                }
            }
            IpcRequest::ReloadWebServer { server } => {
                if let Some(p) = self.providers.iter().find(|p| p.name() == server) {
                    match p.reload_service() {
                        Ok(()) => IpcResponse::Ok {
                            message: format!("Reloaded {server} successfully"),
                        },
                        Err(e) => IpcResponse::Error { message: e },
                    }
                } else {
                    IpcResponse::Error {
                        message: format!("Unknown web server '{server}'"),
                    }
                }
            }
            IpcRequest::SubscribeEvents => IpcResponse::Ok {
                message: "Subscribed".to_string(),
            },
        }
    }
}

async fn handle_ipc_stream<S>(stream: S, state: DaemonState)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req: IpcRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let err = IpcResponse::Error {
                    message: format!("Invalid IPC JSON: {e}"),
                };
                if let Ok(s) = serde_json::to_string(&err) {
                    let _ = writer.write_all(format!("{s}\n").as_bytes()).await;
                }
                continue;
            }
        };

        if matches!(req, IpcRequest::SubscribeEvents) {
            let mut rx = state.event_tx.subscribe();
            let ack = serde_json::to_string(&IpcResponse::Ok {
                message: "Subscribed".to_string(),
            })
            .unwrap();
            let _ = writer.write_all(format!("{ack}\n").as_bytes()).await;
            while let Ok(evt) = rx.recv().await {
                let push = IpcResponse::EventPush { event: evt };
                if let Ok(s) = serde_json::to_string(&push) {
                    if writer.write_all(format!("{s}\n").as_bytes()).await.is_err() {
                        break;
                    }
                }
            }
            break;
        }

        let resp = state.handle_request(req).await;
        if let Ok(s) = serde_json::to_string(&resp) {
            if writer.write_all(format!("{s}\n").as_bytes()).await.is_err() {
                break;
            }
        }
    }
}

/// Starts the IPC server (Unix Domain Socket on Linux/Unix, loopback TCP on Windows).
pub async fn serve_ipc(
    state: DaemonState,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        use tokio::net::UnixListener;
        let sock_path = &state.config.general.socket_path;
        if let Some(parent) = sock_path.parent() {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        if sock_path.exists() {
            let _ = std::fs::remove_file(sock_path);
        }
        let listener = UnixListener::bind(sock_path)
            .with_context(|| format!("Failed to bind IPC socket {}", sock_path.display()))?;
        std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o600))?;
        info!("IPC Unix socket listening at {} (mode 0600)", sock_path.display());

        loop {
            tokio::select! {
                _ = shutdown.recv() => {
                    debug!("Shutting down IPC Unix socket");
                    let _ = std::fs::remove_file(sock_path);
                    break;
                }
                accepted = listener.accept() => {
                    if let Ok((stream, _)) = accepted {
                        let st = state.clone();
                        tokio::spawn(handle_ipc_stream(stream, st));
                    }
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        use tokio::net::TcpListener;
        let addr = format!("127.0.0.1:{}", state.config.general.ipc_tcp_port);
        let listener = TcpListener::bind(&addr)
            .await
            .with_context(|| format!("Failed to bind Windows IPC TCP socket {addr}"))?;
        info!("IPC loopback TCP listening at {addr}");

        loop {
            tokio::select! {
                _ = shutdown.recv() => {
                    debug!("Shutting down IPC TCP socket");
                    break;
                }
                accepted = listener.accept() => {
                    if let Ok((stream, _)) = accepted {
                        let st = state.clone();
                        tokio::spawn(handle_ipc_stream(stream, st));
                    }
                }
            }
        }
    }

    Ok(())
}

/// Sends a single synchronous IPC request from CLI/TUI to the running daemon.
pub async fn send_ipc_request(cfg: &Config, req: IpcRequest) -> Result<IpcResponse> {
    let payload = format!("{}\n", serde_json::to_string(&req)?);

    #[cfg(unix)]
    let mut stream = tokio::net::UnixStream::connect(&cfg.general.socket_path)
        .await
        .with_context(|| {
            format!(
                "Cannot connect to AegisRS daemon at {}. Is `aegis daemon` running?",
                cfg.general.socket_path.display()
            )
        })?;

    #[cfg(not(unix))]
    let mut stream = tokio::net::TcpStream::connect(format!(
        "127.0.0.1:{}",
        cfg.general.ipc_tcp_port
    ))
    .await
    .context("Cannot connect to AegisRS daemon on loopback IPC port. Is `aegis daemon` running?")?;

    stream.write_all(payload.as_bytes()).await?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let resp: IpcResponse = serde_json::from_str(line.trim())
        .with_context(|| format!("Invalid IPC response: {line}"))?;
    Ok(resp)
}
