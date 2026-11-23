mod actions;
mod collectors;
mod config;
mod engine;
mod ipc;
mod models;
mod storage;
mod tui;
mod web;

use actions::firewall::FirewallManager;
use actions::quarantine::quarantine_file;
use actions::webhook::WebhookNotifier;
use anyhow::Result;
use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHasher};
use chrono::Utc;
use clap::{Parser, Subcommand};
use collectors::docker::spawn_docker_monitor;
use collectors::fim::spawn_fim_watcher;
use collectors::log_watcher::spawn_log_tailer;
use collectors::proc_watcher::spawn_process_watcher;
use collectors::webserver::apache::ApacheProvider;
use collectors::webserver::nginx::NginxProvider;
use collectors::webserver::{RealIpResolver, WebServerProvider};
use config::{parse_duration, Config};
use engine::DetectionEngine;
use ipc::socket::{send_ipc_request, serve_ipc, DaemonState};
use models::{CollectorMessage, EventCategory, IpcRequest, IpcResponse, SecurityEvent, Severity};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use storage::sqlite::{RingBuffer, SqliteStorage};
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "aegis",
    version,
    about = "AegisRS — Lightweight single-binary VPS security agent, IDS & anti-defacement daemon"
)]
struct Cli {
    /// Path to config.toml
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the 24/7 security monitoring daemon
    Daemon {
        /// Enable the embedded Web GUI (default listen 127.0.0.1:8080)
        #[arg(long)]
        web: bool,
    },
    /// Open the interactive Terminal UI dashboard
    Tui,
    /// Ban an IP address via the configured firewall backend
    Ban {
        ip: String,
        /// Optional duration (e.g. 24h, 30m). Omit for permanent ban.
        #[arg(long)]
        duration: Option<String>,
        #[arg(long, default_value = "Manual CLI Ban")]
        reason: String,
    },
    /// Unban an IP address
    Unban { ip: String },
    /// Show daemon status, active bans, and web server health
    Status,
    /// Pause File Integrity Monitoring during deployments (Maintenance Window)
    Pause {
        #[arg(long, default_value = "15m")]
        duration: String,
    },
    /// Resume File Integrity Monitoring immediately
    Resume,
    /// Generate an Argon2id password hash for [web_gui].password_hash
    HashPassword { password: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let mut cfg = Config::load(cli.config.as_deref())?;

    match cli.command {
        Commands::Daemon { web } => {
            if web {
                cfg.web_gui.enabled = true;
            }
            run_daemon(cfg, cli.config).await?;
        }
        Commands::Tui => {
            tui::run_tui(&cfg).await?;
        }
        Commands::Ban {
            ip,
            duration,
            reason,
        } => {
            let duration_secs = match duration {
                Some(d) => Some(parse_duration(&d)?.as_secs()),
                None => None,
            };
            let resp = send_ipc_request(
                &cfg,
                IpcRequest::BanIp {
                    ip,
                    reason,
                    duration_secs,
                },
            )
            .await?;
            print_ipc_response(resp);
        }
        Commands::Unban { ip } => {
            let resp = send_ipc_request(&cfg, IpcRequest::UnbanIp { ip }).await?;
            print_ipc_response(resp);
        }
        Commands::Status => {
            let resp = send_ipc_request(&cfg, IpcRequest::GetStatus).await?;
            print_ipc_response(resp);
        }
        Commands::Pause { duration } => {
            let secs = parse_duration(&duration)?.as_secs();
            let resp = send_ipc_request(&cfg, IpcRequest::PauseFim { duration_secs: secs }).await?;
            print_ipc_response(resp);
        }
        Commands::Resume => {
            let resp = send_ipc_request(&cfg, IpcRequest::ResumeFim).await?;
            print_ipc_response(resp);
        }
        Commands::HashPassword { password } => {
            let salt = SaltString::generate(&mut OsRng);
            let hash = Argon2::default()
                .hash_password(password.as_bytes(), &salt)
                .map_err(|e| anyhow::anyhow!("Argon2 hashing failed: {e}"))?
                .to_string();
            println!("{hash}");
        }
    }

    Ok(())
}

fn print_ipc_response(resp: IpcResponse) {
    match resp {
        IpcResponse::Ok { message } => println!("[OK] {message}"),
        IpcResponse::Error { message } => eprintln!("[ERROR] {message}"),
        IpcResponse::Status { status } => {
            println!("AegisRS v{} ({})", status.version, status.hostname);
            println!(
                "Uptime: {}s | Events: {} | Alerts: {} | Active Bans: {}",
                status.uptime_secs,
                status.events_processed,
                status.alerts_total,
                status.active_bans
            );
            if let Some(until) = status.paused_until {
                println!("FIM Status: PAUSED until {until}");
            } else {
                println!("FIM Status: ACTIVE");
            }
            for ws in status.web_servers {
                println!(
                    "  WebServer {:<8}: installed={}, config_ok={:?}",
                    ws.name, ws.installed, ws.config_ok
                );
            }
        }
        other => println!("{}", serde_json::to_string_pretty(&other).unwrap_or_default()),
    }
}

async fn run_daemon(cfg: Config, config_path: Option<PathBuf>) -> Result<()> {
    info!(
        "Starting AegisRS daemon v{} on {}",
        env!("CARGO_PKG_VERSION"),
        cfg.general.hostname
    );

    let storage = SqliteStorage::open(&cfg.general.sqlite_path)?;
    let firewall = FirewallManager::new(
        &cfg.ids.firewall_backend,
        &cfg.ids.whitelist_ips,
        &cfg.web_servers.trusted_proxies,
    );
    let notifier = WebhookNotifier::new(&cfg.general.hostname, cfg.alerts.clone());
    let resolver = RealIpResolver::new(&cfg.web_servers.trusted_proxies);

    let providers: Vec<Arc<dyn WebServerProvider>> = vec![
        Arc::new(NginxProvider::new(resolver.clone())),
        Arc::new(ApacheProvider::new(resolver)),
    ];

    let (event_tx, _) = broadcast::channel::<SecurityEvent>(256);
    let (shutdown_tx, _) = broadcast::channel::<()>(16);

    let state = DaemonState {
        config: cfg.clone(),
        storage: storage.clone(),
        firewall: firewall.clone(),
        providers: providers.clone(),
        paused_until: Arc::new(RwLock::new(None)),
        events_processed: Arc::new(AtomicU64::new(0)),
        start_time: Utc::now(),
        live_events: Arc::new(RwLock::new(RingBuffer::new(200))),
        rps_history: Arc::new(RwLock::new(RingBuffer::new(60))),
        docker_metrics: Arc::new(RwLock::new(Vec::new())),
        event_tx: event_tx.clone(),
    };

    let (collector_tx, mut collector_rx) = mpsc::channel::<CollectorMessage>(1024);

    // 1. Spawn web server access & error log tailers
    for provider in &providers {
        let (enabled, access_log, error_log) = match provider.name() {
            "nginx" => (
                cfg.web_servers.nginx.enabled
                    || (cfg.web_servers.auto_detect && provider.detect_installed()),
                cfg.web_servers.nginx.access_log.clone(),
                cfg.web_servers.nginx.error_log.clone(),
            ),
            "apache" => (
                cfg.web_servers.apache.enabled
                    || (cfg.web_servers.auto_detect && provider.detect_installed()),
                cfg.web_servers.apache.access_log.clone(),
                cfg.web_servers.apache.error_log.clone(),
            ),
            _ => (false, PathBuf::new(), PathBuf::new()),
        };
        if enabled && !access_log.as_os_str().is_empty() {
            info!(
                "Watching {} access log: {}",
                provider.name(),
                access_log.display()
            );
            spawn_log_tailer(
                access_log,
                Some(provider.clone()),
                false,
                None,
                collector_tx.clone(),
                shutdown_tx.subscribe(),
            );
        }
        if enabled && !error_log.as_os_str().is_empty() {
            info!(
                "Watching {} error log: {}",
                provider.name(),
                error_log.display()
            );
            spawn_log_tailer(
                error_log,
                None,
                false,
                Some(provider.name().to_string()),
                collector_tx.clone(),
                shutdown_tx.subscribe(),
            );
        }
    }

    // 2. Spawn SSH auth.log tailer
    if !cfg.general.auth_log_path.as_os_str().is_empty() {
        spawn_log_tailer(
            cfg.general.auth_log_path.clone(),
            None,
            true,
            None,
            collector_tx.clone(),
            shutdown_tx.subscribe(),
        );
    }

    // 3. Spawn FIM & Persistence Watcher
    spawn_fim_watcher(
        cfg.fim.clone(),
        state.paused_until.clone(),
        collector_tx.clone(),
        shutdown_tx.subscribe(),
    );

    // 3b. Spawn Linux /proc Reverse-Shell & Web User Process Watcher
    spawn_process_watcher(collector_tx.clone(), shutdown_tx.subscribe());

    // 3c. Spawn Self-Integrity Tamper Watcher (config.toml & AegisRS binary)
    spawn_self_integrity_watcher(config_path, collector_tx.clone(), shutdown_tx.subscribe());

    // 4. Spawn Docker Monitor
    spawn_docker_monitor(
        cfg.docker.clone(),
        state.docker_metrics.clone(),
        collector_tx.clone(),
        shutdown_tx.subscribe(),
    );

    // 5. Spawn IPC Server
    let ipc_state = state.clone();
    let ipc_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        if let Err(e) = serve_ipc(ipc_state, ipc_shutdown).await {
            error!("IPC server error: {e}");
        }
    });

    // 6. Spawn Embedded Web GUI (if enabled)
    if cfg.web_gui.enabled {
        let web_state = state.clone();
        let web_shutdown = shutdown_tx.subscribe();
        tokio::spawn(async move {
            if let Err(e) = web::serve_web_gui(web_state, web_shutdown).await {
                error!("Web GUI server error: {e}");
            }
        });
    }

    // 7. RPS Sparkline sampler
    let rps_counter = Arc::new(AtomicU64::new(0));
    let rps_counter_tick = rps_counter.clone();
    let rps_hist = state.rps_history.clone();
    let mut rps_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = rps_shutdown.recv() => break,
                _ = interval.tick() => {
                    let count = rps_counter_tick.swap(0, Ordering::Relaxed);
                    rps_hist.write().await.push(count);
                }
            }
        }
    });

    let mut engine = DetectionEngine::new(&cfg);
    let webhook_sem = Arc::new(tokio::sync::Semaphore::new(8));

    loop {
        tokio::select! {
            _ = shutdown_signal() => {
                warn!("Shutdown signal received; sending off-site alert and stopping...");
                let evt = SecurityEvent::new(
                    Severity::High,
                    EventCategory::System,
                    "AegisRS Daemon Stopping",
                    "AegisRS daemon received termination signal (SIGINT/SIGTERM)",
                )
                .with_rule_id("AEGIS-SYS-SHUTDOWN");
                notifier.notify(&evt).await;
                let _ = shutdown_tx.send(());
                break;
            }
            Some(msg) = collector_rx.recv() => {
                state.events_processed.fetch_add(1, Ordering::Relaxed);
                rps_counter.fetch_add(1, Ordering::Relaxed);

                let detected = match msg {
                    CollectorMessage::LogEntry(entry) => engine.analyze_log(&entry),
                    CollectorMessage::DirectEvent(evt) => vec![evt],
                };

                for mut evt in detected {
                    // Auto-Quarantine for detected Web Shells
                    if evt.category == EventCategory::WebShell && cfg.fim.auto_quarantine {
                        if let Some(ref fpath) = evt.file_path {
                            match quarantine_file(Path::new(fpath), &cfg.fim.quarantine_dir, &evt.title) {
                                Ok(dest) => {
                                    evt = evt.with_action_taken(format!("Quarantined to {}", dest.display()));
                                }
                                Err(e) => {
                                    warn!("Auto-quarantine failed for {fpath}: {e}");
                                }
                            }
                        }
                    }

                    // Optional Auto-Ban on Critical events (protected by circuit breaker)
                    if evt.severity == Severity::Critical && cfg.ids.auto_ban_on_critical {
                        if let Some(ip) = evt.source_ip.clone() {
                            match firewall.try_auto_ban(&ip, &evt.title, Some(cfg.ids.auto_ban_duration_secs)) {
                                Ok(ban) => {
                                    let _ = storage.upsert_ban(&ban);
                                    evt = evt.with_action_taken(format!("Auto-banned {ip}"));
                                }
                                Err(e) => warn!("Auto-ban skipped for {ip}: {e}"),
                            }
                        }
                    }

                    if let Err(e) = storage.insert_event(&evt) {
                        warn!("Failed to persist event to SQLite: {e}");
                    }
                    state.live_events.write().await.push(evt.clone());
                    let _ = event_tx.send(evt.clone());

                    let n = notifier.clone();
                    let sem = webhook_sem.clone();
                    tokio::spawn(async move {
                        if let Ok(_permit) = sem.acquire().await {
                            n.notify(&evt).await;
                        }
                    });
                }
            }
        }
    }

    Ok(())
}

fn spawn_self_integrity_watcher(
    config_path: Option<PathBuf>,
    tx: mpsc::Sender<CollectorMessage>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    let mut targets: Vec<(PathBuf, Option<(u64, std::time::SystemTime)>)> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Ok(meta) = std::fs::metadata(&exe) {
            if let Ok(mtime) = meta.modified() {
                targets.push((exe, Some((meta.len(), mtime))));
            }
        }
    }
    if let Some(cfg) = config_path {
        if let Ok(meta) = std::fs::metadata(&cfg) {
            if let Ok(mtime) = meta.modified() {
                targets.push((cfg, Some((meta.len(), mtime))));
            }
        }
    }
    if targets.is_empty() {
        return;
    }

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = shutdown.recv() => break,
                _ = interval.tick() => {
                    for (path, baseline) in &mut targets {
                        let current = std::fs::metadata(&*path)
                            .ok()
                            .and_then(|m| m.modified().ok().map(|t| (m.len(), t)));
                        if *baseline != current {
                            warn!("CRITICAL: Self-integrity change detected on {}", path.display());
                            let evt = SecurityEvent::new(
                                Severity::Critical,
                                EventCategory::System,
                                "AegisRS Self-Integrity Tampering Detected",
                                format!("Protected AegisRS file modified or removed: {}", path.display()),
                            )
                            .with_file_path(path.display().to_string())
                            .with_rule_id("AEGIS-SELF-TAMPER");
                            let _ = tx.send(CollectorMessage::DirectEvent(evt)).await;
                            *baseline = current;
                        }
                    }
                }
            }
        }
    });
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
