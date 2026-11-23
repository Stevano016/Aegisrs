pub mod ui;

use crate::config::Config;
use crate::ipc::socket::send_ipc_request;
use crate::models::{IpcRequest, IpcResponse};
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::time::{Duration, Instant};
use ui::{render_dashboard, TuiAppState};

pub async fn run_tui(cfg: &Config) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = TuiAppState::new();
    let res = event_loop(&mut terminal, cfg, &mut app).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res
}

async fn refresh_state(cfg: &Config, app: &mut TuiAppState) {
    if let Ok(IpcResponse::Status { status }) = send_ipc_request(cfg, IpcRequest::GetStatus).await {
        app.status = Some(status);
    }
    if let Ok(IpcResponse::Events { events }) =
        send_ipc_request(cfg, IpcRequest::GetRecentEvents { limit: 100 }).await
    {
        app.events = events;
    }
    if let Ok(IpcResponse::BannedIps { ips }) = send_ipc_request(cfg, IpcRequest::GetBannedIps).await
    {
        app.bans = ips;
    }
}

async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    cfg: &Config,
    app: &mut TuiAppState,
) -> Result<()> {
    let mut last_refresh = Instant::now() - Duration::from_secs(10);

    loop {
        if last_refresh.elapsed() >= Duration::from_secs(1) {
            refresh_state(cfg, app).await;
            last_refresh = Instant::now();
        }

        terminal.draw(|f| render_dashboard(f, app))?;

        if event::poll(Duration::from_millis(150))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Down | KeyCode::Char('j') => app.move_selection(1),
                    KeyCode::Up | KeyCode::Char('k') => app.move_selection(-1),
                    KeyCode::Char('b') | KeyCode::Char('B') => {
                        let permanent = key.code == KeyCode::Char('B');
                        if let Some(ip) = app.selected_event().and_then(|e| e.source_ip.clone()) {
                            let req = IpcRequest::BanIp {
                                ip: ip.clone(),
                                reason: "TUI 1-Key Ban".into(),
                                duration_secs: if permanent { None } else { Some(86400) },
                            };
                            match send_ipc_request(cfg, req).await {
                                Ok(IpcResponse::Ok { message }) => app.status_message = message,
                                Ok(IpcResponse::Error { message }) => {
                                    app.status_message = format!("Error: {message}")
                                }
                                Err(e) => app.status_message = format!("IPC error: {e}"),
                                _ => {}
                            }
                            refresh_state(cfg, app).await;
                        } else {
                            app.status_message = "Selected alert has no source IP.".into();
                        }
                    }
                    KeyCode::Char('p') => {
                        let is_paused = app
                            .status
                            .as_ref()
                            .and_then(|s| s.paused_until)
                            .is_some();
                        let req = if is_paused {
                            IpcRequest::ResumeFim
                        } else {
                            IpcRequest::PauseFim { duration_secs: 900 }
                        };
                        match send_ipc_request(cfg, req).await {
                            Ok(IpcResponse::Ok { message }) => app.status_message = message,
                            Ok(IpcResponse::Error { message }) => {
                                app.status_message = format!("Error: {message}")
                            }
                            Err(e) => app.status_message = format!("IPC error: {e}"),
                            _ => {}
                        }
                        refresh_state(cfg, app).await;
                    }
                    KeyCode::Char('r') => {
                        match send_ipc_request(
                            cfg,
                            IpcRequest::ReloadWebServer {
                                server: "nginx".into(),
                            },
                        )
                        .await
                        {
                            Ok(IpcResponse::Ok { message }) => app.status_message = message,
                            Ok(IpcResponse::Error { message }) => {
                                app.status_message = format!("Reload error: {message}")
                            }
                            Err(e) => app.status_message = format!("IPC error: {e}"),
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}
