use crate::models::{BannedIp, DaemonStatus, SecurityEvent, Severity};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table, TableState},
    Frame,
};
use std::collections::HashMap;

pub struct TuiAppState {
    pub status: Option<DaemonStatus>,
    pub events: Vec<SecurityEvent>,
    pub bans: Vec<BannedIp>,
    pub table_state: TableState,
    pub status_message: String,
}

impl TuiAppState {
    pub fn new() -> Self {
        let mut ts = TableState::default();
        ts.select(Some(0));
        Self {
            status: None,
            events: Vec::new(),
            bans: Vec::new(),
            table_state: ts,
            status_message: "Connected to AegisRS daemon. Press 'b' to 1-Key Ban selected IP.".into(),
        }
    }

    pub fn selected_event(&self) -> Option<&SecurityEvent> {
        self.table_state
            .selected()
            .and_then(|idx| self.events.get(idx))
    }

    pub fn move_selection(&mut self, delta: isize) {
        if self.events.is_empty() {
            self.table_state.select(None);
            return;
        }
        let len = self.events.len() as isize;
        let current = self.table_state.selected().unwrap_or(0) as isize;
        let next = (current + delta).clamp(0, len - 1) as usize;
        self.table_state.select(Some(next));
    }
}

fn severity_style(sev: Severity) -> Style {
    match sev {
        Severity::Critical => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        Severity::High => Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
        Severity::Medium => Style::default().fg(Color::Yellow),
        Severity::Low => Style::default().fg(Color::Cyan),
    }
}

pub fn render_dashboard(f: &mut Frame, app: &mut TuiAppState) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(f.area());

    render_header(f, root[0], app);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(34), Constraint::Percentage(66)])
        .split(root[1]);

    render_left_sidebar(f, body[0], app);
    render_alerts_table(f, body[1], app);
    render_footer(f, root[2], app);
}

fn render_header(f: &mut Frame, area: Rect, app: &TuiAppState) {
    let (host, ver, uptime, fim_state, alerts, bans) = if let Some(ref st) = app.status {
        let fim = if st.paused_until.is_some() {
            "PAUSED (MAINT)"
        } else {
            "ACTIVE"
        };
        (
            st.hostname.as_str(),
            st.version.as_str(),
            format!("{}s", st.uptime_secs),
            fim,
            st.alerts_total,
            st.active_bans,
        )
    } else {
        ("connecting...", env!("CARGO_PKG_VERSION"), "-".into(), "UNKNOWN", 0, 0)
    };

    let line = Line::from(vec![
        Span::styled(
            format!(" AegisRS v{ver} "),
            Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("  Host: {host}  |  Uptime: {uptime}  |  FIM: ")),
        Span::styled(
            fim_state,
            if fim_state == "ACTIVE" {
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            },
        ),
        Span::raw(format!("  |  Alerts: {alerts}  |  Banned IPs: {bans}")),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" AegisRS Security Operations TUI ");
    f.render_widget(Paragraph::new(line).block(block), area);
}

fn render_left_sidebar(f: &mut Frame, area: Rect, app: &TuiAppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Min(6),
            Constraint::Length(8),
        ])
        .split(area);

    // 1. Traffic Sparkline
    let rps_data: Vec<u64> = app
        .status
        .as_ref()
        .map(|s| {
            if s.traffic_rps_history.is_empty() {
                vec![0, 0, 0, 0]
            } else {
                s.traffic_rps_history.clone()
            }
        })
        .unwrap_or_else(|| vec![0]);

    let sparkline = Sparkline::default()
        .block(Block::default().borders(Borders::ALL).title(" Log Events / Sec "))
        .data(&rps_data)
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(sparkline, chunks[0]);

    // 2. Top Attacker IPs
    let mut ip_counts: HashMap<&str, usize> = HashMap::new();
    for ev in &app.events {
        if let Some(ref ip) = ev.source_ip {
            *ip_counts.entry(ip.as_str()).or_insert(0) += 1;
        }
    }
    let mut sorted_ips: Vec<(&str, usize)> = ip_counts.into_iter().collect();
    sorted_ips.sort_by(|a, b| b.1.cmp(&a.1));

    let ip_rows: Vec<Row> = sorted_ips
        .into_iter()
        .take(8)
        .map(|(ip, count)| Row::new(vec![Cell::from(ip), Cell::from(count.to_string())]))
        .collect();

    let ip_table = Table::new(ip_rows, [Constraint::Percentage(70), Constraint::Percentage(30)])
        .header(
            Row::new(vec!["IP Address", "Hits"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().borders(Borders::ALL).title(" Top Attacker IPs "));
    f.render_widget(ip_table, chunks[1]);

    // 3. Web Server & Docker Status
    let mut lines = Vec::new();
    if let Some(ref st) = app.status {
        for ws in &st.web_servers {
            let state_str = if ws.installed {
                if ws.config_ok == Some(true) {
                    "OK"
                } else {
                    "CFG ERR"
                }
            } else {
                "Not Found"
            };
            lines.push(Line::from(format!("• {:<8} : {}", ws.name, state_str)));
        }
        lines.push(Line::from(format!(
            "• Docker   : {} containers",
            st.docker_containers.len()
        )));
    }
    let svc_widget = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Services & Containers "));
    f.render_widget(svc_widget, chunks[2]);
}

fn render_alerts_table(f: &mut Frame, area: Rect, app: &mut TuiAppState) {
    let rows: Vec<Row> = app
        .events
        .iter()
        .map(|ev| {
            let ts = ev.timestamp.format("%H:%M:%S").to_string();
            let sev = ev.severity.to_string();
            let ip = ev.source_ip.as_deref().unwrap_or("-");
            Row::new(vec![
                Cell::from(ts),
                Cell::from(sev).style(severity_style(ev.severity)),
                Cell::from(ip.to_string()),
                Cell::from(ev.title.clone()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(9),
            Constraint::Length(10),
            Constraint::Length(16),
            Constraint::Min(20),
        ],
    )
    .header(
        Row::new(vec!["Time", "Severity", "Source IP", "Alert Title"])
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().borders(Borders::ALL).title(" Live Security Alerts "))
    .row_highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD));

    f.render_stateful_widget(table, area, &mut app.table_state);
}

fn render_footer(f: &mut Frame, area: Rect, app: &TuiAppState) {
    let text = format!(
        "[↑/↓] Select  [b] 1-Key Ban (24h)  [B] Perm Ban  [p] Pause FIM (15m)  [r] Reload Nginx  [q] Quit  |  {}",
        app.status_message
    );
    let p = Paragraph::new(text)
        .style(Style::default().fg(Color::Gray))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(p, area);
}
