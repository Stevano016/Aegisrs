# AegisRS

Lightweight single-binary VPS security agent, reverse-proxy IDS (Nginx & Apache), real-time File Integrity Monitor (FIM), and anti-defacement daemon written in Rust.

## Features
- **Log Tampering Detection (Anti-Log Wipe):** Detects unexpected log truncation or deletion while distinguishing normal `logrotate` cycles.
- **Real-Time FIM & Anti-Defacement:** Watches `/var/www` and web server configs via `inotify` (`notify`), scans for PHP/web-shell signatures, supports `.aegisignore`, maintenance pauses (`aegis pause`), and optional auto-quarantine (`chmod 000`).
- **Live Log-Based IDS:** `WebServerProvider` trait for Nginx & Apache with `X-Forwarded-For` / `CF-Connecting-IP` resolution, Aho-Corasick + Regex rules (SQLi, XSS, LFI/RFI, Recon), and sliding-window rate limiting / brute-force detection (HTTP 401/403 & SSH `auth.log`).
- **Persistence Watcher:** Monitors `/root/.ssh/authorized_keys`, `/etc/passwd`, `/etc/shadow`, and `/etc/crontab`.
- **Three Modes in One Binary:**
  - `aegis daemon [--web]` — 24/7 background monitor + SQLite WAL + off-site webhooks (Telegram, Discord, Slack, Custom).
  - `aegis tui` — Interactive `ratatui` terminal dashboard over IPC with **1-Key Ban**.
  - **Embedded Web GUI** — `axum` + `rust-embed` dashboard bound to `127.0.0.1:8080` with Argon2 authentication and WebSocket live feed.

## Quick Start

```bash
# Build release binary
cargo build --release

# Generate Argon2 password hash for Web GUI
./target/release/aegis hash-password "your-strong-password"

# Start daemon (with optional embedded Web GUI)
./target/release/aegis --config config.example.toml daemon --web

# In another terminal (or SSH session):
./target/release/aegis tui
./target/release/aegis status
./target/release/aegis pause --duration 15m
./target/release/aegis ban 203.0.113.50 --duration 24h
```
