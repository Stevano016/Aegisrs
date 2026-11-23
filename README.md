# AegisRS

Lightweight single-binary VPS security agent, Nginx/Apache Intrusion Detection System (IDS), real-time File Integrity Monitor (FIM), and anti-defacement daemon written in Rust.

## Key Features

- **Log Tampering Detection (Anti-Log Wipe):** Monitors log size and Unix inodes on Nginx, Apache, and `/var/log/auth.log` to detect unexpected `truncate` or deletion while distinguishing normal `logrotate` / `copytruncate` cycles.
- **Real-Time FIM & Anti-Defacement:** Watches web roots using non-recursive `inotify` (`walkdir` + dynamic folder registration, skipping `node_modules`, `vendor`, `.git`, `storage/framework`, and `.aegisignore` patterns). Scans for PHP/web-shell signatures, supports maintenance windows (`aegis pause`), and optional auto-quarantine (`chmod 000`).
- **Live Log-Based IDS & Anti-Evasion:**
  - `WebServerProvider` trait for **Nginx** & **Apache** (access + error logs) with `RealIpResolver` (`X-Forwarded-For`, `CF-Connecting-IP`, CIDR `trusted_proxies`).
  - Two-stage **Aho-Corasick + Regex** engine with two-pass URL decoding & SQL comment normalization (`SQLi`, `XSS`, `LFI/RFI`, `.env`/`.git` recon, vulnerability scanners, plus custom TOML rules).
  - Sliding-window **Rate Limiter** with OOM-safe IP eviction, per-IP brute-force detection, and **Distributed IP-Rotation Brute-Force** detection (catches VPN/Tor/proxy rotation).
- **Linux `/proc` Reverse-Shell Watcher:** Monitors processes spawned by web server users (`www-data`, `nginx`, `apache`, `http`) for shells (`sh`, `bash`, `nc`, `socat`, `python`, `/dev/tcp/`, `mkfifo`).
- **Persistence & Docker Monitoring:** Watches `/root/.ssh/authorized_keys`, `/etc/passwd`, `/etc/shadow`, `/etc/crontab`, and Docker container restart loops via `bollard`.
- **Self-Defense Hardening:**
  - Hardcoded anti-self-lockout firewall protection + per-minute auto-ban circuit breaker.
  - Self-integrity tamper watcher on `config.toml` and the AegisRS binary.
  - Hardened Unix Domain Socket (`0600` in `0700` dir) + `systemd` `UMask=0077` & `Restart=always`.
  - Embedded Web GUI bound to `127.0.0.1:8080` with Argon2id auth, login lockout, session TTL, and strict CSP headers.
- **Three Modes in One Binary:**
  - `aegis daemon [--web]` — 24/7 background monitor + SQLite WAL + off-site webhooks (Telegram, Discord, Slack, Custom).
  - `aegis tui` — Interactive `ratatui` terminal dashboard over IPC with **1-Key Ban**.
  - **Embedded Web GUI** — Grafana-style dark observability dashboard (`axum` + `rust-embed`) with live SVG time-series chart and WebSocket alert stream.

## Build & Installation

```bash
# Build optimized release binary
cargo build --release

# Run unit tests
cargo test
```

## Quick Start

```bash
# 1. Generate Argon2id password hash for [web_gui].password_hash
./target/release/aegis hash-password "your-strong-password"

# 2. Copy and edit configuration
cp config.example.toml /etc/aegisrs/config.toml
chmod 600 /etc/aegisrs/config.toml

# 3. Run daemon with embedded Grafana-style Web GUI (127.0.0.1:8080)
./target/release/aegis --config /etc/aegisrs/config.toml daemon --web
```

### CLI Commands

```bash
aegis daemon [--web]              # Start 24/7 monitoring daemon
aegis tui                         # Open interactive Terminal UI dashboard
aegis status                      # Query daemon status via IPC
aegis pause --duration 15m        # Pause FIM during deployments
aegis resume                      # Resume FIM immediately
aegis ban 203.0.113.50 --duration 24h
aegis unban 203.0.113.50
aegis hash-password "<password>"  # Generate Argon2id hash for config.toml
```

### Systemd Service (Linux VPS)

```bash
sudo cp target/release/aegis /usr/local/bin/aegis
sudo cp systemd/aegisrs.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now aegisrs
```

## License

Dual-licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
