use crate::models::Severity;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Root configuration loaded from `config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub general: GeneralConfig,
    pub web_servers: WebServersConfig,
    pub fim: FimConfig,
    pub ids: IdsConfig,
    pub alerts: AlertsConfig,
    pub web_gui: WebGuiConfig,
    pub docker: DockerConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            web_servers: WebServersConfig::default(),
            fim: FimConfig::default(),
            ids: IdsConfig::default(),
            alerts: AlertsConfig::default(),
            web_gui: WebGuiConfig::default(),
            docker: DockerConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    pub hostname: String,
    pub sqlite_path: PathBuf,
    pub socket_path: PathBuf,
    /// Used on Windows where Unix Domain Sockets are not used for IPC.
    pub ipc_tcp_port: u16,
    pub auth_log_path: PathBuf,
    pub custom_rules_path: Option<PathBuf>,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            hostname: default_hostname(),
            sqlite_path: PathBuf::from("/var/lib/aegisrs/events.db"),
            socket_path: PathBuf::from("/run/aegisrs/aegis.sock"),
            ipc_tcp_port: 19450,
            auth_log_path: PathBuf::from("/var/log/auth.log"),
            custom_rules_path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebServersConfig {
    pub auto_detect: bool,
    pub trusted_proxies: Vec<String>,
    pub nginx: WebServerInstanceConfig,
    pub apache: WebServerInstanceConfig,
}

impl Default for WebServersConfig {
    fn default() -> Self {
        Self {
            auto_detect: true,
            trusted_proxies: vec!["127.0.0.1".to_string(), "::1".to_string()],
            nginx: WebServerInstanceConfig {
                enabled: true,
                access_log: PathBuf::from("/var/log/nginx/access.log"),
                error_log: PathBuf::from("/var/log/nginx/error.log"),
            },
            apache: WebServerInstanceConfig {
                enabled: true,
                access_log: PathBuf::from("/var/log/apache2/access.log"),
                error_log: PathBuf::from("/var/log/apache2/error.log"),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebServerInstanceConfig {
    pub enabled: bool,
    pub access_log: PathBuf,
    pub error_log: PathBuf,
}

impl Default for WebServerInstanceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            access_log: PathBuf::new(),
            error_log: PathBuf::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FimConfig {
    pub enabled: bool,
    pub watch_paths: Vec<PathBuf>,
    pub persistence_paths: Vec<PathBuf>,
    pub auto_quarantine: bool,
    pub quarantine_dir: PathBuf,
    pub ignore_file: PathBuf,
}

impl Default for FimConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            watch_paths: vec![
                PathBuf::from("/var/www/html"),
                PathBuf::from("/etc/nginx/sites-enabled"),
                PathBuf::from("/etc/apache2/sites-enabled"),
            ],
            persistence_paths: vec![
                PathBuf::from("/root/.ssh/authorized_keys"),
                PathBuf::from("/etc/passwd"),
                PathBuf::from("/etc/shadow"),
                PathBuf::from("/etc/crontab"),
            ],
            auto_quarantine: false,
            quarantine_dir: PathBuf::from("/var/lib/aegisrs/quarantine"),
            ignore_file: PathBuf::from(".aegisignore"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IdsConfig {
    pub max_rps_per_ip: u32,
    pub auth_fail_threshold: u32,
    pub distributed_auth_threshold: u32,
    pub window_secs: u64,
    pub auto_ban_on_critical: bool,
    pub auto_ban_duration_secs: u64,
    /// "ufw", "iptables", "nftables", or "none"
    pub firewall_backend: String,
    pub whitelist_ips: Vec<String>,
}

impl Default for IdsConfig {
    fn default() -> Self {
        Self {
            max_rps_per_ip: 50,
            auth_fail_threshold: 10,
            distributed_auth_threshold: 15,
            window_secs: 10,
            auto_ban_on_critical: false,
            auto_ban_duration_secs: 86400,
            firewall_backend: "ufw".to_string(),
            whitelist_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AlertsConfig {
    pub telegram: TelegramAlertConfig,
    pub discord: WebhookAlertConfig,
    pub slack: WebhookAlertConfig,
    pub custom_webhook: WebhookAlertConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TelegramAlertConfig {
    pub enabled: bool,
    pub bot_token: String,
    pub chat_id: String,
    pub min_severity: Severity,
}

impl Default for TelegramAlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bot_token: String::new(),
            chat_id: String::new(),
            min_severity: Severity::High,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebhookAlertConfig {
    pub enabled: bool,
    pub url: String,
    pub min_severity: Severity,
    pub bearer_token: Option<String>,
}

impl Default for WebhookAlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            min_severity: Severity::High,
            bearer_token: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebGuiConfig {
    pub enabled: bool,
    pub bind_address: String,
    /// Argon2id PHC hash string for Web GUI password login.
    /// Generate via `aegis hash-password`.
    pub password_hash: String,
    /// Optional static API bearer token (supports `ENV:VAR_NAME`).
    pub api_token: String,
}

impl Default for WebGuiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: "127.0.0.1:8080".to_string(),
            password_hash: String::new(),
            api_token: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerConfig {
    pub enabled: bool,
    pub poll_interval_secs: u64,
    pub cpu_alert_threshold_percent: f64,
    pub restart_loop_threshold: i64,
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval_secs: 15,
            cpu_alert_threshold_percent: 85.0,
            restart_loop_threshold: 5,
        }
    }
}

impl Config {
    /// Loads configuration from a TOML file, or returns defaults if `path` is None.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(p) => {
                let raw = fs::read_to_string(p)
                    .with_context(|| format!("Failed to read config file: {}", p.display()))?;
                let mut cfg: Config = toml::from_str(&raw)
                    .with_context(|| format!("Failed to parse TOML config: {}", p.display()))?;
                cfg.resolve_env_secrets();
                Ok(cfg)
            }
            None => {
                let default_path = Path::new("/etc/aegisrs/config.toml");
                if default_path.exists() {
                    Self::load(Some(default_path))
                } else {
                    let local_path = Path::new("config.toml");
                    if local_path.exists() {
                        Self::load(Some(local_path))
                    } else {
                        Ok(Self::default())
                    }
                }
            }
        }
    }

    fn resolve_env_secrets(&mut self) {
        self.alerts.telegram.bot_token = resolve_secret(&self.alerts.telegram.bot_token);
        self.alerts.discord.url = resolve_secret(&self.alerts.discord.url);
        self.alerts.slack.url = resolve_secret(&self.alerts.slack.url);
        self.alerts.custom_webhook.url = resolve_secret(&self.alerts.custom_webhook.url);
        if let Some(ref tok) = self.alerts.custom_webhook.bearer_token {
            self.alerts.custom_webhook.bearer_token = Some(resolve_secret(tok));
        }
        self.web_gui.api_token = resolve_secret(&self.web_gui.api_token);
    }
}

/// Resolves `"ENV:VAR_NAME"` values from process environment variables.
pub fn resolve_secret(value: &str) -> String {
    if let Some(var_name) = value.strip_prefix("ENV:") {
        std::env::var(var_name.trim()).unwrap_or_default()
    } else {
        value.to_string()
    }
}

/// Parses human-readable durations such as `"30s"`, `"15m"`, `"24h"`, `"7d"`.
pub fn parse_duration(input: &str) -> Result<Duration> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        anyhow::bail!("Duration string cannot be empty");
    }
    let (num_str, multiplier) = if let Some(s) = trimmed.strip_suffix('s') {
        (s, 1u64)
    } else if let Some(m) = trimmed.strip_suffix('m') {
        (m, 60u64)
    } else if let Some(h) = trimmed.strip_suffix('h') {
        (h, 3600u64)
    } else if let Some(d) = trimmed.strip_suffix('d') {
        (d, 86400u64)
    } else {
        (trimmed, 1u64)
    };
    let val: u64 = num_str
        .trim()
        .parse()
        .with_context(|| format!("Invalid duration number in '{input}'"))?;
    Ok(Duration::from_secs(val * multiplier))
}

fn default_hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "aegis-vps".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86400));
        assert_eq!(parse_duration("2d").unwrap(), Duration::from_secs(172800));
        assert!(parse_duration("abc").is_err());
    }

    #[test]
    fn test_resolve_secret_env() {
        std::env::set_var("AEGIS_TEST_SECRET_KEY", "secret-123");
        assert_eq!(resolve_secret("ENV:AEGIS_TEST_SECRET_KEY"), "secret-123");
        assert_eq!(resolve_secret("plain-token"), "plain-token");
        std::env::remove_var("AEGIS_TEST_SECRET_KEY");
    }

    #[test]
    fn test_default_config_serializes() {
        let cfg = Config::default();
        let toml_str = toml::to_string_pretty(&cfg).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.ids.max_rps_per_ip, 50);
        assert_eq!(parsed.web_gui.bind_address, "127.0.0.1:8080");
    }
}
