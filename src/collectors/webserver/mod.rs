pub mod apache;
pub mod nginx;

use crate::models::UnifiedLogEntry;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use regex::Regex;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::OnceLock;

/// Trait abstracting web server log parsing, detection, and service management.
pub trait WebServerProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn detect_installed(&self) -> bool;
    fn default_log_paths(&self) -> Vec<PathBuf>;
    fn parse_log_line(&self, raw_line: &str) -> Option<UnifiedLogEntry>;
    fn test_config(&self) -> Result<String, String>;
    fn reload_service(&self) -> Result<(), String>;
}

/// Resolves the true client IP behind reverse proxies (Nginx, Cloudflare, etc.).
#[derive(Debug, Clone)]
pub struct RealIpResolver {
    trusted_proxies: Vec<IpNetwork>,
}

impl RealIpResolver {
    pub fn new(cidrs: &[String]) -> Self {
        let mut trusted_proxies = Vec::new();
        for raw in cidrs {
            if let Ok(net) = raw.trim().parse::<IpNetwork>() {
                trusted_proxies.push(net);
            } else if let Ok(ip) = raw.trim().parse::<IpAddr>() {
                let net = match ip {
                    IpAddr::V4(v4) => IpNetwork::V4(ipnetwork::Ipv4Network::new(v4, 32).unwrap()),
                    IpAddr::V6(v6) => IpNetwork::V6(ipnetwork::Ipv6Network::new(v6, 128).unwrap()),
                };
                trusted_proxies.push(net);
            }
        }
        Self { trusted_proxies }
    }

    pub fn is_trusted_proxy(&self, ip_str: &str) -> bool {
        let Ok(ip) = ip_str.trim().parse::<IpAddr>() else {
            return false;
        };
        self.trusted_proxies.iter().any(|net| net.contains(ip))
    }

    /// Resolves real client IP given the socket peer IP and optional forwarded headers.
    pub fn resolve(&self, peer_ip: &str, cf_connecting_ip: Option<&str>, x_forwarded_for: Option<&str>) -> String {
        if !self.is_trusted_proxy(peer_ip) {
            return peer_ip.to_string();
        }
        if let Some(cf) = cf_connecting_ip.map(str::trim).filter(|s| !s.is_empty() && *s != "-") {
            if cf.parse::<IpAddr>().is_ok() {
                return cf.to_string();
            }
        }
        if let Some(xff) = x_forwarded_for {
            // Walk right-to-left skipping trusted proxies to find the first untrusted client IP.
            for candidate in xff.split(',').rev().map(str::trim) {
                if candidate.parse::<IpAddr>().is_ok() && !self.is_trusted_proxy(candidate) {
                    return candidate.to_string();
                }
            }
            if let Some(first) = xff.split(',').next().map(str::trim) {
                if first.parse::<IpAddr>().is_ok() {
                    return first.to_string();
                }
            }
        }
        peer_ip.to_string()
    }
}

fn combined_log_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Matches standard Nginx/Apache Combined Log Format, with optional trailing forwarded IP.
        Regex::new(
            r#"^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s"]+)(?:\s+[^"]*)?"\s+(\d{3})\s+(\d+|-)\s+"[^"]*"\s+"([^"]*)"(?:\s+"([^"]*)")?"#,
        )
        .expect("combined log regex must compile")
    })
}

/// Shared parser for Combined / VHost-Combined access log lines used by Nginx and Apache.
pub fn parse_combined_access_log(
    server: &str,
    raw_line: &str,
    resolver: &RealIpResolver,
) -> Option<UnifiedLogEntry> {
    let caps = combined_log_regex().captures(raw_line)?;
    let peer_ip = caps.get(1)?.as_str();
    let ts_str = caps.get(2)?.as_str();
    let method = caps.get(3)?.as_str().to_string();
    let path = caps.get(4)?.as_str().to_string();
    let status: u16 = caps.get(5)?.as_str().parse().ok()?;
    let bytes_sent: u64 = caps
        .get(6)
        .and_then(|m| m.as_str().parse().ok())
        .unwrap_or(0);
    let user_agent = caps.get(7).map(|m| m.as_str().to_string()).unwrap_or_default();
    let xff_tail = caps.get(8).map(|m| m.as_str());

    let client_ip = resolver.resolve(peer_ip, None, xff_tail);
    let timestamp = DateTime::parse_from_str(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    let is_auth_failure = status == 401 || status == 403;

    Some(UnifiedLogEntry {
        timestamp,
        server: server.to_string(),
        client_ip,
        method,
        path,
        status,
        user_agent,
        bytes_sent,
        raw_line: raw_line.to_string(),
        is_auth_failure,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_real_ip_resolver_with_trusted_proxy() {
        let resolver = RealIpResolver::new(&["127.0.0.1".into(), "173.245.48.0/20".into()]);
        assert_eq!(
            resolver.resolve("127.0.0.1", None, Some("203.0.113.50, 173.245.48.10")),
            "203.0.113.50"
        );
        assert_eq!(
            resolver.resolve("173.245.48.5", Some("198.51.100.42"), None),
            "198.51.100.42"
        );
        // Untrusted peer cannot spoof XFF
        assert_eq!(
            resolver.resolve("192.0.2.99", Some("1.1.1.1"), Some("8.8.8.8")),
            "192.0.2.99"
        );
    }
}
