use crate::models::BannedIp;
use anyhow::{bail, Result};
use chrono::{Duration, Utc};
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::process::Command;
use tracing::{info, warn};

/// Executes firewall bans/unbans while enforcing strict anti-self-lockout safeguards.
#[derive(Debug, Clone)]
pub struct FirewallManager {
    backend: String,
    protected_nets: Vec<IpNetwork>,
}

impl FirewallManager {
    pub fn new(backend: impl Into<String>, whitelist_ips: &[String], trusted_proxies: &[String]) -> Self {
        let mut protected_nets = Vec::new();
        for raw in whitelist_ips.iter().chain(trusted_proxies.iter()) {
            if let Ok(net) = raw.trim().parse::<IpNetwork>() {
                protected_nets.push(net);
            } else if let Ok(ip) = raw.trim().parse::<IpAddr>() {
                let net = match ip {
                    IpAddr::V4(v4) => IpNetwork::V4(ipnetwork::Ipv4Network::new(v4, 32).unwrap()),
                    IpAddr::V6(v6) => IpNetwork::V6(ipnetwork::Ipv6Network::new(v6, 128).unwrap()),
                };
                protected_nets.push(net);
            }
        }
        Self {
            backend: backend.into().to_lowercase(),
            protected_nets,
        }
    }

    /// Returns true if the IP is hardcoded-protected or whitelisted (never ban).
    pub fn is_protected(&self, ip: IpAddr) -> bool {
        if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
            return true;
        }
        match ip {
            IpAddr::V4(v4) if v4.is_link_local() => return true,
            _ => {}
        }
        self.protected_nets.iter().any(|net| net.contains(ip))
    }

    pub fn ban_ip(&self, ip_str: &str, reason: &str, duration_secs: Option<u64>) -> Result<BannedIp> {
        let ip: IpAddr = ip_str
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid IP address: '{ip_str}'"))?;

        if self.is_protected(ip) {
            bail!("Refusing to ban protected/whitelisted IP: {ip}");
        }

        let ip_clean = ip.to_string();
        match self.backend.as_str() {
            "ufw" => {
                let out = Command::new("ufw")
                    .args(["insert", "1", "deny", "from", &ip_clean, "to", "any"])
                    .output();
                match out {
                    Ok(o) if o.status.success() => info!("UFW banned {ip_clean}"),
                    Ok(o) => warn!("UFW ban stderr: {}", String::from_utf8_lossy(&o.stderr)),
                    Err(e) => warn!("UFW execution failed (dry/non-linux?): {e}"),
                }
            }
            "iptables" => {
                let cmd = match ip {
                    IpAddr::V4(_) => "iptables",
                    IpAddr::V6(_) => "ip6tables",
                };
                let out = Command::new(cmd)
                    .args(["-I", "INPUT", "1", "-s", &ip_clean, "-j", "DROP"])
                    .output();
                if let Err(e) = out {
                    warn!("{cmd} execution failed: {e}");
                }
            }
            "nftables" => {
                let out = Command::new("nft")
                    .args(["add", "element", "inet", "filter", "aegis_blacklist", "{", &ip_clean, "}"])
                    .output();
                if let Err(e) = out {
                    warn!("nftables execution failed: {e}");
                }
            }
            "none" | "" => {
                info!("Firewall backend is 'none'; recording virtual ban for {ip_clean}");
            }
            other => {
                bail!("Unsupported firewall backend: {other}");
            }
        }

        let now = Utc::now();
        let expires_at = duration_secs.map(|s| now + Duration::seconds(s as i64));
        Ok(BannedIp {
            ip: ip_clean,
            reason: reason.to_string(),
            banned_at: now,
            expires_at,
            permanent: duration_secs.is_none(),
            backend: self.backend.clone(),
        })
    }

    pub fn unban_ip(&self, ip_str: &str) -> Result<()> {
        let ip: IpAddr = ip_str
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid IP address: '{ip_str}'"))?;
        let ip_clean = ip.to_string();

        match self.backend.as_str() {
            "ufw" => {
                let _ = Command::new("ufw")
                    .args(["delete", "deny", "from", &ip_clean, "to", "any"])
                    .output();
            }
            "iptables" => {
                let cmd = match ip {
                    IpAddr::V4(_) => "iptables",
                    IpAddr::V6(_) => "ip6tables",
                };
                let _ = Command::new(cmd)
                    .args(["-D", "INPUT", "-s", &ip_clean, "-j", "DROP"])
                    .output();
            }
            "nftables" => {
                let _ = Command::new("nft")
                    .args(["delete", "element", "inet", "filter", "aegis_blacklist", "{", &ip_clean, "}"])
                    .output();
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_self_lockout_protection() {
        let fw = FirewallManager::new("none", &["10.0.0.5".into()], &["173.245.48.0/20".into()]);
        assert!(fw.ban_ip("127.0.0.1", "test", None).is_err());
        assert!(fw.ban_ip("::1", "test", None).is_err());
        assert!(fw.ban_ip("10.0.0.5", "test", None).is_err());
        assert!(fw.ban_ip("173.245.48.10", "test", None).is_err());
        assert!(fw.ban_ip("203.0.113.99", "malicious", Some(3600)).is_ok());
    }
}
