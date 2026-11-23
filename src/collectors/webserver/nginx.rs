use super::{parse_combined_access_log, RealIpResolver, WebServerProvider};
use crate::models::UnifiedLogEntry;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct NginxProvider {
    resolver: RealIpResolver,
}

impl NginxProvider {
    pub fn new(resolver: RealIpResolver) -> Self {
        Self { resolver }
    }
}

impl WebServerProvider for NginxProvider {
    fn name(&self) -> &'static str {
        "nginx"
    }

    fn detect_installed(&self) -> bool {
        Path::new("/usr/sbin/nginx").exists()
            || Path::new("/etc/nginx/nginx.conf").exists()
            || Command::new("nginx")
                .arg("-v")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
    }

    fn default_log_paths(&self) -> Vec<PathBuf> {
        vec![
            PathBuf::from("/var/log/nginx/access.log"),
            PathBuf::from("/var/log/nginx/error.log"),
        ]
    }

    fn parse_log_line(&self, raw_line: &str) -> Option<UnifiedLogEntry> {
        parse_combined_access_log("nginx", raw_line, &self.resolver)
    }

    fn test_config(&self) -> Result<String, String> {
        let out = Command::new("nginx")
            .arg("-t")
            .output()
            .map_err(|e| format!("Failed to execute nginx -t: {e}"))?;
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if out.status.success() {
            Ok(combined.trim().to_string())
        } else {
            Err(combined.trim().to_string())
        }
    }

    fn reload_service(&self) -> Result<(), String> {
        self.test_config()?;
        let out = Command::new("systemctl")
            .args(["reload", "nginx"])
            .output()
            .map_err(|e| format!("Failed to reload nginx: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nginx_combined_line() {
        let provider = NginxProvider::new(RealIpResolver::new(&["127.0.0.1".into()]));
        let line = r#"203.0.113.10 - - [23/Nov/2026:10:15:30 +0700] "GET /index.php?id=1 UNION SELECT 1,2-- HTTP/1.1" 200 1024 "-" "sqlmap/1.7""#;
        let entry = provider.parse_log_line(line).expect("should parse nginx line");
        assert_eq!(entry.server, "nginx");
        assert_eq!(entry.client_ip, "203.0.113.10");
        assert_eq!(entry.method, "GET");
        assert_eq!(entry.path, "/index.php?id=1");
        assert_eq!(entry.status, 200);
        assert_eq!(entry.user_agent, "sqlmap/1.7");
    }
}
