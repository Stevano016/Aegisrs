use super::{parse_combined_access_log, RealIpResolver, WebServerProvider};
use crate::models::UnifiedLogEntry;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct ApacheProvider {
    resolver: RealIpResolver,
}

impl ApacheProvider {
    pub fn new(resolver: RealIpResolver) -> Self {
        Self { resolver }
    }

    fn service_name() -> &'static str {
        if Path::new("/etc/apache2/apache2.conf").exists() {
            "apache2"
        } else {
            "httpd"
        }
    }
}

impl WebServerProvider for ApacheProvider {
    fn name(&self) -> &'static str {
        "apache"
    }

    fn detect_installed(&self) -> bool {
        Path::new("/etc/apache2/apache2.conf").exists()
            || Path::new("/etc/httpd/conf/httpd.conf").exists()
            || Command::new("apachectl")
                .arg("-v")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
    }

    fn default_log_paths(&self) -> Vec<PathBuf> {
        if Path::new("/var/log/httpd").exists() {
            vec![
                PathBuf::from("/var/log/httpd/access_log"),
                PathBuf::from("/var/log/httpd/error_log"),
            ]
        } else {
            vec![
                PathBuf::from("/var/log/apache2/access.log"),
                PathBuf::from("/var/log/apache2/error.log"),
            ]
        }
    }

    fn parse_log_line(&self, raw_line: &str) -> Option<UnifiedLogEntry> {
        parse_combined_access_log("apache", raw_line, &self.resolver)
    }

    fn test_config(&self) -> Result<String, String> {
        let out = Command::new("apachectl")
            .arg("configtest")
            .output()
            .map_err(|e| format!("Failed to execute apachectl configtest: {e}"))?;
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
            .args(["reload", Self::service_name()])
            .output()
            .map_err(|e| format!("Failed to reload apache: {e}"))?;
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
    fn test_parse_apache_combined_line() {
        let provider = ApacheProvider::new(RealIpResolver::new(&[]));
        let line = r#"198.51.100.77 - - [23/Nov/2026:11:00:00 +0700] "POST /wp-login.php HTTP/1.1" 401 512 "-" "Mozilla/5.0""#;
        let entry = provider.parse_log_line(line).expect("should parse apache line");
        assert_eq!(entry.server, "apache");
        assert_eq!(entry.client_ip, "198.51.100.77");
        assert_eq!(entry.method, "POST");
        assert_eq!(entry.path, "/wp-login.php");
        assert_eq!(entry.status, 401);
        assert!(entry.is_auth_failure);
    }
}
