use crate::config::IdsConfig;
use crate::models::{EventCategory, SecurityEvent, Severity, UnifiedLogEntry};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// Sliding-window rate limiter for RPS anomalies, per-IP brute force,
/// and distributed IP-rotation brute force (VPN/Tor/botnet).
pub struct RateLimiter {
    window: Duration,
    max_rps_per_ip: u32,
    auth_fail_threshold: u32,
    distributed_auth_threshold: u32,
    requests_by_ip: HashMap<String, VecDeque<Instant>>,
    auth_fails_by_ip: HashMap<String, VecDeque<Instant>>,
    distributed_auth_fails: VecDeque<(Instant, String)>,
    cooldowns: HashMap<String, Instant>,
}

impl RateLimiter {
    pub fn new(cfg: &IdsConfig) -> Self {
        Self {
            window: Duration::from_secs(cfg.window_secs.max(1)),
            max_rps_per_ip: cfg.max_rps_per_ip,
            auth_fail_threshold: cfg.auth_fail_threshold,
            distributed_auth_threshold: cfg.distributed_auth_threshold.max(2),
            requests_by_ip: HashMap::new(),
            auth_fails_by_ip: HashMap::new(),
            distributed_auth_fails: VecDeque::new(),
            cooldowns: HashMap::new(),
        }
    }

    fn prune_old(queue: &mut VecDeque<Instant>, cutoff: Instant) {
        while let Some(&front) = queue.front() {
            if front < cutoff {
                queue.pop_front();
            } else {
                break;
            }
        }
    }

    fn in_cooldown(&mut self, key: &str, now: Instant) -> bool {
        if let Some(&until) = self.cooldowns.get(key) {
            if now < until {
                return true;
            }
        }
        self.cooldowns
            .insert(key.to_string(), now + Duration::from_secs(30));
        false
    }

    /// Records a log entry and returns any rate-limit or brute-force events triggered.
    pub fn record(&mut self, entry: &UnifiedLogEntry) -> Vec<SecurityEvent> {
        let now = Instant::now();
        let cutoff = now - self.window;
        let mut events = Vec::new();

        // 1. RPS / Layer-7 flood check
        let reqs = self
            .requests_by_ip
            .entry(entry.client_ip.clone())
            .or_default();
        Self::prune_old(reqs, cutoff);
        reqs.push_back(now);

        let window_secs = self.window.as_secs_f64().max(1.0);
        let current_rps = (reqs.len() as f64) / window_secs;
        if current_rps > self.max_rps_per_ip as f64 {
            let cd_key = format!("rps:{}", entry.client_ip);
            if !self.in_cooldown(&cd_key, now) {
                events.push(
                    SecurityEvent::new(
                        Severity::High,
                        EventCategory::RateLimit,
                        "Layer-7 RPS Anomaly / Flood Detected",
                        format!(
                            "IP {} exceeded max RPS ({:.1} req/s > {} req/s)",
                            entry.client_ip, current_rps, self.max_rps_per_ip
                        ),
                    )
                    .with_source_ip(entry.client_ip.clone())
                    .with_rule_id("AEGIS-RATE-RPS"),
                );
            }
        }

        // 2. Auth failure / Brute-force check (per-IP & distributed VPN/Proxy rotation)
        if entry.is_auth_failure {
            let fails = self
                .auth_fails_by_ip
                .entry(entry.client_ip.clone())
                .or_default();
            Self::prune_old(fails, cutoff);
            fails.push_back(now);

            let fail_count = fails.len();
            if fail_count as u32 >= self.auth_fail_threshold {
                let cd_key = format!("bf:{}", entry.client_ip);
                if !self.in_cooldown(&cd_key, now) {
                    events.push(
                        SecurityEvent::new(
                            Severity::High,
                            EventCategory::BruteForce,
                            format!("Brute Force Detected ({})", entry.server),
                            format!(
                                "IP {} triggered {} auth failures within {}s on {}",
                                entry.client_ip,
                                fail_count,
                                self.window.as_secs(),
                                entry.server
                            ),
                        )
                        .with_source_ip(entry.client_ip.clone())
                        .with_rule_id("AEGIS-BRUTE-FORCE")
                        .with_raw_snippet(entry.raw_line.clone()),
                    );
                }
            }

            // Distributed brute-force across distinct IPs (e.g. rotating VPN / Tor)
            while let Some((ts, _)) = self.distributed_auth_fails.front() {
                if *ts < cutoff {
                    self.distributed_auth_fails.pop_front();
                } else {
                    break;
                }
            }
            self.distributed_auth_fails
                .push_back((now, entry.client_ip.clone()));

            let distinct_count = self
                .distributed_auth_fails
                .iter()
                .map(|(_, ip)| ip.as_str())
                .collect::<HashSet<&str>>()
                .len();

            if distinct_count as u32 >= self.distributed_auth_threshold {
                let cd_key = format!("dist_bf:{}", entry.server);
                if !self.in_cooldown(&cd_key, now) {
                    events.push(
                        SecurityEvent::new(
                            Severity::High,
                            EventCategory::BruteForce,
                            format!("Distributed Brute Force / IP Rotation ({})", entry.server),
                            format!(
                                "{} distinct IPs failed authentication within {}s on {}",
                                distinct_count,
                                self.window.as_secs(),
                                entry.server
                            ),
                        )
                        .with_source_ip(entry.client_ip.clone())
                        .with_rule_id("AEGIS-DIST-BRUTEFORCE"),
                    );
                }
            }
        }

        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_brute_force_detection() {
        let mut cfg = IdsConfig::default();
        cfg.auth_fail_threshold = 3;
        cfg.window_secs = 10;
        let mut limiter = RateLimiter::new(&cfg);

        let entry = UnifiedLogEntry {
            timestamp: Utc::now(),
            server: "sshd".into(),
            client_ip: "198.51.100.20".into(),
            method: "SSH".into(),
            path: "/ssh/auth".into(),
            status: 401,
            user_agent: "sshd".into(),
            bytes_sent: 0,
            raw_line: "Failed password".into(),
            is_auth_failure: true,
        };

        assert!(limiter.record(&entry).is_empty());
        assert!(limiter.record(&entry).is_empty());
        let evts = limiter.record(&entry);
        assert_eq!(evts.len(), 1);
        assert_eq!(evts[0].category, EventCategory::BruteForce);
    }

    #[test]
    fn test_distributed_ip_rotation_brute_force() {
        let mut cfg = IdsConfig::default();
        cfg.auth_fail_threshold = 10;
        cfg.distributed_auth_threshold = 5;
        cfg.window_secs = 30;
        let mut limiter = RateLimiter::new(&cfg);

        for i in 1..=4 {
            let entry = UnifiedLogEntry {
                timestamp: Utc::now(),
                server: "sshd".into(),
                client_ip: format!("203.0.113.{i}"),
                method: "SSH".into(),
                path: "/ssh/auth".into(),
                status: 401,
                user_agent: "sshd".into(),
                bytes_sent: 0,
                raw_line: "Failed password".into(),
                is_auth_failure: true,
            };
            assert!(limiter.record(&entry).is_empty());
        }

        let fifth = UnifiedLogEntry {
            timestamp: Utc::now(),
            server: "sshd".into(),
            client_ip: "203.0.113.5".into(),
            method: "SSH".into(),
            path: "/ssh/auth".into(),
            status: 401,
            user_agent: "sshd".into(),
            bytes_sent: 0,
            raw_line: "Failed password".into(),
            is_auth_failure: true,
        };
        let evts = limiter.record(&fifth);
        assert_eq!(evts.len(), 1);
        assert_eq!(evts[0].rule_id.as_deref(), Some("AEGIS-DIST-BRUTEFORCE"));
    }
}
