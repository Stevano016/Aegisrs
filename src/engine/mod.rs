pub mod rate_limit;
pub mod rules;

use crate::config::Config;
use crate::models::{SecurityEvent, UnifiedLogEntry};
use rate_limit::RateLimiter;
use rules::RuleEngine;

/// Coordinates rule-based signature matching and behavioral rate limiting.
pub struct DetectionEngine {
    rules: RuleEngine,
    rate_limiter: RateLimiter,
}

impl DetectionEngine {
    pub fn new(cfg: &Config) -> Self {
        Self {
            rules: RuleEngine::new(cfg.general.custom_rules_path.as_deref()),
            rate_limiter: RateLimiter::new(&cfg.ids),
        }
    }

    pub fn analyze_log(&mut self, entry: &UnifiedLogEntry) -> Vec<SecurityEvent> {
        let mut events = self.rules.evaluate(entry);
        events.extend(self.rate_limiter.record(entry));
        events
    }
}
