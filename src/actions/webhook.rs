use crate::config::AlertsConfig;
use crate::models::SecurityEvent;
use reqwest::Client;
use serde_json::json;
use std::time::Duration;
use tracing::warn;

/// Dispatches real-time security alerts to Telegram, Discord, Slack, and custom webhooks.
#[derive(Clone)]
pub struct WebhookNotifier {
    client: Client,
    hostname: String,
    cfg: AlertsConfig,
}

impl WebhookNotifier {
    pub fn new(hostname: impl Into<String>, cfg: AlertsConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self {
            client,
            hostname: hostname.into(),
            cfg,
        }
    }

    pub async fn notify(&self, event: &SecurityEvent) {
        if self.cfg.telegram.enabled
            && event.severity >= self.cfg.telegram.min_severity
            && !self.cfg.telegram.bot_token.is_empty()
            && !self.cfg.telegram.chat_id.is_empty()
        {
            self.send_telegram(event).await;
        }

        if self.cfg.discord.enabled
            && event.severity >= self.cfg.discord.min_severity
            && !self.cfg.discord.url.is_empty()
        {
            self.send_discord(event).await;
        }

        if self.cfg.slack.enabled
            && event.severity >= self.cfg.slack.min_severity
            && !self.cfg.slack.url.is_empty()
        {
            self.send_slack(event).await;
        }

        if self.cfg.custom_webhook.enabled
            && event.severity >= self.cfg.custom_webhook.min_severity
            && !self.cfg.custom_webhook.url.is_empty()
        {
            self.send_custom(event).await;
        }
    }

    async fn send_telegram(&self, event: &SecurityEvent) {
        let url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            self.cfg.telegram.bot_token
        );
        let text = format!(
            "[AegisRS | {}] [{}] {}\n{}\nIP: {}\nFile: {}\nRule: {}",
            self.hostname,
            event.severity,
            event.title,
            event.description,
            event.source_ip.as_deref().unwrap_or("-"),
            event.file_path.as_deref().unwrap_or("-"),
            event.rule_id.as_deref().unwrap_or("-"),
        );
        let payload = json!({
            "chat_id": self.cfg.telegram.chat_id,
            "text": text,
            "disable_web_page_preview": true
        });
        if let Err(e) = self.client.post(&url).json(&payload).send().await {
            warn!("Telegram webhook failed: {e}");
        }
    }

    async fn send_discord(&self, event: &SecurityEvent) {
        let color = match event.severity {
            crate::models::Severity::Critical => 0xE11D48,
            crate::models::Severity::High => 0xF97316,
            crate::models::Severity::Medium => 0xEAB308,
            crate::models::Severity::Low => 0x38BDF8,
        };
        let payload = json!({
            "embeds": [{
                "title": format!("[{}] {}", event.severity, event.title),
                "description": event.description,
                "color": color,
                "fields": [
                    { "name": "Host", "value": &self.hostname, "inline": true },
                    { "name": "Category", "value": event.category.to_string(), "inline": true },
                    { "name": "Source IP", "value": event.source_ip.as_deref().unwrap_or("-"), "inline": true },
                    { "name": "File", "value": event.file_path.as_deref().unwrap_or("-"), "inline": false }
                ],
                "timestamp": event.timestamp.to_rfc3339()
            }]
        });
        if let Err(e) = self.client.post(&self.cfg.discord.url).json(&payload).send().await {
            warn!("Discord webhook failed: {e}");
        }
    }

    async fn send_slack(&self, event: &SecurityEvent) {
        let payload = json!({
            "text": format!(
                "*[AegisRS | {}]* `[{}]` *{}*\n>{}\nIP: `{}` | File: `{}`",
                self.hostname,
                event.severity,
                event.title,
                event.description,
                event.source_ip.as_deref().unwrap_or("-"),
                event.file_path.as_deref().unwrap_or("-")
            )
        });
        if let Err(e) = self.client.post(&self.cfg.slack.url).json(&payload).send().await {
            warn!("Slack webhook failed: {e}");
        }
    }

    async fn send_custom(&self, event: &SecurityEvent) {
        let mut req = self.client.post(&self.cfg.custom_webhook.url).json(&json!({
            "hostname": self.hostname,
            "event": event,
        }));
        if let Some(ref tok) = self.cfg.custom_webhook.bearer_token {
            if !tok.is_empty() {
                req = req.bearer_auth(tok);
            }
        }
        if let Err(e) = req.send().await {
            warn!("Custom webhook failed: {e}");
        }
    }
}
