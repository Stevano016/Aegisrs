use crate::models::{BannedIp, EventCategory, SecurityEvent, Severity};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::collections::VecDeque;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Bounded in-memory ring buffer for live UI feeds.
#[derive(Debug, Clone)]
pub struct RingBuffer<T> {
    cap: usize,
    buf: VecDeque<T>,
}

impl<T> RingBuffer<T> {
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            buf: VecDeque::with_capacity(cap.max(1)),
        }
    }

    pub fn push(&mut self, item: T) {
        if self.buf.len() >= self.cap {
            self.buf.pop_front();
        }
        self.buf.push_back(item);
    }

    pub fn recent(&self, limit: usize) -> Vec<T>
    where
        T: Clone,
    {
        self.buf.iter().rev().take(limit).cloned().collect()
    }
}

/// Embedded SQLite storage (WAL mode) for security alerts and banned IPs.
#[derive(Clone)]
pub struct SqliteStorage {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStorage {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create DB dir: {}", parent.display()))?;
            }
        }
        let conn = Connection::open(path)
            .with_context(|| format!("Failed to open SQLite DB: {}", path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }

        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS events (
                 id TEXT PRIMARY KEY,
                 timestamp TEXT NOT NULL,
                 severity TEXT NOT NULL,
                 category TEXT NOT NULL,
                 title TEXT NOT NULL,
                 description TEXT NOT NULL,
                 source_ip TEXT,
                 file_path TEXT,
                 rule_id TEXT,
                 raw_snippet TEXT,
                 action_taken TEXT
             );
             CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp DESC);
             CREATE TABLE IF NOT EXISTS banned_ips (
                 ip TEXT PRIMARY KEY,
                 reason TEXT NOT NULL,
                 banned_at TEXT NOT NULL,
                 expires_at TEXT,
                 permanent INTEGER NOT NULL,
                 backend TEXT NOT NULL
             );",
        )?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "CREATE TABLE events (
                 id TEXT PRIMARY KEY,
                 timestamp TEXT NOT NULL,
                 severity TEXT NOT NULL,
                 category TEXT NOT NULL,
                 title TEXT NOT NULL,
                 description TEXT NOT NULL,
                 source_ip TEXT,
                 file_path TEXT,
                 rule_id TEXT,
                 raw_snippet TEXT,
                 action_taken TEXT
             );
             CREATE TABLE banned_ips (
                 ip TEXT PRIMARY KEY,
                 reason TEXT NOT NULL,
                 banned_at TEXT NOT NULL,
                 expires_at TEXT,
                 permanent INTEGER NOT NULL,
                 backend TEXT NOT NULL
             );",
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn insert_event(&self, evt: &SecurityEvent) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let sev_json = serde_json::to_string(&evt.severity)?;
        let cat_json = serde_json::to_string(&evt.category)?;
        conn.execute(
            "INSERT OR REPLACE INTO events
             (id, timestamp, severity, category, title, description, source_ip, file_path, rule_id, raw_snippet, action_taken)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                evt.id,
                evt.timestamp.to_rfc3339(),
                sev_json.trim_matches('"'),
                cat_json.trim_matches('"'),
                evt.title,
                evt.description,
                evt.source_ip,
                evt.file_path,
                evt.rule_id,
                evt.raw_snippet,
                evt.action_taken,
            ],
        )?;
        Ok(())
    }

    pub fn recent_events(&self, limit: usize) -> Result<Vec<SecurityEvent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, severity, category, title, description, source_ip, file_path, rule_id, raw_snippet, action_taken
             FROM events ORDER BY timestamp DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let ts_str: String = row.get(1)?;
            let sev_str: String = row.get(2)?;
            let cat_str: String = row.get(3)?;
            let timestamp = DateTime::parse_from_rfc3339(&ts_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let severity: Severity =
                serde_json::from_str(&format!("\"{sev_str}\"")).unwrap_or(Severity::Low);
            let category: EventCategory =
                serde_json::from_str(&format!("\"{cat_str}\"")).unwrap_or(EventCategory::System);

            Ok(SecurityEvent {
                id: row.get(0)?,
                timestamp,
                severity,
                category,
                title: row.get(4)?,
                description: row.get(5)?,
                source_ip: row.get(6)?,
                file_path: row.get(7)?,
                rule_id: row.get(8)?,
                raw_snippet: row.get(9)?,
                action_taken: row.get(10)?,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn total_events(&self) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        Ok(count.max(0) as u64)
    }

    pub fn upsert_ban(&self, ban: &BannedIp) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO banned_ips (ip, reason, banned_at, expires_at, permanent, backend)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                ban.ip,
                ban.reason,
                ban.banned_at.to_rfc3339(),
                ban.expires_at.map(|t| t.to_rfc3339()),
                if ban.permanent { 1i64 } else { 0i64 },
                ban.backend,
            ],
        )?;
        Ok(())
    }

    pub fn remove_ban(&self, ip: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let deleted = conn.execute("DELETE FROM banned_ips WHERE ip = ?1", params![ip])?;
        Ok(deleted > 0)
    }

    pub fn list_bans(&self) -> Result<Vec<BannedIp>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ip, reason, banned_at, expires_at, permanent, backend FROM banned_ips ORDER BY banned_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            let banned_str: String = row.get(2)?;
            let expires_str: Option<String> = row.get(3)?;
            let perm_int: i64 = row.get(4)?;
            Ok(BannedIp {
                ip: row.get(0)?,
                reason: row.get(1)?,
                banned_at: DateTime::parse_from_rfc3339(&banned_str)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                expires_at: expires_str.and_then(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .map(|d| d.with_timezone(&Utc))
                        .ok()
                }),
                permanent: perm_int != 0,
                backend: row.get(5)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqlite_roundtrip_events_and_bans() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let evt = SecurityEvent::new(
            Severity::Critical,
            EventCategory::WebShell,
            "Shell detected",
            "eval() found",
        )
        .with_source_ip("1.2.3.4");
        db.insert_event(&evt).unwrap();
        let recent = db.recent_events(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].title, "Shell detected");

        let ban = BannedIp {
            ip: "1.2.3.4".into(),
            reason: "webshell".into(),
            banned_at: Utc::now(),
            expires_at: None,
            permanent: true,
            backend: "ufw".into(),
        };
        db.upsert_ban(&ban).unwrap();
        assert_eq!(db.list_bans().unwrap().len(), 1);
        assert!(db.remove_ban("1.2.3.4").unwrap());
        assert!(db.list_bans().unwrap().is_empty());
    }
}
