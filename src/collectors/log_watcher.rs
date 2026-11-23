use crate::collectors::webserver::WebServerProvider;
use crate::models::{CollectorMessage, EventCategory, SecurityEvent, Severity, UnifiedLogEntry};
use chrono::Utc;
use regex::Regex;
use std::fs::{self, File, Metadata};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Tracks file offset, size, and Unix inode to distinguish `logrotate` from malicious log wiping.
#[derive(Debug, Clone)]
pub struct LogFileState {
    pub offset: u64,
    pub last_size: u64,
    pub inode: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TamperCheckResult {
    Normal,
    Rotated,
    Tampered { reason: String },
}

fn file_inode(meta: &Metadata) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(meta.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        None
    }
}

const ROTATE_RECENCY_SECS: u64 = 10;

fn is_recent_archive(archive_path: &Path) -> bool {
    let Ok(meta) = fs::metadata(archive_path) else {
        return false;
    };
    let Ok(mtime) = meta.modified() else {
        return false;
    };
    SystemTime::now()
        .duration_since(mtime)
        .map(|elapsed| elapsed <= Duration::from_secs(ROTATE_RECENCY_SECS))
        .unwrap_or(false)
}

fn has_recent_rotated_sibling(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let parent = path.parent().unwrap_or_else(|| Path::new("."));

    // Check common suffix conventions (.1, .1.gz, .0)
    for suffix in [".1", ".1.gz", ".0"] {
        if is_recent_archive(&parent.join(format!("{name}{suffix}"))) {
            return true;
        }
    }

    // Check dateext conventions (<log_path>-YYYYMMDD or .gz)
    let date_prefix = format!("{name}-");
    if let Ok(entries) = fs::read_dir(parent) {
        for entry in entries.flatten() {
            if let Some(fname) = entry.file_name().to_str() {
                if fname.starts_with(&date_prefix) && is_recent_archive(&entry.path()) {
                    return true;
                }
            }
        }
    }

    false
}

/// Evaluates whether a log file underwent normal rotation (`create` or `copytruncate`)
/// or suspicious tampering/truncation.
pub fn evaluate_log_state(
    path: &Path,
    prev: &LogFileState,
    current_meta: Option<&Metadata>,
) -> TamperCheckResult {
    let Some(meta) = current_meta else {
        if has_recent_rotated_sibling(path) {
            return TamperCheckResult::Rotated;
        }
        return TamperCheckResult::Tampered {
            reason: format!("Log file deleted without rotation: {}", path.display()),
        };
    };

    let current_size = meta.len();
    let current_inode = file_inode(meta);

    // Inode changed: check if logrotate created a recent archive
    if let (Some(old_ino), Some(new_ino)) = (prev.inode, current_inode) {
        if old_ino != new_ino {
            if has_recent_rotated_sibling(path) {
                return TamperCheckResult::Rotated;
            }
            return TamperCheckResult::Tampered {
                reason: format!(
                    "Log file inode replaced without logrotate archive ({old_ino} -> {new_ino}): {}",
                    path.display()
                ),
            };
        }
    }

    // Same inode (or non-Unix), but file shrank -> check for logrotate copytruncate vs malicious truncate
    if current_size < prev.offset {
        if has_recent_rotated_sibling(path) {
            return TamperCheckResult::Rotated;
        }
        return TamperCheckResult::Tampered {
            reason: format!(
                "Log file truncated unexpectedly ({} -> {} bytes): {}",
                prev.offset,
                current_size,
                path.display()
            ),
        };
    }

    TamperCheckResult::Normal
}

fn ssh_fail_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?:Failed password|Invalid user|authentication failure).*?(?:from|rhost=)\s*([0-9a-fA-F:\.]+)",
        )
        .expect("ssh fail regex must compile")
    })
}

/// Parses an `/var/log/auth.log` line for SSH brute-force attempts.
pub fn parse_auth_log_line(raw_line: &str) -> Option<UnifiedLogEntry> {
    let caps = ssh_fail_regex().captures(raw_line)?;
    let ip = caps.get(1)?.as_str().to_string();
    Some(UnifiedLogEntry {
        timestamp: Utc::now(),
        server: "sshd".to_string(),
        client_ip: ip,
        method: "SSH".to_string(),
        path: "/ssh/auth".to_string(),
        status: 401,
        user_agent: "sshd".to_string(),
        bytes_sent: 0,
        raw_line: raw_line.to_string(),
        is_auth_failure: true,
    })
}

/// Spawns an async tailer task for a single log file (web server access log or auth.log).
pub fn spawn_log_tailer(
    path: PathBuf,
    provider: Option<Arc<dyn WebServerProvider>>,
    is_auth_log: bool,
    tx: mpsc::Sender<CollectorMessage>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    tokio::spawn(async move {
        let mut state: Option<LogFileState> = None;

        // Initialize at end-of-file if it already exists so we don't replay old history on startup.
        if let Ok(meta) = fs::metadata(&path) {
            state = Some(LogFileState {
                offset: meta.len(),
                last_size: meta.len(),
                inode: file_inode(&meta),
            });
            debug!("Tailing log {} from offset {}", path.display(), meta.len());
        }

        let mut interval = tokio::time::interval(Duration::from_millis(200));

        loop {
            tokio::select! {
                _ = shutdown.recv() => {
                    debug!("Stopping log tailer for {}", path.display());
                    break;
                }
                _ = interval.tick() => {
                    let meta = fs::metadata(&path).ok();
                    match (&state, &meta) {
                        (None, Some(m)) => {
                            state = Some(LogFileState {
                                offset: 0,
                                last_size: m.len(),
                                inode: file_inode(m),
                            });
                        }
                        (Some(prev), curr) => {
                            match evaluate_log_state(&path, prev, curr.as_ref()) {
                                TamperCheckResult::Normal => {}
                                TamperCheckResult::Rotated => {
                                    info!("Normal log rotation (logrotate/copytruncate) detected for {}", path.display());
                                    if let Some(m) = curr {
                                        state = Some(LogFileState {
                                            offset: 0,
                                            last_size: m.len(),
                                            inode: file_inode(m),
                                        });
                                    } else {
                                        state = None;
                                    }
                                    continue;
                                }
                                TamperCheckResult::Tampered { reason } => {
                                    warn!("CRITICAL LOG TAMPERING: {}", reason);
                                    let evt = SecurityEvent::new(
                                        Severity::Critical,
                                        EventCategory::LogTampering,
                                        "Log Tampering / Anti-Forensics Detected",
                                        reason,
                                    )
                                    .with_file_path(path.display().to_string())
                                    .with_rule_id("AEGIS-LOG-TAMPER");
                                    let _ = tx.send(CollectorMessage::DirectEvent(evt)).await;

                                    if let Some(m) = curr {
                                        state = Some(LogFileState {
                                            offset: m.len(),
                                            last_size: m.len(),
                                            inode: file_inode(m),
                                        });
                                    } else {
                                        state = None;
                                    }
                                    continue;
                                }
                            }
                        }
                        (None, None) => continue,
                    }

                    // Read newly appended lines
                    if let Some(ref mut st) = state {
                        let current_len = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                        if current_len > st.offset {
                            if let Ok(mut file) = File::open(&path) {
                                if file.seek(SeekFrom::Start(st.offset)).is_ok() {
                                    let mut reader = BufReader::new(file);
                                    let mut line = String::new();
                                    while let Ok(bytes) = reader.read_line(&mut line) {
                                        if bytes == 0 {
                                            break;
                                        }
                                        st.offset += bytes as u64;
                                        let trimmed = line.trim_end_matches(['\r', '\n']);
                                        if !trimmed.is_empty() {
                                            let parsed = if is_auth_log {
                                                parse_auth_log_line(trimmed)
                                            } else if let Some(ref p) = provider {
                                                p.parse_log_line(trimmed)
                                            } else {
                                                None
                                            };
                                            if let Some(entry) = parsed {
                                                let _ = tx.send(CollectorMessage::LogEntry(entry)).await;
                                            }
                                        }
                                        line.clear();
                                    }
                                    st.last_size = st.offset;
                                }
                            }
                        }
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_detect_log_truncation_tampering() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("access.log");
        {
            let mut f = File::create(&log_path).unwrap();
            writeln!(f, "127.0.0.1 - - [23/Nov/2026:10:00:00 +0000] \"GET / HTTP/1.1\" 200 100 \"-\" \"curl\"").unwrap();
        }
        let meta1 = fs::metadata(&log_path).unwrap();
        let prev = LogFileState {
            offset: meta1.len(),
            last_size: meta1.len(),
            inode: file_inode(&meta1),
        };

        // Truncate file to 0 bytes without rotation
        File::create(&log_path).unwrap();
        let meta2 = fs::metadata(&log_path).unwrap();
        let res = evaluate_log_state(&log_path, &prev, Some(&meta2));
        assert!(matches!(res, TamperCheckResult::Tampered { .. }));
    }

    #[test]
    fn test_allow_normal_logrotate() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("access.log");
        let rotated_path = dir.path().join("access.log.1");
        File::create(&rotated_path).unwrap();
        File::create(&log_path).unwrap();
        let meta = fs::metadata(&log_path).unwrap();
        let prev = LogFileState {
            offset: 5000,
            last_size: 5000,
            inode: file_inode(&meta),
        };
        let res = evaluate_log_state(&log_path, &prev, Some(&meta));
        assert_eq!(res, TamperCheckResult::Rotated);
    }

    #[test]
    fn test_copytruncate_with_new_writes_and_dateext_archive() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("access.log");
        let rotated_path = dir.path().join("access.log-20261123");
        File::create(&rotated_path).unwrap();
        {
            let mut f = File::create(&log_path).unwrap();
            writeln!(f, "127.0.0.1 - - [23/Nov/2026:10:00:00 +0000] \"GET / HTTP/1.1\" 200 10 \"-\" \"curl\"").unwrap();
        }
        let meta = fs::metadata(&log_path).unwrap();
        let prev = LogFileState {
            offset: 50000,
            last_size: 50000,
            inode: file_inode(&meta),
        };
        let res = evaluate_log_state(&log_path, &prev, Some(&meta));
        assert_eq!(res, TamperCheckResult::Rotated);
    }

    #[test]
    fn test_parse_auth_log_ssh_failure() {
        let line = "Nov 23 18:01:02 vps sshd[1234]: Failed password for invalid user admin from 203.0.113.88 port 54321 ssh2";
        let entry = parse_auth_log_line(line).expect("should parse ssh fail");
        assert_eq!(entry.client_ip, "203.0.113.88");
        assert!(entry.is_auth_failure);
    }
}
