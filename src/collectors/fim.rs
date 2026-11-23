use crate::config::FimConfig;
use crate::models::{CollectorMessage, EventCategory, SecurityEvent, Severity};
use aho_corasick::AhoCorasick;
use chrono::{DateTime, Utc};
use globset::{Glob, GlobSet, GlobSetBuilder};
use notify::event::CreateKind;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};
use walkdir::WalkDir;

const MAX_SCAN_BYTES: u64 = 512 * 1024;

const DEFAULT_IGNORED_DIR_NAMES: &[&str] = &[
    "vendor",
    "node_modules",
    ".git",
    "cache",
    "tmp",
    ".next",
    "dist",
];

struct WebShellSignatures {
    matcher: AhoCorasick,
    patterns: Vec<&'static str>,
}

fn webshell_signatures() -> &'static WebShellSignatures {
    static SIGS: OnceLock<WebShellSignatures> = OnceLock::new();
    SIGS.get_or_init(|| {
        let patterns = vec![
            "eval(",
            "base64_decode(",
            "shell_exec(",
            "passthru(",
            "proc_open(",
            "popen(",
            "system($_",
            "exec($_",
            "assert($_",
            "gzinflate(",
            "str_rot13(",
            "move_uploaded_file(",
            "wso_version",
            "FilesMan",
            "c99shell",
            "r57shell",
        ];
        let matcher = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
            .expect("webshell AhoCorasick must compile");
        WebShellSignatures { matcher, patterns }
    })
}

/// Scans file content for known PHP/web-shell dangerous function patterns.
pub fn scan_content_for_webshell(content: &str) -> Option<&'static str> {
    let sigs = webshell_signatures();
    sigs.matcher
        .find(content)
        .map(|m| sigs.patterns[m.pattern().as_usize()])
}

/// Loads `.aegisignore` glob patterns if the file exists.
pub fn load_ignore_set(path: &Path) -> GlobSet {
    let mut builder = GlobSetBuilder::new();
    if let Ok(raw) = fs::read_to_string(path) {
        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Ok(glob) = Glob::new(trimmed) {
                builder.add(glob);
            }
        }
    }
    builder.build().unwrap_or_else(|_| GlobSet::empty())
}

/// Returns true if `path` matches built-in noisy/heavy directories or `.aegisignore`.
pub fn is_ignored_path(path: &Path, ignore_set: &GlobSet) -> bool {
    if ignore_set.is_match(path) {
        return true;
    }

    let mut prev_storage = false;
    for comp in path.components() {
        if let Component::Normal(os_str) = comp {
            let name = os_str.to_string_lossy();
            if DEFAULT_IGNORED_DIR_NAMES
                .iter()
                .any(|ignored| name.eq_ignore_ascii_case(ignored))
            {
                return true;
            }
            if prev_storage && name.eq_ignore_ascii_case("framework") {
                return true;
            }
            prev_storage = name.eq_ignore_ascii_case("storage");
        } else {
            prev_storage = false;
        }
    }
    false
}

/// Traverses `root` and returns all non-ignored directories to be watched individually
/// with `RecursiveMode::NonRecursive`, preventing `fs.inotify.max_user_watches` exhaustion.
pub fn collect_watchable_dirs(root: &Path, ignore_set: &GlobSet) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let walker = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !is_ignored_path(entry.path(), ignore_set));

    for entry in walker.flatten() {
        if entry.file_type().is_dir() {
            dirs.push(entry.into_path());
        }
    }
    dirs
}

fn is_scannable_extension(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "php" | "phtml" | "php5" | "php7" | "phar" | "jsp" | "asp" | "aspx" | "sh" | "py" | "html" | "htm"
    )
}

/// Spawns real-time FIM and Persistence Watcher tasks.
pub fn spawn_fim_watcher(
    cfg: FimConfig,
    paused_until: Arc<RwLock<Option<DateTime<Utc>>>>,
    tx: mpsc::Sender<CollectorMessage>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    if !cfg.enabled {
        info!("FIM watcher is disabled in config");
        return;
    }

    let ignore_set = Arc::new(load_ignore_set(&cfg.ignore_file));
    let (fs_tx, mut fs_rx) = mpsc::channel::<(PathBuf, bool)>(256);

    let watch_paths = cfg.watch_paths.clone();
    let persistence_paths = cfg.persistence_paths.clone();
    let ignore_for_fs = ignore_set.clone();

    std::thread::spawn(move || {
        let watcher_slot: Arc<Mutex<Option<RecommendedWatcher>>> = Arc::new(Mutex::new(None));
        let watcher_for_cb = watcher_slot.clone();
        let ignore_for_cb = ignore_for_fs.clone();
        let persistence_for_cb = persistence_paths.clone();

        let watcher: RecommendedWatcher = match notify::recommended_watcher(
            move |res: notify::Result<Event>| {
                if let Ok(event) = res {
                    let is_relevant = matches!(
                        event.kind,
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                    );
                    if !is_relevant {
                        return;
                    }
                    let is_folder_create = matches!(
                        event.kind,
                        EventKind::Create(CreateKind::Folder) | EventKind::Create(CreateKind::Any)
                    );

                    for path in event.paths {
                        let is_persistence = persistence_for_cb
                            .iter()
                            .any(|p| path == *p || path.starts_with(p));

                        if !is_persistence && is_ignored_path(&path, &ignore_for_cb) {
                            continue;
                        }

                        // Dynamic watch registration for newly created non-ignored directories
                        if !is_persistence && is_folder_create && path.is_dir() {
                            if let Ok(mut guard) = watcher_for_cb.lock() {
                                if let Some(ref mut w) = *guard {
                                    for dir in collect_watchable_dirs(&path, &ignore_for_cb) {
                                        let _ = w.watch(&dir, RecursiveMode::NonRecursive);
                                    }
                                }
                            }
                            continue;
                        }

                        let _ = fs_tx.blocking_send((path, is_persistence));
                    }
                }
            },
        ) {
            Ok(w) => w,
            Err(e) => {
                warn!("Failed to initialize FIM watcher: {e}");
                return;
            }
        };

        {
            let mut guard = watcher_slot.lock().unwrap();
            *guard = Some(watcher);
        }

        if let Ok(mut guard) = watcher_slot.lock() {
            if let Some(ref mut w) = *guard {
                for p in &watch_paths {
                    if p.exists() {
                        let dirs = collect_watchable_dirs(p, &ignore_for_fs);
                        let mut count = 0usize;
                        for dir in dirs {
                            if let Err(e) = w.watch(&dir, RecursiveMode::NonRecursive) {
                                warn!("FIM failed to watch {}: {e}", dir.display());
                            } else {
                                count += 1;
                            }
                        }
                        info!("FIM watching {} ({count} non-ignored directories)", p.display());
                    } else {
                        debug!("FIM watch path does not exist yet: {}", p.display());
                    }
                }

                for p in &persistence_paths {
                    let target = if p.exists() {
                        Some(p.as_path())
                    } else {
                        p.parent().filter(|parent| parent.exists())
                    };
                    if let Some(t) = target {
                        if let Err(e) = w.watch(t, RecursiveMode::NonRecursive) {
                            warn!("Persistence watcher failed for {}: {e}", t.display());
                        } else {
                            info!("Persistence watcher active on: {}", t.display());
                        }
                    }
                }
            }
        }

        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    });

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.recv() => {
                    debug!("Stopping FIM event processor");
                    break;
                }
                Some((path, is_persistence)) = fs_rx.recv() => {
                    if is_persistence {
                        let evt = SecurityEvent::new(
                            Severity::Critical,
                            EventCategory::Persistence,
                            "Persistence Target Modified",
                            format!("Critical system persistence file changed: {}", path.display()),
                        )
                        .with_file_path(path.display().to_string())
                        .with_rule_id("AEGIS-PERSIST-001");
                        let _ = tx.send(CollectorMessage::DirectEvent(evt)).await;
                        continue;
                    }

                    // Respect Maintenance Window (`aegis pause`)
                    if let Some(until) = *paused_until.read().await {
                        if Utc::now() < until {
                            debug!("FIM paused (maintenance window), skipping {}", path.display());
                            continue;
                        }
                    }

                    if is_ignored_path(&path, &ignore_set) {
                        continue;
                    }

                    if !path.is_file() {
                        continue;
                    }

                    if is_scannable_extension(&path) {
                        if let Ok(meta) = fs::metadata(&path) {
                            if meta.len() <= MAX_SCAN_BYTES {
                                if let Ok(content) = fs::read_to_string(&path) {
                                    if let Some(matched_sig) = scan_content_for_webshell(&content) {
                                        let evt = SecurityEvent::new(
                                            Severity::Critical,
                                            EventCategory::WebShell,
                                            "Potential Web Shell / Malicious Script Detected",
                                            format!(
                                                "Suspicious pattern '{matched_sig}' found in {}",
                                                path.display()
                                            ),
                                        )
                                        .with_file_path(path.display().to_string())
                                        .with_rule_id("AEGIS-FIM-WEBSHELL")
                                        .with_raw_snippet(matched_sig);
                                        let _ = tx.send(CollectorMessage::DirectEvent(evt)).await;
                                        continue;
                                    }
                                }
                            }
                        }
                    }

                    let evt = SecurityEvent::new(
                        Severity::Medium,
                        EventCategory::FileIntegrity,
                        "Web File Modified / Created",
                        format!("File integrity change detected: {}", path.display()),
                    )
                    .with_file_path(path.display().to_string())
                    .with_rule_id("AEGIS-FIM-CHANGE");
                    let _ = tx.send(CollectorMessage::DirectEvent(evt)).await;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_webshell_signature_detection() {
        let malicious = "<?php @eval(base64_decode($_POST['cmd'])); ?>";
        assert!(scan_content_for_webshell(malicious).is_some());

        let benign = "<?php echo htmlspecialchars($username, ENT_QUOTES); ?>";
        assert!(scan_content_for_webshell(benign).is_none());
    }

    #[test]
    fn test_fim_ignores_node_modules_and_vendor() {
        let dir = tempdir().unwrap();
        let app_dir = dir.path().join("app");
        let nm_dir = dir.path().join("node_modules").join("lodash");
        let vendor_dir = dir.path().join("vendor").join("laravel");
        let fw_cache = dir.path().join("storage").join("framework").join("views");

        fs::create_dir_all(&app_dir).unwrap();
        fs::create_dir_all(&nm_dir).unwrap();
        fs::create_dir_all(&vendor_dir).unwrap();
        fs::create_dir_all(&fw_cache).unwrap();

        let ignore_set = GlobSet::empty();
        let dirs = collect_watchable_dirs(dir.path(), &ignore_set);

        assert!(dirs.contains(&dir.path().to_path_buf()));
        assert!(dirs.contains(&app_dir));
        assert!(!dirs.iter().any(|d| d.ends_with("node_modules") || d.ends_with("lodash")));
        assert!(!dirs.iter().any(|d| d.ends_with("vendor") || d.ends_with("laravel")));
        assert!(!dirs.iter().any(|d| d.ends_with("framework") || d.ends_with("views")));
    }
}
