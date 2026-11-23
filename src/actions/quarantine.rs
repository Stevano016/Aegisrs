use anyhow::{Context, Result};
use chrono::Utc;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Serialize)]
struct QuarantineMetadata {
    original_path: String,
    quarantined_at: String,
    reason: String,
}

/// Moves a suspicious file to an isolated quarantine directory and strips permissions (`chmod 000`).
pub fn quarantine_file(src: &Path, quarantine_dir: &Path, reason: &str) -> Result<PathBuf> {
    fs::create_dir_all(quarantine_dir)
        .with_context(|| format!("Failed to create quarantine dir: {}", quarantine_dir.display()))?;

    let fname = src
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown_file");
    let ts = Utc::now().format("%Y%m%dT%H%M%SZ");
    let dest = quarantine_dir.join(format!("{ts}_{fname}.quarantine"));

    if fs::rename(src, &dest).is_err() {
        fs::copy(src, &dest)
            .with_context(|| format!("Failed to copy {} to quarantine", src.display()))?;
        fs::remove_file(src)
            .with_context(|| format!("Failed to remove original {}", src.display()))?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o000);
        let _ = fs::set_permissions(&dest, perms);
    }

    let meta = QuarantineMetadata {
        original_path: src.display().to_string(),
        quarantined_at: Utc::now().to_rfc3339(),
        reason: reason.to_string(),
    };
    let meta_path = quarantine_dir.join(format!("{ts}_{fname}.meta.json"));
    if let Ok(json) = serde_json::to_string_pretty(&meta) {
        let _ = fs::write(meta_path, json);
    }

    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_quarantine_moves_file() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("shell.php");
        let qdir = dir.path().join("quarantine");
        fs::write(&src, "<?php eval($_POST['x']); ?>").unwrap();

        let dest = quarantine_file(&src, &qdir, "webshell").unwrap();
        assert!(!src.exists());
        assert!(dest.exists());
    }
}
