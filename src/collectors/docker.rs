use crate::config::DockerConfig;
use crate::models::{CollectorMessage, DockerContainerMetric, EventCategory, SecurityEvent, Severity};
use bollard::container::{InspectContainerOptions, ListContainersOptions};
use bollard::Docker;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, warn};

/// Polls local Docker daemon for container health, restart loops, and resource anomalies.
pub fn spawn_docker_monitor(
    cfg: DockerConfig,
    latest_metrics: Arc<RwLock<Vec<DockerContainerMetric>>>,
    tx: mpsc::Sender<CollectorMessage>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    if !cfg.enabled {
        return;
    }

    tokio::spawn(async move {
        let docker = match Docker::connect_with_local_defaults() {
            Ok(d) => d,
            Err(e) => {
                debug!("Docker daemon not available: {e}");
                return;
            }
        };

        let mut interval = tokio::time::interval(Duration::from_secs(cfg.poll_interval_secs.max(5)));
        let mut alerted_restarts: HashMap<String, i64> = HashMap::new();

        loop {
            tokio::select! {
                _ = shutdown.recv() => break,
                _ = interval.tick() => {
                    let opts = Some(ListContainersOptions::<String> {
                        all: true,
                        ..Default::default()
                    });
                    let containers = match docker.list_containers(opts).await {
                        Ok(c) => c,
                        Err(e) => {
                            debug!("Docker list_containers failed (daemon stopped?): {e}");
                            continue;
                        }
                    };

                    let mut snapshot = Vec::with_capacity(containers.len());
                    for c in containers {
                        let id = c.id.unwrap_or_default();
                        let short_id = id.chars().take(12).collect::<String>();
                        let name = c
                            .names
                            .and_then(|n| n.into_iter().next())
                            .unwrap_or_else(|| short_id.clone())
                            .trim_start_matches('/')
                            .to_string();
                        let status = c.state.unwrap_or_else(|| "unknown".to_string());

                        let mut restart_count = 0i64;
                        if let Ok(info) = docker.inspect_container(&id, None::<InspectContainerOptions>).await {
                            restart_count = info.restart_count.unwrap_or(0);
                        }

                        let mut anomaly = None;
                        if restart_count >= cfg.restart_loop_threshold {
                            let prev = alerted_restarts.get(&id).copied().unwrap_or(0);
                            anomaly = Some(format!("Restart loop ({restart_count} restarts)"));
                            if restart_count > prev {
                                alerted_restarts.insert(id.clone(), restart_count);
                                warn!("Docker restart loop detected on {name}: {restart_count}");
                                let evt = SecurityEvent::new(
                                    Severity::High,
                                    EventCategory::DockerAnomaly,
                                    format!("Docker Container Restart Loop: {name}"),
                                    format!("Container '{name}' ({short_id}) has restarted {restart_count} times"),
                                )
                                .with_rule_id("AEGIS-DOCKER-RESTART");
                                let _ = tx.send(CollectorMessage::DirectEvent(evt)).await;
                            }
                        }

                        snapshot.push(DockerContainerMetric {
                            id: short_id,
                            name,
                            status,
                            cpu_percent: 0.0,
                            memory_mb: 0.0,
                            restart_count,
                            anomaly,
                        });
                    }

                    *latest_metrics.write().await = snapshot;
                }
            }
        }
    });
}
