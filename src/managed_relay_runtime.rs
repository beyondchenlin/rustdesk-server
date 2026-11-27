//! Transaction coordinator for managed relay pools. It owns the selection
//! snapshot consumed by the rendezvous routing adapter. Network commands must
//! be authenticated before calling this API.

use crate::{
    managed_relay_probe::{probe, RelayPublicKey, RelayTarget},
    managed_relay_store::{
        normalize_nodes, validate_actor, PoolSnapshot, PoolVersion, ProbeRecord, RelayPoolStore,
    },
};
use hbb_common::{
    anyhow::{anyhow, Context},
    bail,
    futures::{stream, StreamExt},
    tokio::sync::Mutex,
    ResultType,
};
use serde_derive::Serialize;
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        RwLock,
    },
    time::{Duration, Instant},
};

const MAX_PROBE_CONCURRENCY: usize = 4;
const HEALTH_MAX_AGE: Duration = Duration::from_secs(150);

#[derive(Clone, Debug, Serialize)]
pub struct RuntimeReadback {
    pub version: PoolVersion,
    pub eligible: Vec<String>,
    pub checks: Vec<ProbeRecord>,
    pub checked_at: Option<String>,
    pub state: &'static str,
}

struct RuntimeState {
    version: PoolVersion,
    checks: Vec<ProbeRecord>,
    checked_at: Option<String>,
    last_check: Option<Instant>,
    enabled: bool,
}

impl RuntimeState {
    fn eligible(&self) -> Vec<String> {
        self.checks
            .iter()
            .filter(|report| report.healthy)
            .map(|report| report.endpoint.clone())
            .collect()
    }

    fn fresh(&self) -> bool {
        self.last_check
            .is_some_and(|time| time.elapsed() <= HEALTH_MAX_AGE)
    }

    fn readback(&self) -> RuntimeReadback {
        let eligible = if self.enabled && self.fresh() {
            self.eligible()
        } else {
            Vec::new()
        };
        let state = if !self.enabled {
            "recovery_required"
        } else if !self.fresh() {
            "health_unknown"
        } else if eligible.is_empty() {
            "unavailable"
        } else if eligible.len() < self.version.nodes.len() {
            "degraded"
        } else {
            "healthy"
        };
        RuntimeReadback {
            version: self.version.clone(),
            eligible,
            checks: self.checks.clone(),
            checked_at: self.checked_at.clone(),
            state,
        }
    }
}

async fn check_nodes(nodes: &[String], key: &RelayPublicKey) -> ResultType<Vec<ProbeRecord>> {
    let targets = normalize_nodes(nodes, false)?
        .iter()
        .map(|address| RelayTarget::parse(address))
        .collect::<ResultType<Vec<_>>>()?;
    let mut checks = stream::iter(targets)
        .map(|target| async move {
            let started = Instant::now();
            let result = probe(&target, key).await;
            let healthy = result.is_ok();
            let resolved_endpoints = result
                .as_ref()
                .ok()
                .map(|addresses| addresses.iter().map(ToString::to_string).collect())
                .unwrap_or_default();
            let reason = result.err().map(|err| {
                let mut text = format!("{err:#}");
                while text.len() > 1024 {
                    text.pop();
                }
                text
            });
            ProbeRecord {
                endpoint: target.as_str().to_owned(),
                healthy,
                checked_at: chrono::Utc::now().to_rfc3339(),
                elapsed_ms: started.elapsed().as_millis() as u64,
                resolved_endpoints,
                reason,
            }
        })
        .buffer_unordered(MAX_PROBE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    checks.sort_by(|a, b| a.endpoint.cmp(&b.endpoint));
    Ok(checks)
}

pub struct ManagedRelayRuntime {
    store: RelayPoolStore,
    _owner_lock: std::fs::File,
    key: RelayPublicKey,
    state: RwLock<RuntimeState>,
    operation: Mutex<()>,
    rotation: AtomicUsize,
}

impl ManagedRelayRuntime {
    pub async fn open(store: RelayPoolStore, key: RelayPublicKey) -> ResultType<Self> {
        let owner_lock = store
            .lock_runtime_owner()
            .context("Another relay runtime owns this configuration journal")?;
        let snapshot = store.snapshot().await?;
        let runtime = Self {
            store,
            _owner_lock: owner_lock,
            key,
            state: RwLock::new(RuntimeState {
                version: snapshot.current,
                checks: Vec::new(),
                checked_at: None,
                last_check: None,
                enabled: false,
            }),
            operation: Mutex::new(()),
            rotation: AtomicUsize::new(0),
        };
        // A pending attempt never becomes active merely because the process
        // restarts. Restore the committed configuration and re-probe it.
        runtime.reconcile("startup").await?;
        Ok(runtime)
    }

    fn install(
        &self,
        version: PoolVersion,
        checks: Vec<ProbeRecord>,
        enabled: bool,
    ) -> ResultType<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| anyhow!("Relay selection lock poisoned"))?;
        *state = RuntimeState {
            version,
            checks,
            checked_at: Some(chrono::Utc::now().to_rfc3339()),
            last_check: Some(Instant::now()),
            enabled,
        };
        Ok(())
    }

    fn disable(&self) -> ResultType<()> {
        self.state
            .write()
            .map_err(|_| anyhow!("Relay selection lock poisoned"))?
            .enabled = false;
        Ok(())
    }

    fn enable(&self, expected: i64) -> ResultType<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| anyhow!("Relay selection lock poisoned"))?;
        if state.version.revision != expected {
            bail!("Runtime version changed before enabling routing");
        }
        state.enabled = true;
        drop(state);
        self.report_health_transition("recovery_required")
    }

    pub fn readback(&self) -> ResultType<RuntimeReadback> {
        Ok(self
            .state
            .read()
            .map_err(|_| anyhow!("Relay selection lock poisoned"))?
            .readback())
    }

    /// The rendezvous adapter selects only from this exact snapshot.
    /// Existing established relay connections are not touched.
    pub fn select(&self) -> Option<String> {
        let state = self.state.read().ok()?;
        if !state.enabled || !state.fresh() {
            return None;
        }
        let count = state.checks.iter().filter(|check| check.healthy).count();
        if count == 0 {
            return None;
        }
        let index = self.rotation.fetch_add(1, Ordering::Relaxed) % count;
        state
            .checks
            .iter()
            .filter(|check| check.healthy)
            .nth(index)
            .map(|check| check.endpoint.clone())
    }

    pub fn permits(&self, endpoint: &str) -> bool {
        let Ok(target) = RelayTarget::parse(endpoint) else {
            return false;
        };
        let Ok(state) = self.state.read() else {
            return false;
        };
        state.enabled
            && state.fresh()
            && state.checks.iter().any(|check| {
                check.healthy && check.endpoint == target.as_str()
            })
    }

    pub async fn status(&self) -> ResultType<(PoolSnapshot, RuntimeReadback)> {
        let _guard = self.operation.lock().await;
        let journal = self.snapshot_or_disable().await?;
        let runtime = self.readback()?;
        if journal.pending.is_some() || journal.current != runtime.version {
            self.disable()?;
            return Ok((journal, self.readback()?));
        }
        Ok((journal, runtime))
    }

    pub async fn publish(
        &self,
        expected: i64,
        nodes: &[String],
        actor: &str,
    ) -> ResultType<PoolSnapshot> {
        let _guard = self.operation.lock().await;
        self.apply(expected, Some(nodes), actor).await
    }

    pub async fn rollback(&self, expected: i64, actor: &str) -> ResultType<PoolSnapshot> {
        let _guard = self.operation.lock().await;
        self.apply(expected, None, actor).await
    }

    async fn apply(
        &self,
        expected: i64,
        nodes: Option<&[String]>,
        actor: &str,
    ) -> ResultType<PoolSnapshot> {
        validate_actor(actor)?;
        let journal = self.snapshot_or_disable().await?;
        if journal.current.revision != expected {
            bail!("Stale relay configuration revision");
        }
        if journal.pending.is_some() {
            self.disable()?;
            bail!("Pending relay publication requires recovery");
        }
        let baseline = self.readback()?;
        if baseline.version != journal.current {
            self.disable()?;
            bail!("Durable configuration and runtime differ; recovery required");
        }
        let (candidate, action) = match nodes {
            Some(nodes) => (normalize_nodes(nodes, false)?, "publish"),
            None => (
                journal
                    .previous
                    .as_ref()
                    .context("No previous relay version")?
                    .nodes
                    .clone(),
                "rollback",
            ),
        };

        let checks = check_nodes(&candidate, &self.key).await?;
        self.store
            .record_probes(expected, action, actor, &checks)
            .await?;
        let verified: Vec<_> = checks
            .iter()
            .filter(|c| c.healthy)
            .map(|c| c.endpoint.clone())
            .collect();
        if verified.is_empty() {
            bail!("No candidate relay passed the protocol probe; previous configuration retained");
        }
        let prepared = match nodes {
            Some(_) => {
                self.store
                    .prepare_publish(
                        expected,
                        &candidate,
                        &verified,
                        &baseline.version.nodes,
                        actor,
                    )
                    .await
            }
            None => {
                self.store
                    .prepare_rollback(expected, &verified, &baseline.version.nodes, actor)
                    .await
            }
        };
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(err) => {
                // Even a failed database operation may have an uncertain result.
                self.disable()?;
                return Err(
                    err.context("Publication journal could not be prepared; recovery required")
                );
            }
        };
        let pending = prepared.pending.context("Missing prepared publication")?;
        let revision = pending.candidate.revision;

        // Keep routing disabled until the candidate is durably confirmed.
        // A cancellation anywhere after prepare leaves a journal to reconcile.
        self.install(pending.candidate, checks, false)?;
        let confirmation = self.confirm_installed(revision, actor).await;
        match confirmation {
            Ok(committed) => {
                self.enable(revision)?;
                Ok(committed)
            }
            Err(error) => {
                self.disable()?;
                // Re-read the durable journal before restoring: a failed commit
                // acknowledgement must never cause rollback of a committed change.
                match self.reconcile(actor).await {
                    Ok(()) => Err(error.context(
                        "Publication not confirmed; durable state reconciled, inspect status",
                    )),
                    Err(recovery) => Err(anyhow!(
                        "Publication not confirmed: {error:#}; recovery required: {recovery:#}"
                    )),
                }
            }
        }
    }

    async fn confirm_installed(&self, revision: i64, actor: &str) -> ResultType<PoolSnapshot> {
        let (version, eligible) = {
            let state = self
                .state
                .read()
                .map_err(|_| anyhow!("Relay selection lock poisoned"))?;
            if state.version.revision != revision || !state.fresh() {
                bail!("Candidate runtime readback is stale or mismatched");
            }
            (state.version.clone(), state.eligible())
        };
        self.store
            .confirm(revision, &version.nodes, &eligible, actor)
            .await
    }

    /// Refresh health using a real protocol probe. A zero-healthy result
    /// removes all eligible nodes without erasing the committed configuration.
    pub async fn refresh(&self) -> ResultType<()> {
        let _guard = self.operation.lock().await;
        let journal = self.snapshot_or_disable().await?;
        if journal.pending.is_some() || self.readback()?.version != journal.current {
            return self.reconcile("health-recovery").await;
        }
        let checks = check_nodes(&journal.current.nodes, &self.key).await?;
        // Detect another writer before making a fresh selection visible.
        if self.snapshot_or_disable().await? != journal {
            self.disable()?;
            bail!("Relay journal changed during health check");
        }
        let previous = self.readback()?.state;
        self.install(journal.current, checks, true)?;
        self.report_health_transition(previous)
    }

    fn report_health_transition(&self, previous: &str) -> ResultType<()> {
        let current = self.readback()?;
        if current.state != previous {
            match current.state {
                "unavailable" => hbb_common::log::error!(
                    "Managed relay unavailable: no healthy nodes; new relay requests refused; revision {}",
                    current.version.revision
                ),
                "degraded" => hbb_common::log::warn!(
                    "Managed relay degraded: {} of {} nodes healthy; revision {}",
                    current.eligible.len(), current.version.nodes.len(), current.version.revision
                ),
                "healthy" => hbb_common::log::info!(
                    "Managed relay healthy: {} nodes; revision {}",
                    current.eligible.len(), current.version.revision
                ),
                _ => {}
            }
        }
        Ok(())
    }

    pub async fn recover(&self, actor: &str) -> ResultType<()> {
        let _guard = self.operation.lock().await;
        self.reconcile(actor).await
    }

    async fn snapshot_or_disable(&self) -> ResultType<PoolSnapshot> {
        match self.store.snapshot().await {
            Ok(snapshot) => Ok(snapshot),
            Err(error) => {
                self.disable()?;
                Err(error.context("Relay journal unreadable; routing disabled"))
            }
        }
    }

    async fn reconcile(&self, actor: &str) -> ResultType<()> {
        validate_actor(actor)?;
        self.disable()?;
        let journal = self.store.snapshot().await?;
        let checks = check_nodes(&journal.current.nodes, &self.key).await?;
        self.store
            .record_probes(journal.current.revision, "recover", actor, &checks)
            .await?;
        if self.store.snapshot().await? != journal {
            bail!("Relay journal changed during recovery");
        }
        self.install(journal.current.clone(), checks, false)?;
        if let Some(pending) = journal.pending {
            let restored = self.readback()?;
            if restored.version != journal.current {
                bail!("Committed runtime version was not restored");
            }
            self.store
                .abort_after_restore(pending.candidate.revision, &restored.version.nodes, actor)
                .await?;
        }
        self.enable(journal.current.revision)
    }
}
