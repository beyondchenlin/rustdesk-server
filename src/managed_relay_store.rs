//! Durable relay publication journal. The native runtime adapter must supply real
//! probe results and readback; a prepared candidate is not a successful publication.

use crate::managed_relay_probe::RelayTarget;
use hbb_common::{bail, ResultType};
use serde_derive::{Deserialize, Serialize};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    SqlitePool,
};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    time::Duration,
};

const APPLICATION_ID: i64 = 0x424b5250; // BKRP
const SCHEMA_VERSION: i64 = 1;
const MAX_NODES: usize = 16;
const MAX_STATE_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PoolVersion {
    pub revision: i64,
    pub nodes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Publish,
    Rollback,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PendingPublication {
    pub operation: Operation,
    pub base_revision: i64,
    pub candidate: PoolVersion,
    pub verified_nodes: Vec<String>,
    /// Configured runtime nodes, not the transient healthy subset.
    pub baseline_runtime: Vec<String>,
    pub actor: String,
    pub prepared_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PoolSnapshot {
    pub generation: i64,
    pub next_revision: i64,
    pub current: PoolVersion,
    pub previous: Option<PoolVersion>,
    pub pending: Option<PendingPublication>,
}

pub(crate) fn normalize_nodes(nodes: &[String], allow_empty: bool) -> ResultType<Vec<String>> {
    if nodes.len() > MAX_NODES || (!allow_empty && nodes.is_empty()) {
        bail!("Relay pool must contain 1 to {MAX_NODES} nodes");
    }
    let mut canonical = BTreeSet::new();
    for node in nodes {
        let node = RelayTarget::parse(node)?;
        if !canonical.insert(node.as_str().to_owned()) {
            bail!("Duplicate relay endpoint");
        }
    }
    Ok(canonical.into_iter().collect())
}

fn subset(nodes: &[String], configured: &[String]) -> bool {
    nodes.iter().all(|node| configured.contains(node))
}

pub(crate) fn validate_actor(actor: &str) -> ResultType<()> {
    if actor.trim().is_empty() || actor.len() > 128 || actor.chars().any(char::is_control) {
        bail!("Invalid publication actor");
    }
    Ok(())
}

impl PoolSnapshot {
    fn validate(&self) -> ResultType<()> {
        if self.generation < 1
            || self.current.revision < 1
            || self.next_revision <= self.current.revision
            || normalize_nodes(&self.current.nodes, false)? != self.current.nodes
        {
            bail!("Invalid persisted relay pool state");
        }
        if let Some(previous) = &self.previous {
            if previous.revision < 1
                || previous.revision >= self.current.revision
                || normalize_nodes(&previous.nodes, false)? != previous.nodes
            {
                bail!("Invalid previous relay version");
            }
        }
        if let Some(pending) = &self.pending {
            validate_actor(&pending.actor)?;
            if pending.base_revision != self.current.revision
                || pending.candidate.revision <= self.current.revision
                || pending.candidate.revision >= self.next_revision
                || normalize_nodes(&pending.candidate.nodes, false)? != pending.candidate.nodes
                || normalize_nodes(&pending.verified_nodes, false)? != pending.verified_nodes
                || normalize_nodes(&pending.baseline_runtime, false)? != pending.baseline_runtime
                || !subset(&pending.verified_nodes, &pending.candidate.nodes)
                || pending.baseline_runtime != self.current.nodes
                || chrono::DateTime::parse_from_rfc3339(&pending.prepared_at).is_err()
            {
                bail!("Invalid pending relay publication");
            }
            if pending.operation == Operation::Rollback
                && self.previous.as_ref().map(|p| &p.nodes) != Some(&pending.candidate.nodes)
            {
                bail!("Rollback target differs from previous version");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeRecord {
    pub endpoint: String,
    pub healthy: bool,
    pub checked_at: String,
    pub elapsed_ms: u64,
    pub resolved_endpoints: Vec<String>,
    pub reason: Option<String>,
}

#[derive(Clone)]
pub struct RelayPoolStore {
    db: SqlitePool,
    path: PathBuf,
}

impl RelayPoolStore {
    async fn connect(path: &Path, initialize: bool) -> ResultType<Self> {
        let path = std::fs::canonicalize(path)?;
        let mut options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(false)
            .busy_timeout(Duration::from_secs(5))
            .synchronous(SqliteSynchronous::Full);
        if initialize {
            options = options.journal_mode(SqliteJournalMode::Wal);
        }
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(6))
            .connect_with(options)
            .await?;
        Ok(Self { db, path })
    }

    /// Initialize a separate, new configuration database. This records a
    /// configured pool, not a claim about the runtime or node health.
    pub async fn initialize(path: &Path, nodes: &[String], actor: &str) -> ResultType<Self> {
        validate_actor(actor)?;
        let current = PoolVersion {
            revision: 1,
            nodes: normalize_nodes(nodes, false)?,
        };
        let state = PoolSnapshot {
            generation: 1,
            next_revision: 2,
            current,
            previous: None,
            pending: None,
        };
        state.validate()?;

        // Never overwrite the existing server DB or any other pre-existing file.
        let mut file = OpenOptions::new();
        file.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            file.mode(0o600);
        }
        drop(file.open(path)?);

        let store = Self::connect(path, true).await?;
        let mut tx = store.db.begin().await?;
        sqlx::query("PRAGMA application_id = 1112232528")
            .execute(&mut *tx)
            .await?;
        sqlx::query("PRAGMA user_version = 1")
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "CREATE TABLE relay_pool_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                generation INTEGER NOT NULL,
                state_json TEXT NOT NULL
            )",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "CREATE TABLE relay_pool_audit (
                generation INTEGER PRIMARY KEY,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                state_json TEXT NOT NULL
            )",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "CREATE TABLE relay_pool_probe_audit (
                event_id TEXT PRIMARY KEY,
                base_revision INTEGER NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                checks_json TEXT NOT NULL
            )",
        )
        .execute(&mut *tx)
        .await?;
        let json = serde_json::to_string(&state)?;
        sqlx::query("INSERT INTO relay_pool_state VALUES (1, 1, ?)")
            .bind(&json)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO relay_pool_audit VALUES (1, 'initialize', ?, ?, ?)")
            .bind(actor)
            .bind(chrono::Utc::now().to_rfc3339())
            .bind(&json)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(store)
    }

    pub async fn open(path: &Path) -> ResultType<Self> {
        if !std::fs::metadata(path)?.is_file() {
            bail!("Expected a relay configuration database file");
        }
        let store = Self::connect(path, false).await?;
        let id: i64 = sqlx::query_scalar("PRAGMA application_id")
            .fetch_one(&store.db)
            .await?;
        if id != APPLICATION_ID {
            bail!("Not a BK Remote relay configuration database");
        }
        let schema: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&store.db)
            .await?;
        if schema != SCHEMA_VERSION {
            bail!("Unsupported relay configuration schema version");
        }
        store.snapshot().await?;
        Ok(store)
    }

    /// Only one active runtime may own this canonical journal path. The lock
    /// file is deliberately retained; deleting a live lock file would allow a
    /// second process to lock a different inode.
    pub(crate) fn lock_runtime_owner(&self) -> ResultType<File> {
        let mut lock_name = self.path.as_os_str().to_os_string();
        lock_name.push(".runtime.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(0);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(lock_name)?;
        if !file.metadata()?.is_file() {
            bail!("Relay runtime lock is not a regular file");
        }
        #[cfg(unix)]
        {
            use hbb_common::libc;
            use std::os::fd::AsRawFd;
            // SAFETY: the descriptor is owned by this live File. The lock is
            // released by the OS when the File (or process) closes.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        #[cfg(not(any(unix, windows)))]
        bail!("Managed relay runtime locking is unsupported on this platform");
        Ok(file)
    }

    pub async fn snapshot(&self) -> ResultType<PoolSnapshot> {
        let (generation, json): (i64, String) = sqlx::query_as(
            "SELECT generation, state_json FROM relay_pool_state
             WHERE singleton = 1 AND length(state_json) <= ?",
        )
        .bind(MAX_STATE_BYTES as i64)
        .fetch_one(&self.db)
        .await?;
        let state: PoolSnapshot = serde_json::from_str(&json)?;
        if state.generation != generation {
            bail!("Relay journal generation mismatch");
        }
        state.validate()?;
        Ok(state)
    }

    /// Record measured candidate checks, including all-failed attempts, without
    /// changing the committed configuration. Only the coordinator calls this.
    pub(crate) async fn record_probes(
        &self,
        base_revision: i64,
        action: &str,
        actor: &str,
        checks: &[ProbeRecord],
    ) -> ResultType<()> {
        validate_actor(actor)?;
        if base_revision < 1 || !matches!(action, "publish" | "rollback" | "recover") {
            bail!("Invalid relay probe audit context");
        }
        let nodes: Vec<_> = checks.iter().map(|c| c.endpoint.clone()).collect();
        let canonical = normalize_nodes(&nodes, false)?;
        if nodes != canonical {
            bail!("Probe audit endpoints must be canonical and unique");
        }
        for check in checks {
            if chrono::DateTime::parse_from_rfc3339(&check.checked_at).is_err()
                || check.resolved_endpoints.len() > 8
                || check.reason.as_ref().is_some_and(|r| r.len() > 1024)
                || (check.healthy
                    && (check.reason.is_some() || check.resolved_endpoints.is_empty()))
                || (!check.healthy && check.reason.is_none())
                || check
                    .resolved_endpoints
                    .iter()
                    .any(|a| a.parse::<std::net::SocketAddr>().is_err())
            {
                bail!("Invalid relay probe observation");
            }
        }
        let json = serde_json::to_string(checks)?;
        if json.len() > MAX_STATE_BYTES {
            bail!("Relay probe audit too large");
        }
        sqlx::query("INSERT INTO relay_pool_probe_audit VALUES (?, ?, ?, ?, ?, ?)")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(base_revision)
            .bind(action)
            .bind(actor)
            .bind(chrono::Utc::now().to_rfc3339())
            .bind(json)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    pub async fn recent_probes(&self, limit: i64) -> ResultType<Vec<serde_json::Value>> {
        if !(1..=100).contains(&limit) {
            bail!("Invalid probe history limit");
        }
        let rows: Vec<(String, i64, String, String, String, String)> = sqlx::query_as(
            "SELECT event_id, base_revision, action, actor, occurred_at, checks_json
             FROM relay_pool_probe_audit ORDER BY rowid DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.db)
        .await?;
        rows.into_iter()
            .map(|(id, revision, action, actor, time, json)| {
                let checks: Vec<ProbeRecord> = serde_json::from_str(&json)?;
                Ok(serde_json::json!({
                    "event_id": id, "base_revision": revision, "action": action,
                    "actor": actor, "occurred_at": time, "checks": checks
                }))
            })
            .collect()
    }

    async fn change(
        &self,
        old_generation: i64,
        mut state: PoolSnapshot,
        action: &str,
        actor: &str,
    ) -> ResultType<PoolSnapshot> {
        validate_actor(actor)?;
        state.generation = old_generation
            .checked_add(1)
            .ok_or_else(|| hbb_common::anyhow::anyhow!("Relay generation exhausted"))?;
        state.validate()?;
        let json = serde_json::to_string(&state)?;
        if json.len() > MAX_STATE_BYTES {
            bail!("Relay journal state too large");
        }
        let mut tx = self.db.begin().await?;
        let result = sqlx::query(
            "UPDATE relay_pool_state SET generation = ?, state_json = ?
             WHERE singleton = 1 AND generation = ?",
        )
        .bind(state.generation)
        .bind(&json)
        .bind(old_generation)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() != 1 {
            tx.rollback().await?;
            bail!("Relay configuration changed concurrently; reload before retry");
        }
        sqlx::query("INSERT INTO relay_pool_audit VALUES (?, ?, ?, ?, ?)")
            .bind(state.generation)
            .bind(action)
            .bind(actor)
            .bind(chrono::Utc::now().to_rfc3339())
            .bind(&json)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(state)
    }

    /// Only the trusted runtime coordinator may supply the verified and baseline
    /// readbacks. No public endpoint accepts these observations from clients.
    pub async fn prepare_publish(
        &self,
        expected_revision: i64,
        nodes: &[String],
        verified_nodes: &[String],
        baseline_runtime: &[String],
        actor: &str,
    ) -> ResultType<PoolSnapshot> {
        let state = self.snapshot().await?;
        self.prepare(
            state,
            expected_revision,
            Operation::Publish,
            nodes,
            verified_nodes,
            baseline_runtime,
            actor,
        )
        .await
    }

    pub async fn prepare_rollback(
        &self,
        expected_revision: i64,
        verified_nodes: &[String],
        baseline_runtime: &[String],
        actor: &str,
    ) -> ResultType<PoolSnapshot> {
        let state = self.snapshot().await?;
        let nodes = state
            .previous
            .as_ref()
            .ok_or_else(|| hbb_common::anyhow::anyhow!("No previous relay version"))?
            .nodes
            .clone();
        self.prepare(
            state,
            expected_revision,
            Operation::Rollback,
            &nodes,
            verified_nodes,
            baseline_runtime,
            actor,
        )
        .await
    }

    async fn prepare(
        &self,
        mut state: PoolSnapshot,
        expected_revision: i64,
        operation: Operation,
        nodes: &[String],
        verified_nodes: &[String],
        baseline_runtime: &[String],
        actor: &str,
    ) -> ResultType<PoolSnapshot> {
        validate_actor(actor)?;
        if state.current.revision != expected_revision {
            bail!("Stale relay configuration revision");
        }
        if state.pending.is_some() {
            bail!("A pending relay publication requires recovery or completion");
        }
        let nodes = normalize_nodes(nodes, false)?;
        let verified_nodes = normalize_nodes(verified_nodes, false)?;
        let baseline_runtime = normalize_nodes(baseline_runtime, false)?;
        if !subset(&verified_nodes, &nodes) || baseline_runtime != state.current.nodes {
            bail!("Probe or runtime readback does not match configured relay nodes");
        }
        let revision = state.next_revision;
        state.next_revision = revision
            .checked_add(1)
            .ok_or_else(|| hbb_common::anyhow::anyhow!("Relay revision exhausted"))?;
        state.pending = Some(PendingPublication {
            operation,
            base_revision: state.current.revision,
            candidate: PoolVersion { revision, nodes },
            verified_nodes,
            baseline_runtime,
            actor: actor.to_owned(),
            prepared_at: chrono::Utc::now().to_rfc3339(),
        });
        let action = match operation {
            Operation::Publish => "prepare_publish",
            Operation::Rollback => "prepare_rollback",
        };
        self.change(state.generation, state, action, actor).await
    }

    /// Confirm only after the coordinator obtains real runtime readback. On a
    /// mismatch the pending journal is retained, so recovery cannot be skipped.
    pub async fn confirm(
        &self,
        attempt_revision: i64,
        actual_configured: &[String],
        actual_eligible: &[String],
        actor: &str,
    ) -> ResultType<PoolSnapshot> {
        let mut state = self.snapshot().await?;
        let pending = state
            .pending
            .as_ref()
            .ok_or_else(|| hbb_common::anyhow::anyhow!("No pending relay publication"))?;
        if pending.candidate.revision != attempt_revision {
            bail!("Stale relay publication attempt");
        }
        if normalize_nodes(actual_configured, false)? != pending.candidate.nodes
            || normalize_nodes(actual_eligible, true)? != pending.verified_nodes
        {
            bail!("Runtime readback differs from verified candidate; recovery required");
        }
        let candidate = pending.candidate.clone();
        state.previous = Some(std::mem::replace(&mut state.current, candidate));
        state.pending = None;
        self.change(state.generation, state, "confirm", actor).await
    }

    /// Abort only after the coordinator verifies that the previous runtime
    /// selection has been restored. Never silently clear an uncertain attempt.
    pub async fn abort_after_restore(
        &self,
        attempt_revision: i64,
        restored_runtime: &[String],
        actor: &str,
    ) -> ResultType<PoolSnapshot> {
        let mut state = self.snapshot().await?;
        let pending = state
            .pending
            .as_ref()
            .ok_or_else(|| hbb_common::anyhow::anyhow!("No pending relay publication"))?;
        if pending.candidate.revision != attempt_revision {
            bail!("Stale relay publication attempt");
        }
        if normalize_nodes(restored_runtime, false)? != pending.baseline_runtime {
            bail!("Previous runtime selection was not restored; recovery required");
        }
        state.pending = None;
        self.change(state.generation, state, "abort_after_restore", actor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio;

    fn nodes(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[hbb_common::tokio::test]
    async fn publication_and_rollback_are_durable_and_versioned() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("relay.sqlite3");
        let old = nodes(&["old.example:21117"]);
        let new = nodes(&["new.example:21117", "spare.example:21117"]);
        let ready = nodes(&["new.example:21117"]);
        let store = RelayPoolStore::initialize(&path, &old, "test")
            .await
            .unwrap();
        let prepared = store
            .prepare_publish(1, &new, &ready, &old, "test")
            .await
            .unwrap();
        assert_eq!(prepared.current.revision, 1);
        assert_eq!(prepared.pending.as_ref().unwrap().candidate.revision, 2);
        drop(store);

        let store = RelayPoolStore::open(&path).await.unwrap();
        assert_eq!(store.snapshot().await.unwrap(), prepared);
        let committed = store.confirm(2, &new, &ready, "test").await.unwrap();
        assert_eq!(
            committed.current,
            PoolVersion {
                revision: 2,
                nodes: new.clone()
            }
        );
        assert_eq!(committed.previous.unwrap().nodes, old);
        let rollback = store.prepare_rollback(2, &old, &new, "test").await.unwrap();
        assert_eq!(rollback.pending.unwrap().operation, Operation::Rollback);
        let restored = store.confirm(3, &old, &old, "test").await.unwrap();
        assert_eq!(restored.current.revision, 3);
        assert_eq!(restored.current.nodes, old);
        assert_eq!(restored.previous.unwrap().nodes, new);
        let audit: i64 = sqlx::query_scalar("SELECT count(*) FROM relay_pool_audit")
            .fetch_one(&store.db)
            .await
            .unwrap();
        assert_eq!(audit, 5);
    }

    #[hbb_common::tokio::test]
    async fn unhealthy_candidate_and_incorrect_readback_never_commit() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("relay.sqlite3");
        let old = nodes(&["old.example:21117"]);
        let new = nodes(&["new.example:21117"]);
        let store = RelayPoolStore::initialize(&path, &old, "test")
            .await
            .unwrap();
        assert!(store
            .prepare_publish(1, &new, &[], &old, "test")
            .await
            .is_err());
        assert!(store
            .prepare_publish(1, &new, &old, &old, "test")
            .await
            .is_err());
        assert_eq!(store.snapshot().await.unwrap().generation, 1);
        let prepared = store
            .prepare_publish(1, &new, &new, &old, "test")
            .await
            .unwrap();
        assert!(store.confirm(2, &new, &old, "test").await.is_err());
        assert!(store.confirm(2, &old, &new, "test").await.is_err());
        assert!(store.abort_after_restore(2, &new, "test").await.is_err());
        assert_eq!(store.snapshot().await.unwrap(), prepared);
        assert!(store
            .prepare_publish(1, &new, &new, &old, "test")
            .await
            .is_err());
        let aborted = store.abort_after_restore(2, &old, "test").await.unwrap();
        assert_eq!(aborted.current.revision, 1);
        assert!(aborted.pending.is_none());
        assert!(store.confirm(2, &new, &new, "test").await.is_err());
        let next = store
            .prepare_publish(1, &new, &new, &old, "test")
            .await
            .unwrap();
        assert_eq!(next.pending.unwrap().candidate.revision, 3);
    }

    #[hbb_common::tokio::test]
    async fn competing_writers_cannot_both_prepare() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("relay.sqlite3");
        let old = nodes(&["old.example:21117"]);
        let a = nodes(&["a.example:21117"]);
        let b = nodes(&["b.example:21117"]);
        let first = RelayPoolStore::initialize(&path, &old, "test")
            .await
            .unwrap();
        let second = RelayPoolStore::open(&path).await.unwrap();
        let (left, right) = hbb_common::tokio::join!(
            first.prepare_publish(1, &a, &a, &old, "first"),
            second.prepare_publish(1, &b, &b, &old, "second")
        );
        assert_ne!(left.is_ok(), right.is_ok());
        let state = first.snapshot().await.unwrap();
        assert_eq!(state.current.revision, 1);
        assert_eq!(state.next_revision, 3);
        let pending = state.pending.unwrap();
        assert!(pending.candidate.nodes == a || pending.candidate.nodes == b);
    }

    #[hbb_common::tokio::test]
    async fn initialization_refuses_existing_files_and_duplicate_addresses() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("existing.sqlite3");
        let original = b"do not overwrite";
        std::fs::write(&path, original).unwrap();
        let configured = nodes(&["relay.example:21117"]);
        assert!(RelayPoolStore::initialize(&path, &configured, "test")
            .await
            .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        let duplicate = nodes(&["relay.example", "RELAY.example:21117"]);
        assert!(
            RelayPoolStore::initialize(&tmp.path().join("new.sqlite3"), &duplicate, "test")
                .await
                .is_err()
        );
    }
}
