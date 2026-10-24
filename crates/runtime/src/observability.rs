use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, IntGauge, Opts, Registry};
use std::future::Future;
use tracing::Instrument;

/// Metrics registry wrapper
#[derive(Clone, Debug)]
pub struct MetricsRegistry {
    pub registry: Registry,
    pub snapshot_pool_available: IntGauge,
    pub task_queue_depth: IntGauge,
    pub token_spend_micros: IntCounterVec,
    pub kv_cache_hit_ratio: HistogramVec,
    pub vfs_merge_conflicts: IntCounterVec,
}

impl MetricsRegistry {
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        let snapshot_pool_available = IntGauge::new(
            "tantry_microvm_snapshot_pool_available",
            "Available MicroVM snapshots",
        )?;
        registry.register(Box::new(snapshot_pool_available.clone()))?;

        let task_queue_depth =
            IntGauge::new("tantry_zenoh_task_queue_depth", "Zenoh task queue depth")?;
        registry.register(Box::new(task_queue_depth.clone()))?;

        let token_spend_micros = IntCounterVec::new(
            Opts::new(
                "tantry_token_spend_micros_total",
                "Total token spend in micros",
            ),
            &["tenant_id", "model_tier"],
        )?;
        registry.register(Box::new(token_spend_micros.clone()))?;

        let kv_cache_hit_ratio = HistogramVec::new(
            HistogramOpts::new("tantry_kv_cache_hit_ratio", "KV cache hit ratio"),
            &["provider", "model_tier"],
        )?;
        registry.register(Box::new(kv_cache_hit_ratio.clone()))?;

        let vfs_merge_conflicts = IntCounterVec::new(
            Opts::new(
                "tantry_vfs_merge_conflicts_total",
                "Total VFS merge conflicts by stage",
            ),
            &["resolution_stage"],
        )?;
        registry.register(Box::new(vfs_merge_conflicts.clone()))?;

        Ok(Self {
            registry,
            snapshot_pool_available,
            task_queue_depth,
            token_spend_micros,
            kv_cache_hit_ratio,
            vfs_merge_conflicts,
        })
    }
}

/// Spawns a task, automatically instrumenting it with the current span.
pub fn spawn_instrumented<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(future.instrument(tracing::Span::current()))
}
