use prometheus::{IntGauge, IntCounterVec, HistogramVec, Registry, Opts, HistogramOpts};
use std::sync::OnceLock;
use std::future::Future;

#[derive(Clone)]
pub struct RuntimeMetrics {
    pub microvm_snapshot_pool_available: IntGauge,
    pub zenoh_task_queue_depth: IntGauge,
    pub token_spend_micros_total: IntCounterVec,
    pub kv_cache_hit_ratio: HistogramVec,
    pub vfs_merge_conflicts_total: IntCounterVec,
}

impl RuntimeMetrics {
    pub fn new(registry: &Registry) -> Result<Self, prometheus::Error> {
        let microvm_snapshot_pool_available = IntGauge::new(
            "tantry_microvm_snapshot_pool_available",
            "Available MicroVM snapshots in pool",
        )?;
        registry.register(Box::new(microvm_snapshot_pool_available.clone()))?;

        let zenoh_task_queue_depth = IntGauge::new(
            "tantry_zenoh_task_queue_depth",
            "Depth of Zenoh task queue",
        )?;
        registry.register(Box::new(zenoh_task_queue_depth.clone()))?;

        let token_spend_micros_total = IntCounterVec::new(
            Opts::new("tantry_token_spend_micros_total", "Total token spend in micros"),
            &["tenant_id", "model_tier"],
        )?;
        registry.register(Box::new(token_spend_micros_total.clone()))?;

        let kv_cache_hit_ratio = HistogramVec::new(
            HistogramOpts::new("tantry_kv_cache_hit_ratio", "KV cache hit ratio"),
            &["provider", "model_tier"],
        )?;
        registry.register(Box::new(kv_cache_hit_ratio.clone()))?;

        let vfs_merge_conflicts_total = IntCounterVec::new(
            Opts::new("tantry_vfs_merge_conflicts_total", "Total VFS merge conflicts"),
            &["resolution_stage"],
        )?;
        registry.register(Box::new(vfs_merge_conflicts_total.clone()))?;

        Ok(Self {
            microvm_snapshot_pool_available,
            zenoh_task_queue_depth,
            token_spend_micros_total,
            kv_cache_hit_ratio,
            vfs_merge_conflicts_total,
        })
    }
}

pub fn get_metrics() -> &'static RuntimeMetrics {
    static METRICS: OnceLock<RuntimeMetrics> = OnceLock::new();
    METRICS.get_or_init(|| {
        let registry = prometheus::default_registry();
        RuntimeMetrics::new(registry).expect("Failed to initialize metrics")
    })
}

pub fn spawn_instrumented<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    use tracing::Instrument;
    let span = tracing::Span::current();
    tokio::spawn(future.instrument(span))
}
