use prometheus::{Gauge, IntCounterVec, HistogramVec, default_registry};
use std::sync::OnceLock;

/// Global tantry_microvm_snapshot_pool_available metric.
pub fn microvm_snapshot_pool_available() -> &'static Gauge {
    static METRIC: OnceLock<Gauge> = OnceLock::new();
    METRIC.get_or_init(|| {
        let gauge = Gauge::new(
            "tantry_microvm_snapshot_pool_available",
            "Number of available MicroVM snapshots",
        )
        .expect("metric creation failed");
        default_registry().register(Box::new(gauge.clone())).expect("registration failed");
        gauge
    })
}

/// Global tantry_zenoh_task_queue_depth metric.
pub fn zenoh_task_queue_depth() -> &'static Gauge {
    static METRIC: OnceLock<Gauge> = OnceLock::new();
    METRIC.get_or_init(|| {
        let gauge = Gauge::new(
            "tantry_zenoh_task_queue_depth",
            "Depth of the Zenoh task queue",
        )
        .expect("metric creation failed");
        default_registry().register(Box::new(gauge.clone())).expect("registration failed");
        gauge
    })
}

/// Global tantry_token_spend_micros_total metric.
pub fn token_spend_micros_total() -> &'static IntCounterVec {
    static METRIC: OnceLock<IntCounterVec> = OnceLock::new();
    METRIC.get_or_init(|| {
        let counter = IntCounterVec::new(
            prometheus::Opts::new(
                "tantry_token_spend_micros_total",
                "Total token spend in microseconds",
            ),
            &["tenant_id", "model_tier"],
        )
        .expect("metric creation failed");
        default_registry().register(Box::new(counter.clone())).expect("registration failed");
        counter
    })
}

/// Global tantry_kv_cache_hit_ratio metric.
pub fn kv_cache_hit_ratio() -> &'static HistogramVec {
    static METRIC: OnceLock<HistogramVec> = OnceLock::new();
    METRIC.get_or_init(|| {
        let histogram = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "tantry_kv_cache_hit_ratio",
                "KV cache hit ratio",
            ),
            &["provider", "model_tier"],
        )
        .expect("metric creation failed");
        default_registry().register(Box::new(histogram.clone())).expect("registration failed");
        histogram
    })
}

/// Global tantry_vfs_merge_conflicts_total metric.
pub fn vfs_merge_conflicts_total() -> &'static IntCounterVec {
    static METRIC: OnceLock<IntCounterVec> = OnceLock::new();
    METRIC.get_or_init(|| {
        let counter = IntCounterVec::new(
            prometheus::Opts::new(
                "tantry_vfs_merge_conflicts_total",
                "Total VFS merge conflicts by resolution stage",
            ),
            &["resolution_stage"],
        )
        .expect("metric creation failed");
        default_registry().register(Box::new(counter.clone())).expect("registration failed");
        counter
    })
}

/// Initializes all metrics so they are registered.
pub fn init_metrics() {
    let _ = microvm_snapshot_pool_available();
    let _ = zenoh_task_queue_depth();
    let _ = token_spend_micros_total();
    let _ = kv_cache_hit_ratio();
    let _ = vfs_merge_conflicts_total();
}
