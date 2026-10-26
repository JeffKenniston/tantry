pub mod error;
pub mod middleware;
pub mod observability;
pub mod slots;

pub use error::RuntimeError;
pub use middleware::{
    AgentMiddleware, NextModelCall, ToolDefinition, ToolExecutionOutput, TurnExecutionContext,
};

#[cfg(test)]
mod tests {
    use super::*;

    use base::typemap::{DefaultExtensionRegistryImpl, StateExtensionMap};
    use std::collections::BTreeSet;
    use uuid::Uuid;

    #[test]
    fn test_slots_roundtrip() {
        let mut registry = DefaultExtensionRegistryImpl::new();
        slots::register_runtime_slots(&mut registry);

        let mut map = StateExtensionMap::new();

        let mut bypass = slots::HitlBypassSlot {
            approved_tool_use_ids: BTreeSet::new(),
        };
        bypass
            .approved_tool_use_ids
            .insert(Uuid::now_v7().to_string());

        let delta = slots::TurnDeltaBufferSlot {
            message_deltas: vec![],
        };
        let depth = slots::McpSamplingDepthSlot { depth: 1 };

        map.insert(bypass.clone());
        map.insert(delta.clone());
        map.insert(depth.clone());

        let serialized = map.serialize_all().unwrap();
        let mut deserialized = StateExtensionMap::new();
        deserialized.hydrate_all(&serialized, &registry).unwrap();

        assert_eq!(
            deserialized.get::<slots::HitlBypassSlot>().unwrap(),
            &bypass
        );
        assert_eq!(
            deserialized.get::<slots::TurnDeltaBufferSlot>().unwrap(),
            &delta
        );
        assert_eq!(
            deserialized.get::<slots::McpSamplingDepthSlot>().unwrap(),
            &depth
        );

        // test fork_shared_only
        let shared = map.fork_shared_only();
        assert!(shared.get::<slots::HitlBypassSlot>().is_none());
        assert!(shared.get::<slots::TurnDeltaBufferSlot>().is_none());
        assert_eq!(shared.get::<slots::McpSamplingDepthSlot>().unwrap(), &depth);
    }

    #[test]
    fn test_metrics_registration() {
        let registry = prometheus::default_registry();
        let metrics = observability::RuntimeMetrics::new(registry).unwrap();

        metrics.microvm_snapshot_pool_available.set(5);
        metrics.zenoh_task_queue_depth.inc();
        metrics
            .token_spend_micros_total
            .with_label_values(&["tenant1", "frontier"])
            .inc_by(100);
        metrics
            .kv_cache_hit_ratio
            .with_label_values(&["openai", "frontier"])
            .observe(0.8);
        metrics
            .vfs_merge_conflicts_total
            .with_label_values(&["fast_path"])
            .inc();
    }
}
