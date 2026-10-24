use base::typemap::StateSlot;
use runtime::observability::*;
use runtime::slots::*;
use std::collections::BTreeSet;

#[test]
fn test_hitl_bypass_slot() {
    let mut slot = HitlBypassSlot {
        approved_tool_use_ids: BTreeSet::new(),
    };
    slot.approved_tool_use_ids.insert("tool_123".to_string());

    let enc = slot.encode_payload().unwrap();
    let dec = HitlBypassSlot::decode_payload(&enc).unwrap();

    assert_eq!(slot.approved_tool_use_ids, dec.approved_tool_use_ids);
}

#[test]
fn test_mcp_sampling_depth_slot() {
    let slot = McpSamplingDepthSlot { depth: 42 };

    let enc = slot.encode_payload().unwrap();
    let dec = McpSamplingDepthSlot::decode_payload(&enc).unwrap();

    assert_eq!(slot.depth, dec.depth);
}

#[test]
fn test_metrics_registry() {
    let metrics = MetricsRegistry::new().unwrap();
    metrics.snapshot_pool_available.set(5);

    let m = metrics.registry.gather();
    assert!(!m.is_empty());
}
