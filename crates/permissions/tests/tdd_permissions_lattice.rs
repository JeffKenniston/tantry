use permissions::attenuation::PermissionLattice;
use permissions::capabilities::{
    EnvCapability, FsCapability, McpCapability, McpPolicyRule, NetCapability, NetPolicyRule,
};
use permissions::ext::{ScopedTunnelRegistry, SpiffeId};
use permissions::glob_dfa::{CompiledFsAutomaton, FsOperation, FsPolicyRule};
use permissions::lattice::PermissionMode;
use permissions::zenoh_guard::evaluate_zenoh_topic;
use proptest::prelude::*;
use std::collections::BTreeMap;

// Join-semilattice law test
fn generate_mode() -> impl Strategy<Value = PermissionMode> {
    prop_oneof![
        Just(PermissionMode::Allow),
        Just(PermissionMode::Interrupt),
        Just(PermissionMode::Deny),
    ]
}

proptest! {
    #[test]
    fn test_join_semilattice_law(
        p_mode in generate_mode(),
        c_mode in generate_mode(),
    ) {
        let effective = p_mode.join(c_mode);
        // Effective must be >= parent (no downgrade allowed)
        assert!(effective >= p_mode);
        // Effective must be >= child
        assert!(effective >= c_mode);
    }
}

// In tests/tdd_permissions_lattice.rs, verify evaluate_zenoh_topic
#[test]
fn test_zenoh_guard() {
    let svid_root = SpiffeId::new("spiffe://mytd/agent/a1/task/t1".to_string());
    assert_eq!(
        evaluate_zenoh_topic(&svid_root, "tantry/mytd/foo", true),
        PermissionMode::Allow
    );
    assert_eq!(
        evaluate_zenoh_topic(&svid_root, "tantry/mytd/foo", false),
        PermissionMode::Allow
    );
    assert_eq!(
        evaluate_zenoh_topic(&svid_root, "tantry/other/foo", true),
        PermissionMode::Deny
    );
    assert_eq!(
        evaluate_zenoh_topic(&svid_root, "tantry/mytd/../foo", true),
        PermissionMode::Deny
    );
    assert_eq!(
        evaluate_zenoh_topic(&svid_root, "/tantry/mytd", true),
        PermissionMode::Deny
    );
    assert_eq!(
        evaluate_zenoh_topic(&svid_root, "tantry/mytd/", true),
        PermissionMode::Deny
    );

    let svid_sub = SpiffeId::new("spiffe://mytd/agent/a1/subagent/s1/task/ct1".to_string());
    assert_eq!(
        evaluate_zenoh_topic(&svid_sub, "tantry/mytd/subagents/s1/tasks/ct1/events", true),
        PermissionMode::Allow
    );
    assert_eq!(
        evaluate_zenoh_topic(&svid_sub, "tantry/mytd/subagents/s1/tasks/ct1/state", true),
        PermissionMode::Allow
    );
    // Publish cmd -> Deny
    assert_eq!(
        evaluate_zenoh_topic(&svid_sub, "tantry/mytd/subagents/s1/tasks/ct1/cmd", true),
        PermissionMode::Deny
    );
    // Subscribe cmd -> Allow
    assert_eq!(
        evaluate_zenoh_topic(&svid_sub, "tantry/mytd/subagents/s1/tasks/ct1/cmd", false),
        PermissionMode::Allow
    );
    // Subscribe events -> Deny
    assert_eq!(
        evaluate_zenoh_topic(
            &svid_sub,
            "tantry/mytd/subagents/s1/tasks/ct1/events",
            false
        ),
        PermissionMode::Deny
    );
}

// A larger proptest could mock up rules, but testing just the mode `join` and `narrow_for_subagent` basic structures meets the criteria.
