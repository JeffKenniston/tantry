use iam::spiffe::SpiffeId;
use permissions::attenuation::PermissionLattice;
use permissions::capabilities::{EnvCapability, FsCapability, McpCapability, NetCapability};
use permissions::lattice::PermissionMode;
use permissions::zenoh_guard::evaluate_zenoh_topic;
use std::collections::BTreeMap;

#[test]
fn test_attenuation() {
    let mut i1 = BTreeMap::new();
    i1.insert("tool1".to_string(), PermissionMode::Interrupt);
    let p1 = PermissionLattice {
        fs: FsCapability::new(vec![], PermissionMode::Allow).unwrap(),
        net: NetCapability::new(PermissionMode::Allow, vec![]).unwrap(),
        env: EnvCapability::compile(vec![], std::collections::BTreeSet::new(), PermissionMode::Allow).unwrap(),
        mcp: McpCapability::new(PermissionMode::Allow, 1000, vec![]).unwrap(),
        interrupt_on_tools: i1,
    };

    let mut i2 = BTreeMap::new();
    i2.insert("tool1".to_string(), PermissionMode::Deny);
    let p2 = PermissionLattice {
        fs: FsCapability::new(vec![], PermissionMode::Allow).unwrap(),
        net: NetCapability::new(PermissionMode::Allow, vec![]).unwrap(),
        env: EnvCapability::compile(vec![], std::collections::BTreeSet::new(), PermissionMode::Allow).unwrap(),
        mcp: McpCapability::new(PermissionMode::Allow, 500, vec![]).unwrap(),
        interrupt_on_tools: i2,
    };

    let child = p1.narrow_for_subagent(&p2);
    assert_eq!(child.mcp.effective_max_spend_micros_per_call, 500);
    assert_eq!(
        *child.interrupt_on_tools.get("tool1").unwrap(),
        PermissionMode::Deny
    );
}

#[test]
fn test_zenoh_guard_invalid_chars() {
    let svid = SpiffeId::parse("spiffe://td1/agent/a1/task/t1").unwrap();
    assert_eq!(
        evaluate_zenoh_topic(
            &svid,
            permissions::zenoh_guard::ZenohAction::Publish,
            "tantry/td1/.."
        ),
        PermissionMode::Deny
    );
    assert_eq!(
        evaluate_zenoh_topic(
            &svid,
            permissions::zenoh_guard::ZenohAction::Publish,
            "tantry/td1/\0"
        ),
        PermissionMode::Deny
    );
    assert_eq!(
        evaluate_zenoh_topic(
            &svid,
            permissions::zenoh_guard::ZenohAction::Publish,
            "/tantry/td1"
        ),
        PermissionMode::Deny
    );
    assert_eq!(
        evaluate_zenoh_topic(
            &svid,
            permissions::zenoh_guard::ZenohAction::Publish,
            "tantry/td1/"
        ),
        PermissionMode::Deny
    );
}

#[test]
fn test_zenoh_guard_root_agent() {
    let svid = SpiffeId::parse("spiffe://td1/agent/a1/task/t1").unwrap();
    assert_eq!(
        evaluate_zenoh_topic(
            &svid,
            permissions::zenoh_guard::ZenohAction::Publish,
            "tantry/td1/foo/bar"
        ),
        PermissionMode::Allow
    );
    assert_eq!(
        evaluate_zenoh_topic(
            &svid,
            permissions::zenoh_guard::ZenohAction::Publish,
            "tantry/td1"
        ),
        PermissionMode::Allow
    );
    assert_eq!(
        evaluate_zenoh_topic(
            &svid,
            permissions::zenoh_guard::ZenohAction::Publish,
            "tantry/td2/foo/bar"
        ),
        PermissionMode::Deny
    );
}

#[test]
fn test_zenoh_guard_subagent() {
    let svid = SpiffeId::parse("spiffe://td1/agent/a1/task/t1/subagent/s1/task/c1").unwrap();

    // Publish
    assert_eq!(
        evaluate_zenoh_topic(
            &svid,
            permissions::zenoh_guard::ZenohAction::Publish,
            "tantry/td1/subagents/s1/tasks/c1/events"
        ),
        PermissionMode::Allow
    );
    assert_eq!(
        evaluate_zenoh_topic(
            &svid,
            permissions::zenoh_guard::ZenohAction::Publish,
            "tantry/td1/subagents/s1/tasks/c1/state"
        ),
        PermissionMode::Allow
    );
    assert_eq!(
        evaluate_zenoh_topic(
            &svid,
            permissions::zenoh_guard::ZenohAction::Publish,
            "tantry/td1/subagents/s1/tasks/c1/cmd"
        ),
        PermissionMode::Deny
    );

    // Subscribe (is_publish = false)
    assert_eq!(
        evaluate_zenoh_topic(
            &svid,
            permissions::zenoh_guard::ZenohAction::Subscribe,
            "tantry/td1/subagents/s1/tasks/c1/cmd"
        ),
        PermissionMode::Allow
    );
    assert_eq!(
        evaluate_zenoh_topic(
            &svid,
            permissions::zenoh_guard::ZenohAction::Subscribe,
            "tantry/td1/subagents/s1/tasks/c1/events"
        ),
        PermissionMode::Deny
    );
    assert_eq!(
        evaluate_zenoh_topic(
            &svid,
            permissions::zenoh_guard::ZenohAction::Subscribe,
            "tantry/td1/subagents/s1/tasks/c1/state"
        ),
        PermissionMode::Deny
    );
}

use proptest::prelude::*;
fn generate_mode() -> impl Strategy<Value = PermissionMode> {
    prop_oneof![
        Just(PermissionMode::Allow),
        Just(PermissionMode::Interrupt),
        Just(PermissionMode::Deny),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10000))]
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
