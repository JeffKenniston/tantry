use permissions::attenuation::PermissionLattice;
use permissions::capabilities::{
    EnvCapability, FsCapability, McpCapability, McpPolicyRule, NetCapability, NetPolicyRule,
};
use permissions::ext::SpiffeId;
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

// 4D PermissionLattice proptest
fn generate_fs_rule() -> impl Strategy<Value = FsPolicyRule> {
    (
        prop_oneof![
            Just("*.txt".to_string()),
            Just("/tmp/*".to_string()),
            Just("**/*.rs".to_string())
        ],
        generate_mode(),
    )
        .prop_map(|(glob_pattern, mode)| FsPolicyRule {
            glob_pattern,
            operations: FsOperation::ALL,
            mode,
            required_spiffe_prefix: None,
        })
}

fn generate_net_rule() -> impl Strategy<Value = NetPolicyRule> {
    (
        prop_oneof![
            Just("*.com".to_string()),
            Just("api.github.com".to_string())
        ],
        generate_mode(),
    )
        .prop_map(|(domain_glob, mode)| NetPolicyRule {
            domain_glob,
            allowed_ports: vec![],
            allowed_methods: vec![],
            mode,
        })
}

fn generate_env_rule() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("API_KEY".to_string()),
        Just("DEBUG".to_string()),
        Just("*_TOKEN".to_string())
    ]
}

fn generate_mcp_rule() -> impl Strategy<Value = McpPolicyRule> {
    (
        prop_oneof![
            Just("server:tool".to_string()),
            Just("*:*".to_string())
        ],
        generate_mode(),
    )
        .prop_map(|(server_tool_glob, mode)| McpPolicyRule {
            server_tool_glob,
            mode,
        })
}

fn generate_lattice() -> impl Strategy<Value = PermissionLattice> {
    (
        generate_mode(),
        proptest::collection::vec(generate_fs_rule(), 0..3),
        generate_mode(),
        proptest::collection::vec(generate_net_rule(), 0..3),
        proptest::collection::vec(generate_env_rule(), 0..3),
        proptest::collection::vec(generate_env_rule(), 0..3),
        generate_mode(),
        proptest::collection::vec(generate_mcp_rule(), 0..3),
        0..1000u64,
    )
        .prop_map(
            |(
                fs_def,
                fs_rules,
                net_def,
                net_rules,
                env_globs,
                env_exact,
                mcp_def,
                mcp_rules,
                mcp_max,
            )| {
                PermissionLattice {
                    fs: FsCapability {
                        automaton: CompiledFsAutomaton::new(fs_def, fs_rules).unwrap(),
                    },
                    net: NetCapability::new(net_def, net_rules).unwrap(),
                    env: EnvCapability::new(env_globs, env_exact).unwrap(),
                    mcp: McpCapability::new(mcp_def, mcp_max, mcp_rules).unwrap(),
                    interrupt_on_tools: BTreeMap::new(),
                }
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10000))]
    #[test]
    fn test_4d_permission_lattice_join_semilattice_law(
        parent in generate_lattice(),
        child in generate_lattice(),
        fs_path in prop_oneof![Just("/tmp/test.txt"), Just("/usr/bin/echo")],
        net_host in prop_oneof![Just("api.github.com"), Just("example.com")],
        env_key in prop_oneof![Just("API_KEY"), Just("DEBUG"), Just("OTHER_TOKEN")],
        mcp_server in prop_oneof![Just("server"), Just("other")],
        mcp_tool in prop_oneof![Just("tool"), Just("action")],
        mcp_spend in 0..2000u64,
    ) {
        let effective = parent.narrow_for_subagent(&child).unwrap();
        let svid = SpiffeId::new("spiffe://td/foo".to_string());

        // 1. FS
        let p_fs = parent.fs.automaton.evaluate(&svid, FsOperation::READ, fs_path);
        let c_fs = child.fs.automaton.evaluate(&svid, FsOperation::READ, fs_path);
        let e_fs = effective.fs.automaton.evaluate(&svid, FsOperation::READ, fs_path);
        assert!(e_fs >= p_fs);
        assert!(e_fs >= c_fs);

        // 2. Net
        let p_net = parent.net.evaluate_egress(net_host, 80, None, None, 0);
        let c_net = child.net.evaluate_egress(net_host, 80, None, None, 0);
        let e_net = effective.net.evaluate_egress(net_host, 80, None, None, 0);
        assert!(e_net >= p_net);
        assert!(e_net >= c_net);

        // 3. Env
        let host_vars = vec![(env_key.to_string(), "val".to_string())];
        let p_env = parent.env.scrub_host_env(host_vars.clone());
        let c_env = child.env.scrub_host_env(host_vars.clone());
        let e_env = effective.env.scrub_host_env(host_vars.clone());
        // If parent drops it, effective MUST drop it. (No downgrade to Allow).
        if p_env.is_empty() {
            assert!(e_env.is_empty());
        }
        // If child drops it, effective MUST drop it.
        if c_env.is_empty() {
            assert!(e_env.is_empty());
        }

        // 4. MCP
        let p_mcp = parent.mcp.evaluate_mcp_call(mcp_server, mcp_tool, mcp_spend);
        let c_mcp = child.mcp.evaluate_mcp_call(mcp_server, mcp_tool, mcp_spend);
        let e_mcp = effective.mcp.evaluate_mcp_call(mcp_server, mcp_tool, mcp_spend);
        assert!(e_mcp >= p_mcp);
        assert!(e_mcp >= c_mcp);
    }
}
