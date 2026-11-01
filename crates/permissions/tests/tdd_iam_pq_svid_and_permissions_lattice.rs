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


use permissions::capabilities::{NetPolicyRule, EnvPolicyRule, McpPolicyRule};
use std::collections::BTreeSet;


fn valid_string() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9]+"
}

fn generate_net_rule() -> impl Strategy<Value = NetPolicyRule> {
    (valid_string(), generate_mode()).prop_map(|(s, mode)| NetPolicyRule {
        domain_glob: if s.is_empty() { "*".to_string() } else { s },
        allowed_ports: vec![],
        allowed_methods: vec![],
        mode,
    })
}

fn generate_env_rule() -> impl Strategy<Value = EnvPolicyRule> {
    (valid_string(), generate_mode()).prop_map(|(s, mode)| EnvPolicyRule {
        var_glob: if s.is_empty() { "*".to_string() } else { s },
        mode,
    })
}

fn generate_mcp_rule() -> impl Strategy<Value = McpPolicyRule> {
    (valid_string(), any::<u64>(), generate_mode()).prop_map(|(s, ms, mode)| McpPolicyRule {
        server_tool_glob: if s.is_empty() { "*".to_string() } else { s },
        max_spend_micros_per_call: ms,
        mode,
    })
}

fn generate_fs_rule() -> impl Strategy<Value = FsPolicyRule> {
    (valid_string(), generate_mode()).prop_map(|(s, mode)| FsPolicyRule {
        glob_pattern: if s.is_empty() { "*".to_string() } else { s },
        operations: permissions::glob_dfa::FsOperation::ALL,
        mode,
        required_spiffe_prefix: None,
    })
}

fn generate_lattice() -> impl Strategy<Value = PermissionLattice> {
    (
        generate_mode(), prop::collection::vec(generate_fs_rule(), 0..2),
        generate_mode(), prop::collection::vec(generate_net_rule(), 0..2),
        generate_mode(), prop::collection::vec(generate_env_rule(), 0..2),
        generate_mode(), any::<u64>(), prop::collection::vec(generate_mcp_rule(), 0..2),
    ).prop_map(|(fs_def, fs_rules, net_def, net_rules, env_def, env_rules, mcp_def, mcp_spend, mcp_rules)| {
        let fs = FsCapability::new(fs_rules, fs_def).unwrap();
        let net = NetCapability::new(net_def, net_rules).unwrap();
        let env = EnvCapability::compile(env_rules, BTreeSet::new(), env_def).unwrap();
        let mcp = McpCapability::new(mcp_def, mcp_spend, mcp_rules).unwrap();
        PermissionLattice {
            fs,
            net,
            env,
            mcp,
            interrupt_on_tools: BTreeMap::new(),
        }
    })
}


use permissions::glob_dfa::{CompiledFsAutomaton, FsOperation, FsPolicyRule};

#[test]
fn test_compiled_fs_automaton() {
    let svid = SpiffeId::parse("spiffe://td1/agent/a1/task/t1").unwrap();

    let rule1 = FsPolicyRule {
        glob_pattern: "/data/public/*".to_string(),
        operations: FsOperation::READ,
        mode: PermissionMode::Allow,
        required_spiffe_prefix: None,
    };

    let rule2 = FsPolicyRule {
        glob_pattern: "/data/private/*".to_string(),
        operations: FsOperation::ALL,
        mode: PermissionMode::Allow,
        required_spiffe_prefix: Some("spiffe://td1/agent/a1/task/t1".to_string()),
    };

    let automaton = CompiledFsAutomaton::compile(vec![rule1, rule2], PermissionMode::Deny).unwrap();

    // Assert unnormalized paths containing `..` or null bytes return `PermissionMode::Deny` immediately
    assert_eq!(automaton.evaluate(&svid, FsOperation::READ, "/data/public/../private/secret"), PermissionMode::Deny);
    assert_eq!(automaton.evaluate(&svid, FsOperation::READ, "/data/public/\0secret"), PermissionMode::Deny);

    // Verify prefix SPIFFE ID matching filters unauthorized callers
    assert_eq!(automaton.evaluate(&svid, FsOperation::READ, "/data/private/secret"), PermissionMode::Allow);

    let other_svid = SpiffeId::parse("spiffe://td1/agent/a2/task/t2").unwrap();
    assert_eq!(automaton.evaluate(&other_svid, FsOperation::READ, "/data/private/secret"), PermissionMode::Deny);

    // Normal allow case
    assert_eq!(automaton.evaluate(&other_svid, FsOperation::READ, "/data/public/test"), PermissionMode::Allow);
}

use iam::tunnel_grant::ScopedTunnelRegistry;

#[test]
fn test_net_capability_evaluate_egress() {
    let rule_deny = NetPolicyRule {
        domain_glob: "bad.example.com".to_string(),
        allowed_ports: vec![],
        allowed_methods: vec![],
        mode: PermissionMode::Deny,
    };

    let net = NetCapability::new(PermissionMode::Deny, vec![rule_deny]).unwrap();
    let registry = ScopedTunnelRegistry::new();

    let now_ms = 1000;

    // Default deny
    assert_eq!(net.evaluate_egress("good.example.com", 80, None, Some(&registry), now_ms), PermissionMode::Deny);

    // Active ScopedTunnelRegistry grant bypasses default deny
    let _token = registry.request_scoped_tunnel_token("good.example.com", 3600, now_ms).unwrap();
    assert_eq!(net.evaluate_egress("good.example.com", 80, None, Some(&registry), now_ms), PermissionMode::Allow);

    // Explicit Deny overrides active tunnel grants
    let _token_bad = registry.request_scoped_tunnel_token("bad.example.com", 3600, now_ms).unwrap();
    assert_eq!(net.evaluate_egress("bad.example.com", 80, None, Some(&registry), now_ms), PermissionMode::Deny);
}

#[test]
fn test_env_capability_scrub_host_env() {
    let mut allowlist = BTreeSet::new();
    allowlist.insert("GITHUB_TOKEN".to_string());

    let env = EnvCapability::compile(vec![], allowlist.clone(), PermissionMode::Allow).unwrap();

    let host_env = vec![
        ("AWS_SECRET_ACCESS_KEY", "secret1"),
        ("github_token", "secret2"),
        ("GITHUB_TOKEN", "secret3"),
        ("DATABASE_PASSWORD", "secret4"),
        ("BEARER_AUTH", "secret5"),
        ("NORMAL_VAR", "value"),
    ];

    let scrubbed = env.scrub_host_env(host_env);

    // Assert case-insensitive filtering drops specific variables
    assert!(!scrubbed.contains_key("AWS_SECRET_ACCESS_KEY"));
    assert!(!scrubbed.contains_key("github_token"));
    assert!(!scrubbed.contains_key("DATABASE_PASSWORD"));
    assert!(!scrubbed.contains_key("BEARER_AUTH"));

    // Assert explicit allowlist passes through
    assert!(scrubbed.contains_key("GITHUB_TOKEN"));
    assert_eq!(scrubbed.get("GITHUB_TOKEN").unwrap(), "secret3");

    // Normal vars pass through
    assert!(scrubbed.contains_key("NORMAL_VAR"));

    // Test subagent narrowing computes set intersection
    let mut child_allowlist = BTreeSet::new();
    child_allowlist.insert("ANOTHER_TOKEN".to_string());

    let child_env = EnvCapability::compile(vec![], child_allowlist, PermissionMode::Allow).unwrap();
    let narrowed = env.narrow(&child_env);

    // Intersection of {"GITHUB_TOKEN"} and {"ANOTHER_TOKEN"} is empty set
    assert!(narrowed.explicit_secret_allowlist.is_empty());
}

#[test]
fn test_mcp_capability_evaluate_call() {
    let parent = McpCapability::new(PermissionMode::Allow, 1000, vec![]).unwrap();
    let child = McpCapability::new(PermissionMode::Allow, 500, vec![]).unwrap();

    // Assert calls with `estimated_spend_micros > effective_max_spend_micros_per_call` return `PermissionMode::Deny`
    assert_eq!(parent.evaluate_call("server", "tool", 1001), PermissionMode::Deny);
    assert_eq!(parent.evaluate_call("server", "tool", 1000), PermissionMode::Allow);

    // Assert subagent narrowing clamps spend limits to `min(parent, child)`
    let narrowed = parent.narrow(&child);
    assert_eq!(narrowed.effective_max_spend_micros_per_call, 500);
    assert_eq!(narrowed.evaluate_call("server", "tool", 501), PermissionMode::Deny);
    assert_eq!(narrowed.evaluate_call("server", "tool", 500), PermissionMode::Allow);

    let narrowed_rev = child.narrow(&parent);
    assert_eq!(narrowed_rev.effective_max_spend_micros_per_call, 500);
}

#[test]
fn test_evaluate_zenoh_topic_strict_constraints() {
    let svid_root = SpiffeId::parse("spiffe://td1/agent/a1/task/t1").unwrap();
    let svid_sub = SpiffeId::parse("spiffe://td1/agent/a1/task/t1/subagent/s1/task/c1").unwrap();

    // Assert subagents can publish only to `/events` and `/state` and subscribe only to `/cmd` under their own workload path.
    // Assert any subagent publish to `/cmd` or subscribe to `/events` returns `PermissionMode::Deny`.
    assert_eq!(evaluate_zenoh_topic(&svid_sub, permissions::zenoh_guard::ZenohAction::Publish, "tantry/td1/subagents/s1/tasks/c1/events"), PermissionMode::Allow);
    assert_eq!(evaluate_zenoh_topic(&svid_sub, permissions::zenoh_guard::ZenohAction::Publish, "tantry/td1/subagents/s1/tasks/c1/state"), PermissionMode::Allow);
    assert_eq!(evaluate_zenoh_topic(&svid_sub, permissions::zenoh_guard::ZenohAction::Publish, "tantry/td1/subagents/s1/tasks/c1/cmd"), PermissionMode::Deny);
    assert_eq!(evaluate_zenoh_topic(&svid_sub, permissions::zenoh_guard::ZenohAction::Subscribe, "tantry/td1/subagents/s1/tasks/c1/cmd"), PermissionMode::Allow);
    assert_eq!(evaluate_zenoh_topic(&svid_sub, permissions::zenoh_guard::ZenohAction::Subscribe, "tantry/td1/subagents/s1/tasks/c1/events"), PermissionMode::Deny);
    assert_eq!(evaluate_zenoh_topic(&svid_sub, permissions::zenoh_guard::ZenohAction::Subscribe, "tantry/td1/subagents/s1/tasks/c1/state"), PermissionMode::Deny);

    // Assert root agents can supervise subagent topics.
    assert_eq!(evaluate_zenoh_topic(&svid_root, permissions::zenoh_guard::ZenohAction::Publish, "tantry/td1/subagents/s1/tasks/c1/cmd"), PermissionMode::Allow);
    assert_eq!(evaluate_zenoh_topic(&svid_root, permissions::zenoh_guard::ZenohAction::Subscribe, "tantry/td1/subagents/s1/tasks/c1/events"), PermissionMode::Allow);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]
    #[test]
    fn test_permission_mode_algebraic_laws(
        a in generate_mode(),
        b in generate_mode(),
        c in generate_mode(),
    ) {
        // Idempotence
        assert_eq!(a.join(a), a);
        // Commutativity
        assert_eq!(a.join(b), b.join(a));
        // Associativity
        assert_eq!(a.join(b).join(c), a.join(b.join(c)));
        // Monotonicity
        assert!(a <= a.join(b));
        // Bounds
        assert_eq!(PermissionMode::Allow.join(a), a);
        assert_eq!(PermissionMode::Deny.join(a), PermissionMode::Deny);
    }

    #[test]
    fn test_pointwise_join_attenuation_law(
        parent in generate_lattice(),
        child in generate_lattice(),
        host in valid_string(),
        port in any::<u16>(),
        env_var in valid_string(),
        server in valid_string(),
        tool in valid_string(),
        spend in any::<u64>(),
        fs_path in valid_string(),
    ) {
        let effective = parent.narrow_for_subagent(&child);

        // NetCapability
        let p_net = parent.net.evaluate_egress(&host, port, None, None, 0);
        let c_net = child.net.evaluate_egress(&host, port, None, None, 0);
        let e_net = effective.net.evaluate_egress(&host, port, None, None, 0);
        assert_eq!(e_net, p_net.join(c_net));

        // EnvCapability
        let p_env = parent.env.evaluate_var(&env_var);
        let c_env = child.env.evaluate_var(&env_var);
        let e_env = effective.env.evaluate_var(&env_var);
        assert_eq!(e_env, p_env.join(c_env));

        // McpCapability
        let p_mcp = parent.mcp.evaluate_call(&server, &tool, spend);
        let c_mcp = child.mcp.evaluate_call(&server, &tool, spend);
        let e_mcp = effective.mcp.evaluate_call(&server, &tool, spend);
        assert_eq!(e_mcp, p_mcp.join(c_mcp));

        // FsCapability
        let svid = iam::spiffe::SpiffeId::parse("spiffe://td1/agent/a1/task/t1").unwrap();
        let p_fs = parent.fs.evaluate(&svid, permissions::glob_dfa::FsOperation::READ, &fs_path);
        let c_fs = child.fs.evaluate(&svid, permissions::glob_dfa::FsOperation::READ, &fs_path);
        let e_fs = effective.fs.evaluate(&svid, permissions::glob_dfa::FsOperation::READ, &fs_path);
        assert_eq!(e_fs, p_fs.join(c_fs));
    }
}
