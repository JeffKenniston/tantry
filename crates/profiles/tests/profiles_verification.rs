use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use proptest::prelude::*;

use profiles::budget_allocator::PromptTokenBudgetAllocator;
use profiles::schema::{HarnessProfile, HarnessProfileOverride, parse_profile_key};
use profiles::sigstore::{SigstoreVerifier, SigstoreBundle};
use profiles::error::ProfileError;
use runtime::middleware::AgentMiddleware;

#[derive(Clone)]
struct DummyMiddleware {
    name: &'static str,
}

#[async_trait]
impl AgentMiddleware for DummyMiddleware {
    fn name(&self) -> &'static str {
        self.name
    }
}

#[test]
fn test_parse_profile_key() {
    assert_eq!(
        parse_profile_key("google_genai:gemini-3.1-pro:preview").unwrap(),
        ("google_genai", Some("gemini-3.1-pro:preview"))
    );
    assert_eq!(
        parse_profile_key("anthropic").unwrap(),
        ("anthropic", None)
    );
}

#[test]
fn test_merge_override_properties() {
    let mut base = HarnessProfile {
        profile_key: "base".to_string(),
        system_prompt_prefix: None,
        system_prompt_suffix: None,
        excluded_tools: BTreeSet::from(["tool_a".to_string()]),
        excluded_middleware: BTreeSet::from(["mw_a".to_string()]),
        tool_description_overrides: BTreeMap::from([("tool_a".to_string(), "old_desc".to_string())]),
        extra_middleware: vec![
            Arc::new(DummyMiddleware { name: "mw_0" }),
            Arc::new(DummyMiddleware { name: "mw_1" }),
            Arc::new(DummyMiddleware { name: "mw_2" }),
        ],
        supported_media_kinds: None,
        init_kwargs: BTreeMap::from([("key_a".to_string(), serde_json::Value::String("val_a".to_string()))]),
        context_window_tokens: 1000,
        general_purpose_subagent: Some(Box::new(HarnessProfileOverride {
            excluded_tools: BTreeSet::from(["sub_tool_a".to_string()]),
            general_purpose_subagent: Some(Box::new(HarnessProfileOverride {
                 excluded_tools: BTreeSet::from(["sub_sub_tool_a".to_string()]),
                 ..Default::default()
            })),
            ..Default::default()
        })),
    };

    let ovr = HarnessProfileOverride {
        system_prompt_prefix: None,
        system_prompt_suffix: None,
        excluded_tools: BTreeSet::from(["tool_b".to_string()]),
        excluded_middleware: BTreeSet::from(["mw_b".to_string()]),
        tool_description_overrides: BTreeMap::from([("tool_a".to_string(), "new_desc".to_string())]),
        extra_middleware: vec![
            Arc::new(DummyMiddleware { name: "mw_1" }),
            Arc::new(DummyMiddleware { name: "mw_3" }),
        ],
        supported_media_kinds: None,
        init_kwargs: BTreeMap::from([("key_b".to_string(), serde_json::Value::String("val_b".to_string()))]),
        context_window_tokens: None,
        general_purpose_subagent: Some(Box::new(HarnessProfileOverride {
            excluded_tools: BTreeSet::from(["sub_tool_b".to_string()]),
            general_purpose_subagent: Some(Box::new(HarnessProfileOverride {
                 excluded_tools: BTreeSet::from(["sub_sub_tool_b".to_string()]),
                 ..Default::default()
            })),
            ..Default::default()
        })),
    };

    base.apply_override(&ovr);

    assert!(base.excluded_tools.contains("tool_a"));
    assert!(base.excluded_tools.contains("tool_b"));
    assert!(base.excluded_middleware.contains("mw_a"));
    assert!(base.excluded_middleware.contains("mw_b"));
    assert_eq!(base.tool_description_overrides.get("tool_a").unwrap(), "new_desc");

    assert_eq!(base.extra_middleware.len(), 4);
    assert_eq!(base.extra_middleware[0].name(), "mw_0");
    assert_eq!(base.extra_middleware[1].name(), "mw_1");
    assert_eq!(base.extra_middleware[2].name(), "mw_2");
    assert_eq!(base.extra_middleware[3].name(), "mw_3");

    assert_eq!(base.init_kwargs.get("key_a").unwrap().as_str().unwrap(), "val_a");
    assert_eq!(base.init_kwargs.get("key_b").unwrap().as_str().unwrap(), "val_b");

    let subagent = base.general_purpose_subagent.as_ref().unwrap();
    assert!(subagent.excluded_tools.contains("sub_tool_a"));
    assert!(subagent.excluded_tools.contains("sub_tool_b"));

    let sub_subagent = subagent.general_purpose_subagent.as_ref().unwrap();
    assert!(sub_subagent.excluded_tools.contains("sub_sub_tool_a"));
    assert!(sub_subagent.excluded_tools.contains("sub_sub_tool_b"));
}

proptest! {
    #[test]
    fn test_budget_allocator_properties(context_window_tokens in 64usize..=2_000_000usize) {
        let budgets = PromptTokenBudgetAllocator::allocate(context_window_tokens).unwrap();

        prop_assert_eq!(budgets.total_allocated(), budgets.max_total_prompt_tokens);
        prop_assert_eq!(budgets.max_total_prompt_tokens, context_window_tokens / 4);
        prop_assert!(budgets.block3_repomap_max_tokens <= 2500);
        prop_assert!(budgets.block4_memory_max_tokens <= 4000);
    }
}

#[test]
fn test_sigstore_verification() {
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use ml_dsa::Generate;

    let root_sk = SigningKey::generate(&mut OsRng);
    let leaf_sk = SigningKey::generate(&mut OsRng);

    let pq_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::generate();

    let mut artifact_bytes = b"my SKILL.md payload".to_vec();
    let oidc_issuer = "https://github.com/login/oauth";
    let san_uri = "https://github.com/my/repo";
    let not_before = 1000;
    let not_after = 2000;

    let bundle_str = SigstoreVerifier::sign_artifact_bundle(
        &artifact_bytes,
        oidc_issuer,
        san_uri,
        not_before,
        not_after,
        &root_sk,
        &leaf_sk,
        Some(&pq_sk),
    ).unwrap();

    // Inject a sibling hash to be tampered with
    let mut bundle_obj: SigstoreBundle = serde_json::from_str(&bundle_str).unwrap();
    bundle_obj.rekor_entry.inclusion_proof.hashes_hex.push(hex::encode([0x88; 32]));


    let root_vk = ed25519_dalek::VerifyingKey::from(&root_sk);
    let mut trusted_fulcio_root_pk = [0u8; 32];
    trusted_fulcio_root_pk.copy_from_slice(root_vk.as_bytes());
    let verifier = SigstoreVerifier {
        trusted_fulcio_root_pk,
        expected_oidc_issuer: None,
    };

    // Test base Merkle failure (root hash mismatches due to new injected hash in the tree).
    // Let's actually test standard verify passes with empty hashes first.
    let bundle_str_base = SigstoreVerifier::sign_artifact_bundle(
        &artifact_bytes,
        oidc_issuer,
        san_uri,
        not_before,
        not_after,
        &root_sk,
        &leaf_sk,
        Some(&pq_sk),
    ).unwrap();
    let report = verifier.verify_bundle(&artifact_bytes, &bundle_str_base, true).unwrap();
    assert!(report.pq_verified);

    // Tamper artifact 1 byte
    artifact_bytes[0] ^= 1;
    let err = verifier.verify_bundle(&artifact_bytes, &bundle_str_base, true).unwrap_err();
    assert!(matches!(err, ProfileError::SigstoreDigestMismatch { .. }));
    artifact_bytes[0] ^= 1;

    // Merkle tamper validation
    let mut bad_merkle_bundle = serde_json::from_str::<SigstoreBundle>(&bundle_str_base).unwrap();
    // Rebuild root hash to include a single sibling hash so it's a valid tree.
    let sibling_hash = [0x55; 32];
    let mut leaf_can = String::new();
    let mut hasher = sha2::Sha256::new();
    hasher.update(&artifact_bytes);
    use sha2::Digest;
    leaf_can.push_str(&hex::encode(hasher.finalize()));

    let mut hasher = sha2::Sha256::new();
    hasher.update([0x00]);
    hasher.update(leaf_can.as_bytes());
    let leaf_hash: [u8; 32] = hasher.finalize().into();

    let mut hasher = sha2::Sha256::new();
    hasher.update([0x01]);
    hasher.update(leaf_hash);
    hasher.update(sibling_hash);
    let valid_root: [u8; 32] = hasher.finalize().into();

    bad_merkle_bundle.rekor_entry.inclusion_proof.hashes_hex = vec![hex::encode(sibling_hash)];
    bad_merkle_bundle.rekor_entry.inclusion_proof.root_hash_hex = hex::encode(valid_root);
    bad_merkle_bundle.rekor_entry.inclusion_proof.tree_size = 2;
    bad_merkle_bundle.rekor_entry.inclusion_proof.log_index = 0;

    let valid_merkle_str = serde_json::to_string(&bad_merkle_bundle).unwrap();
    let report = verifier.verify_bundle(&artifact_bytes, &valid_merkle_str, true).unwrap();
    assert!(report.pq_verified);

    // Tamper the single sibling hash
    let mut tampered_sibling = sibling_hash;
    tampered_sibling[0] ^= 1;
    bad_merkle_bundle.rekor_entry.inclusion_proof.hashes_hex = vec![hex::encode(tampered_sibling)];
    let err = verifier.verify_bundle(&artifact_bytes, &serde_json::to_string(&bad_merkle_bundle).unwrap(), true).unwrap_err();
    assert!(matches!(err, ProfileError::SigstoreMerkleProofInvalid(_)));


    let mut bundle_obj: SigstoreBundle = serde_json::from_str(&bundle_str_base).unwrap();

    // Tamper timestamp
    bundle_obj.rekor_entry.integrated_time = 3000;
    let err = verifier.verify_bundle(&artifact_bytes, &serde_json::to_string(&bundle_obj).unwrap(), true).unwrap_err();
    assert!(matches!(err, ProfileError::SigstoreTimestampOutOfRange { .. }));
    bundle_obj.rekor_entry.integrated_time = 1500;

    // Missing ML-DSA
    bundle_obj.pq_signature_mldsa65_b64 = None;
    let err = verifier.verify_bundle(&artifact_bytes, &serde_json::to_string(&bundle_obj).unwrap(), true).unwrap_err();
    assert!(matches!(err, ProfileError::SigstoreMissingPqSignature));

    let report_no_pq = verifier.verify_bundle(&artifact_bytes, &serde_json::to_string(&bundle_obj).unwrap(), false).unwrap();
    assert!(!report_no_pq.pq_verified);
}
