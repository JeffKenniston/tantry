use chrono::Utc;
use iam::IdentityManager;
use iam::ca::{SovereignCaIdentityManager, acquire_or_init_master_key};
use iam::error::IamError;
use iam::key_hierarchy::KeyHierarchy;
use iam::svid::WorkloadSvid;
use iam::tunnel_grant::ScopedTunnelRegistry;
use ml_dsa::MlDsa65;
use ml_dsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use ml_dsa::signature::Keypair;
use rand_core::{OsRng, RngCore};
use ml_dsa::KeyExport;

fn mint_dummy_svid_for_test(spiffe_id_str: &str) -> WorkloadSvid {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let ed_sk = ed25519_dalek::SigningKey::from_bytes(&secret);
    let ed_pub = ed_sk.verifying_key().to_bytes();

    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let ml_sk = ml_dsa::SigningKey::<MlDsa65>::from_seed((&seed).into());
    let ml_pkcs8 = ml_sk.to_pkcs8_der().unwrap().as_bytes().to_vec();
    let ml_pk = ml_sk.verifying_key();
    let ml_spki = ml_pk.to_public_key_der().unwrap().as_bytes().to_vec();

    let now = chrono::Utc::now();
    WorkloadSvid {
        spiffe_id: iam::spiffe::SpiffeId::parse(spiffe_id_str).unwrap(),
        cert_der: vec![],
        cert_pem: String::new(),
        ed25519_seed: zeroize::Zeroizing::new(secret),
        ed25519_pk: ed_pub,
        mldsa65_sk_bytes: zeroize::Zeroizing::new(ml_pkcs8),
        mldsa65_pk: ml_spki,
        pq_extension: iam::pq_ext::PqExtensionPayload {
            subject_mldsa65_pk: vec![],
            issuer_mldsa65_sig: vec![],
            pre_tbs_blake3: [0u8; 32],
        },
        issued_at_ms: (now - chrono::Duration::seconds(3600)).timestamp_millis(),
        expires_at_ms: (now + chrono::Duration::seconds(3600)).timestamp_millis(),
    }
}

#[test]
fn test_spiffe_id_subagent_ttl_narrowing() {
    let temp = tempfile::tempdir().unwrap();
    let db_dir = temp.path().to_path_buf();
    let root_kek = acquire_or_init_master_key(&db_dir).unwrap();
    let ca = SovereignCaIdentityManager::new(root_kek.clone(), &db_dir).unwrap();

    let parent_svid = mint_dummy_svid_for_test("spiffe://example.org/agent/agent1/task/task1");

    let child1 = ca
        .mint_subagent_svid(&parent_svid, "sub1", "task2", 7200)
        .unwrap();
    assert_eq!(child1.expires_at_ms, parent_svid.expires_at_ms);
    assert_eq!(
        child1.spiffe_id.uri(),
        "spiffe://example.org/agent/agent1/task/task1/subagent/sub1/task/task2"
    );

    let child2 = ca
        .mint_subagent_svid(&parent_svid, "sub1", "task2", 1800)
        .unwrap();
    assert!(child2.expires_at_ms < parent_svid.expires_at_ms);
}

#[tokio::test]
async fn test_sovereign_ca_and_audits_extended() {
    let temp = tempfile::tempdir().unwrap();
    let db_dir = temp.path().to_path_buf();
    let root_kek = acquire_or_init_master_key(&db_dir).unwrap();
    let ca = SovereignCaIdentityManager::new(root_kek.clone(), &db_dir).unwrap();

    let mmr_root = [42u8; 32];
    let sth = ca.sign_audit_sth(10, 1000, &mmr_root).unwrap();

    assert!(ca.verify_audit_sth(&sth).is_ok());

    let mut tampered_sth = sth.clone();
    tampered_sth.tree_size = 11;
    assert!(ca.verify_audit_sth(&tampered_sth).is_err());
}

#[test]
fn test_dpop_proof_verification_and_replay_rejection() {
    let temp = tempfile::tempdir().unwrap();
    let db_dir = temp.path().to_path_buf();
    let root_kek = acquire_or_init_master_key(&db_dir).unwrap();
    let _ca = SovereignCaIdentityManager::new(root_kek.clone(), &db_dir).unwrap();

    let svid = mint_dummy_svid_for_test("spiffe://example.org/agent/agent1/task/task1");

    let mut seed = [0u8; 32];
    seed.copy_from_slice(svid.ed25519_seed.as_ref());
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let proof = iam::dpop::mint_dpop_proof(
        &signing_key,
        "POST",
        "https://api.example.com/data?query=1",
        Some("token123"),
        chrono::Utc::now().timestamp(),
    )
    .unwrap();

    let verifier = iam::dpop::DpopVerifier::default();
    assert!(
        verifier
            .verify_dpop_proof(
                &proof,
                "POST",
                "https://api.example.com/data",
                Some("token123"),
                chrono::Utc::now().timestamp(),
            )
            .is_ok()
    );

    assert!(
        verifier
            .verify_dpop_proof(
                &proof,
                "POST",
                "https://api.example.com/data",
                Some("token123"),
                chrono::Utc::now().timestamp(),
            )
            .is_err()
    );

    let proof2 = iam::dpop::mint_dpop_proof(
        &signing_key,
        "GET",
        "https://api.example.com/data",
        Some("token123"),
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    assert!(
        verifier
            .verify_dpop_proof(
                &proof2,
                "POST",
                "https://api.example.com/data",
                Some("token123"),
                chrono::Utc::now().timestamp(),
            )
            .is_err()
    );
}

#[tokio::test]
async fn test_scoped_tunnel_registry_host_matching() {
    let temp = tempfile::tempdir().unwrap();
    let db_dir = temp.path().to_path_buf();
    let root_kek = acquire_or_init_master_key(&db_dir).unwrap();
    let _ca = SovereignCaIdentityManager::new(root_kek.clone(), &db_dir).unwrap();

    let svid = mint_dummy_svid_for_test("spiffe://example.org/agent/agent1/task/task1");

    let registry = ScopedTunnelRegistry::new();
    let grant = registry.request_scoped_tunnel_token("api.stripe.com", 3600, chrono::Utc::now().timestamp_millis()).unwrap();

    assert_eq!(
        iam::normalize_service_authority("https://api.stripe.com:443").unwrap(),
        "api.stripe.com"
    );
    assert!(
        registry.is_service_active("https://api.stripe.com:443", Utc::now().timestamp_millis())
    );

    struct DummyVerifier {
        svid: WorkloadSvid,
    }
    impl IdentityManager for DummyVerifier {
        fn current_svid(&self) -> Option<WorkloadSvid> {
            Some(self.svid.clone())
        }
        fn verify_jwt_svid(&self, token: &str, expected_audience: &str) -> Result<(), IamError> {
            iam::svid::verify_hybrid_jwt_svid(
                token,
                expected_audience,
                &self.svid.ed25519_pk,
                &self.svid.mldsa65_pk,
                true,
            )
            .map(|_| ())
        }
        fn key_hierarchy(&self) -> &KeyHierarchy {
            unimplemented!()
        }
        fn sign_audit_sth(
            &self,
            _: u64,
            _: i64,
            _: &[u8; 32],
        ) -> Result<iam::ca::AuditSthSignature, IamError> {
            unimplemented!()
        }
        fn verify_audit_sth(&self, _: &iam::ca::AuditSthSignature) -> Result<(), IamError> {
            unimplemented!()
        }
    }

    let _verifier = DummyVerifier { svid };

    let _verified_grant = registry
        .verify_scoped_tunnel_token(&grant, chrono::Utc::now().timestamp_millis())
        .unwrap();
    // verified_grant returns nothing now
    assert_eq!(grant.service_name, "api.stripe.com");
}

#[test]
fn test_key_hierarchy() {
    let mut kek = [0u8; 32];
    #[allow(clippy::needless_range_loop)]
    for i in 0..32 {
        kek[i] = i as u8;
    }
    let kh = KeyHierarchy::new(kek);

    let mut epoch_salt = [0u8; 32];
    epoch_salt[0] = 1;
    let mut thread_salt = [0u8; 32];
    thread_salt[0] = 2;

    let _dek = kh
        .derive_thread_dek("t1", 1, &epoch_salt, &thread_salt)
        .unwrap();

    kh.crypto_shred_thread("t1");
    let result = kh.derive_thread_dek("t1", 1, &epoch_salt, &thread_salt);
    assert!(result.is_err());
}

use iam::spiffe::SpiffeId;
use base::typemap::{StateExtensionMap, DefaultExtensionRegistryImpl, register_slot};
use iam::WorkloadIdentitySlot;

#[test]
fn test_spiffe_parsing() {
    let s = SpiffeId::parse("spiffe://example.org/agent/agent1/task/task1");
    assert!(s.is_ok());
    let s = s.unwrap();
    assert_eq!(s.workload_path(), "agent/agent1/task/task1");

    // test child derivation
    let c = s.derive_subagent("sub1", "task2");
    assert!(c.is_ok());
    let c = c.unwrap();
    assert_eq!(c.workload_path(), "agent/agent1/task/task1/subagent/sub1/task/task2");

    // test traversal rejection
    let bad_c = s.derive_subagent("../sub1", "task2");
    assert!(matches!(bad_c, Err(IamError::InvalidSpiffeId(_))));

    let bad_c2 = s.derive_subagent("sub1", "/task2");
    assert!(matches!(bad_c2, Err(IamError::InvalidSpiffeId(_))));

    // Test hierarchy violation
    // A manually created SpiffeId that doesn't share the same root path
    let parent = SpiffeId::parse("spiffe://example.org/agent/agent1/task/task1").unwrap();
    let not_child = SpiffeId::parse("spiffe://example.org/agent/agent2/task/task1").unwrap();
    let err = parent.verify_attenuation(&not_child);
    assert!(matches!(err, Err(IamError::HierarchyViolation { .. })));
}

#[test]
fn test_pq_custom_extension() {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let subject_ed_sk = ed25519_dalek::SigningKey::from_bytes(&secret);
    let subject_ed_pub = subject_ed_sk.verifying_key().to_bytes();

    let mut seed1 = [0u8; 32];
    OsRng.fill_bytes(&mut seed1);
    let subject_ml_sk = ml_dsa::SigningKey::<MlDsa65>::from_seed((&seed1).into());
    let subject_ml_pk = subject_ml_sk.verifying_key().to_bytes().to_vec();

    let mut seed2 = [0u8; 32];
    OsRng.fill_bytes(&mut seed2);
    let issuer_ml_sk = ml_dsa::SigningKey::<MlDsa65>::from_seed((&seed2).into());
    let issuer_ml_pkcs8 = issuer_ml_sk.to_pkcs8_der().unwrap().as_bytes().to_vec();
    let _issuer_ml_spki = issuer_ml_sk.verifying_key().to_public_key_der().unwrap().as_bytes().to_vec();

    let mut pk_arr = [0u8; 1952];
    let spki_bytes = issuer_ml_sk.verifying_key().to_bytes();
    pk_arr.copy_from_slice(&spki_bytes);

    let digest = iam::pq_ext::compute_pre_tbs_pq_digest(
        &[1, 2, 3],
        "O=Issuer",
        "spiffe://example.org/agent/agent1/task/task1",
        0,
        3600,
        false,
        &subject_ed_pub,
        &subject_ml_pk,
    );

    let ext = iam::pq_ext::build_pq_custom_extension(
        subject_ml_pk.clone(),
        &issuer_ml_pkcs8,
        digest,
    ).unwrap();

    assert_eq!(ext.oid_components().collect::<Vec<_>>(), iam::pq_ext::PQ_MDSA65_EXT_OID);

    let payload = iam::pq_ext::verify_pq_custom_extension(
        ext.content(),
        &digest,
        &pk_arr,
    ).unwrap();

    assert_eq!(payload.subject_mldsa65_pk, subject_ml_pk);

    // Corrupt one bit
    let _orig = ext.content()[ext.content().len() - 1];
    let mut bad_content = ext.content().to_vec();
    bad_content[ext.content().len() - 1] ^= 1;
    let err = iam::pq_ext::verify_pq_custom_extension(
        &bad_content,
        &digest,
        &pk_arr,
    );
    assert!(matches!(err, Err(IamError::PqSignatureVerificationFailed)));
}

#[test]
fn test_workload_identity_slot() {
    let mut map = StateExtensionMap::new();
    let slot = WorkloadIdentitySlot {
        spiffe_id_uri: "spiffe://example.org/agent/agent1/task/task1".to_string(),
        trust_domain: "example.org".to_string(),
        expires_at_ms: 1234567890,
        traceparent: None,
    };

    map.insert(slot.clone());

    let mut registry = DefaultExtensionRegistryImpl::new();
    register_slot::<WorkloadIdentitySlot>(&mut registry);

    let serialized = map.serialize_all().unwrap();
    let mut hydrated = StateExtensionMap::new();

    hydrated.hydrate_all(&serialized, &registry).unwrap();

    let recovered = hydrated.get::<WorkloadIdentitySlot>().unwrap();
    assert_eq!(recovered.spiffe_id_uri, slot.spiffe_id_uri);
    assert_eq!(recovered.trust_domain, slot.trust_domain);
    assert_eq!(recovered.expires_at_ms, slot.expires_at_ms);
}
