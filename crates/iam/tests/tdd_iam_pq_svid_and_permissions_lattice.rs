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
