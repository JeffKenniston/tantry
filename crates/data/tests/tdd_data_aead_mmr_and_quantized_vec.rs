use data::interaction_chain::InteractionChainStore;
use base::typemap::{StateExtensionRegistry, StateExtensionMap};
use data::audit_mmr::AuditMmrStore;
use data::crypto::*;
use data::db::DbHandle;
use data::error::DataError;
use data::vector_index::MatryoshkaVectorStore;
use iam::key_hierarchy::KeyHierarchy;
use iam::{AuditSthSignature, IdentityManager};

#[test]
fn test_writer_first_dbhandle() {
    let tmp = std::env::temp_dir().join("test_writer.sqlite");
    let _ = std::fs::remove_file(&tmp);
    let ddl = "CREATE TABLE test(id INTEGER PRIMARY KEY);";
    let db = DbHandle::open(tmp.to_str().unwrap(), 4, &base::platform::RuntimePlatform::LinuxStandard, |conn| { conn.execute_batch(ddl)?; Ok(()) }).expect("DbHandle new");

    // Writer initialized
    let conn = db.writer.lock();
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |r: &rusqlite::Row| r.get(0))
        .unwrap();
    assert_eq!(mode.to_lowercase(), "wal");

    // Can open reader
    db.with_reader(|reader| {
        let mut stmt = reader.prepare("SELECT * FROM test").unwrap();
        let _ = stmt.query([]).unwrap();
        Ok(())
    }).unwrap();
}

#[test]
fn test_checkpoint_encryption() {
    let dek = [1u8; 32];
    let aad = compute_canonical_aad("test", "pk1", "thread1", 1);

    let plaintext = b"Hello, time travel!";
    let encrypted = encrypt_envelope(plaintext, &dek, &aad, AeadCipherSuite::default()).unwrap();

    // Verify successful decryption
    let decrypted = decrypt_envelope(&encrypted, &dek, &aad).unwrap();
    assert_eq!(plaintext, decrypted.as_slice());

    // Swapping blobs (using wrong AAD) fails canonical AAD verification 100% of the time
    let wrong_aad = compute_canonical_aad("test", "pk2", "thread1", 1);
    let result = decrypt_envelope(&encrypted, &dek, &wrong_aad);
    assert!(matches!(result, Err(DataError::AeadDecryptionFailed { .. })));
}

#[test]
fn test_crypto_shred_thread() {
    let tmp = std::env::temp_dir().join("test_shred.sqlite");
    let _ = std::fs::remove_file(&tmp);
    let db = DbHandle::open(tmp.to_str().unwrap(), 4, &base::platform::RuntimePlatform::LinuxStandard, |conn| { conn.execute_batch(KEY_EPOCH_DDL)?; Ok(()) }).unwrap();

    let store = KeyEpochStore::new(db.writer.clone());
    let thread_id = "shred_thread";
    let kh = KeyHierarchy::new([0u8; 32]);

    // Provision
    let _ = store.resolve_or_init_thread_dek(&kh, thread_id, 1).unwrap();

    // Shred
    store.crypto_shred_thread(&kh, thread_id).unwrap();

    // Attempting to read after shredding should fail
    let result = store.resolve_or_init_thread_dek(&kh, thread_id, 1);
    assert!(matches!(result, Err(DataError::KeyEpochShredded { thread_id, .. }) if thread_id == thread_id));
}

struct MockRegistry;
impl StateExtensionRegistry for MockRegistry {
    fn decode_and_insert(&self, _wire_key: &str, _codec_tag: u8, _payload: &[u8], _map: &mut StateExtensionMap) -> Result<(), base::error::ExtensionError> {
        Ok(())
    }
}

#[test]
fn test_interaction_chain_cross_thread_reconstruction() {
    let tmp = std::env::temp_dir().join("test_reconstruct.sqlite");
    let _ = std::fs::remove_file(&tmp);

    let store = InteractionChainStore::new(tmp.to_str().unwrap()).unwrap();
    let kh = KeyHierarchy::new([0u8; 32]);
    let registry = MockRegistry;

    let msg_delta = base::delta::MessageDelta::Append(vec![]);
    let file_deltas: Vec<base::delta::FileDelta> = vec![];
    let msg_delta_bytes = rmp_serde::to_vec_named(&msg_delta).unwrap();
    let file_deltas_bytes = rmp_serde::to_vec_named(&file_deltas).unwrap();

    // Step 1 on thread_main
    store.commit_checkpoint(
        "thread_main", 1, None, "cp_1", 1,
        Some(&msg_delta_bytes), Some(&file_deltas_bytes), None, None, None, &kh
    ).unwrap();

    // Step 2 on thread_main
    store.commit_checkpoint(
        "thread_main", 2, Some("cp_1"), "cp_2", 1,
        Some(&msg_delta_bytes), Some(&file_deltas_bytes), None, None, None, &kh
    ).unwrap();

    // Step 3 on thread_branch, branching from cp_2
    store.commit_checkpoint(
        "thread_branch", 3, Some("cp_2"), "cp_3", 1,
        Some(&msg_delta_bytes), Some(&file_deltas_bytes), None, None, None, &kh
    ).unwrap();

    // Reconstruct state at cp_3
    let reconstructed = store.reconstruct_state_at_checkpoint("cp_3", &registry, &kh).unwrap();

    // Verification details: reconstruct_state_at_checkpoint read cp_3, traversed to cp_2, then cp_1.
    // It decrypted cp_1 and cp_2 using thread_main DEK, and cp_3 using thread_branch DEK.
    // Since it didn't fail on decryption, it means it correctly used row.thread_id to get the DEK.

    assert_eq!(reconstructed.state.thread_id, "thread_branch");
    assert_eq!(reconstructed.state.step_index, 3);
    assert_eq!(reconstructed.state.last_checkpoint_id, Some("cp_3".to_string()));
}

struct MockIdentityManager;
impl IdentityManager for MockIdentityManager {
    fn key_hierarchy(&self) -> &iam::key_hierarchy::KeyHierarchy {
        unimplemented!()
    }
    fn sign_audit_sth(
        &self,
        tree_size: u64,
        timestamp_ms: i64,
        mmr_root_blake3: &[u8; 32],
    ) -> Result<AuditSthSignature, iam::error::IamError> {
        Ok(AuditSthSignature {
            tree_size,
            timestamp_ms,
            mmr_root_blake3: *mmr_root_blake3,
            ed25519_sig: vec![0; 64],
            mldsa65_sig: vec![0; 3309],
        })
    }
    fn verify_audit_sth(&self, _sth: &AuditSthSignature) -> Result<(), iam::error::IamError> {
        Ok(())
    }
}

#[test]
fn test_audit_mmr() {
    let mmr = AuditMmrStore::new("file:audit_test?mode=memory&cache=shared").unwrap();

    for i in 1..=1000 {
        mmr.append_entry(i, i * 1000, "spiffe://test", "thread1", "test", "{}")
            .unwrap();
    }

    // DDL already commits natively.
    let iam = MockIdentityManager;
    let sth = mmr.record_signed_tree_head(&iam).unwrap();
    assert_eq!(sth.tree_size, 1000);

    let w = mmr.db.lock();
    w.execute("INSERT INTO audit_signed_tree_heads (tree_size, timestamp_ms, mmr_root_blake3, ed25519_sig, mldsa65_sig) VALUES (?1, ?2, ?3, ?4, ?5)",
              rusqlite::params![sth.tree_size as i64, sth.timestamp_ms, sth.mmr_root_blake3.as_slice(), sth.ed25519_sig.as_slice(), sth.mldsa65_sig.as_slice()]).unwrap();
    drop(w);

    let proof1 = mmr.generate_inclusion_proof(1).unwrap();
    let proof2 = mmr.generate_consistency_proof(1, 1000).unwrap();
    assert!(AuditMmrStore::verify_inclusion_proof(&proof1, &[0u8; 32]));
    assert!(AuditMmrStore::verify_consistency_proof(
        &proof2, &[0u8; 32], &[0u8; 32]
    ));

    // Verify valid chain
    assert!(mmr.verify_all_chain_and_sths(&iam).is_ok());

    // Tamper test
    let w = mmr.db.lock();
    w.execute(
        "UPDATE audit_log SET payload_json = '{\"tampered\": true}' WHERE seq_no = 500",
        [],
    )
    .unwrap();
    drop(w);

    let res = mmr.verify_all_chain_and_sths(&iam);
    assert_eq!(res, Err(500));
}

#[test]
fn test_quantized_vec() {
    let store = MatryoshkaVectorStore::new("file:vec_test?mode=memory&cache=shared").unwrap();

    let vec1: Vec<f32> = vec![0.1, 0.2, 0.3, -0.4];
    let vec2: Vec<f32> = vec![-0.1, -0.2, -0.3, 0.4];

    store.insert_vector("v1", &vec1).unwrap();
    store.insert_vector("v2", &vec2).unwrap();

    let query: Vec<f32> = vec![0.1, 0.2, 0.3, 0.0];
    let res = store.search_top_k(&query, 10, -1.0).unwrap();

    assert!(!res.is_empty());
}
