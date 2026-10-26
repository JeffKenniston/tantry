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
    let db = DbHandle::new(tmp.to_str().unwrap(), ddl).expect("DbHandle new");

    // Writer initialized
    let conn = db.writer.lock().unwrap();
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .unwrap();
    assert_eq!(mode.to_lowercase(), "wal");

    // Can open reader
    let reader = db.get_reader().unwrap();
    let mut stmt = reader.prepare("SELECT * FROM test").unwrap();
    let _ = stmt.query([]).unwrap();
}

#[test]
fn test_checkpoint_encryption() {
    let dek = [1u8; 32];
    let aad = compute_canonical_aad("test", "pk1", "thread1", 1);

    let plaintext = b"Hello, time travel!";
    let encrypted = encrypt_envelope_xchacha20(plaintext, &dek, &aad).unwrap();

    // Verify successful decryption
    let decrypted = decrypt_envelope(&encrypted, &dek, &aad).unwrap();
    assert_eq!(plaintext, decrypted.as_slice());

    // Swapping blobs (using wrong AAD) fails canonical AAD verification 100% of the time
    let wrong_aad = compute_canonical_aad("test", "pk2", "thread1", 1);
    let result = decrypt_envelope(&encrypted, &dek, &wrong_aad);
    assert!(matches!(result, Err(DataError::AadMismatch)));
}

#[test]
fn test_crypto_shred_thread() {
    let tmp = std::env::temp_dir().join("test_shred.sqlite");
    let _ = std::fs::remove_file(&tmp);
    let ddl = "CREATE TABLE key_epochs (thread_id TEXT, key_epoch INTEGER, epoch_salt BLOB, thread_salt BLOB, shredded INTEGER);";
    let db = DbHandle::new(tmp.to_str().unwrap(), ddl).unwrap();

    let mut writer = db.writer.lock().unwrap();
    let thread_id = "shred_thread";

    // Provision
    let _ = get_or_provision_key_epoch(&writer, thread_id, 1).unwrap();

    // Shred
    let kh = KeyHierarchy::new([0u8; 32]);
    crypto_shred_thread(&mut writer, thread_id, &kh).unwrap();

    // Attempting to read after shredding should fail
    let result = get_or_provision_key_epoch(&writer, thread_id, 1);
    assert!(matches!(result, Err(DataError::CryptoShredded(id)) if id == thread_id));
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

    let w = mmr.db.lock().unwrap();
    w.execute("INSERT INTO audit_signed_tree_heads (tree_size, timestamp_ms, mmr_root_blake3, ed25519_sig, mldsa65_sig) VALUES (?1, ?2, ?3, ?4, ?5)",
              rusqlite::params![sth.tree_size as i64, sth.timestamp_ms as i64, sth.mmr_root_blake3.as_slice(), sth.ed25519_sig.as_slice(), sth.mldsa65_sig.as_slice()]).unwrap();
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
    let w = mmr.db.lock().unwrap();
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
    let res = store.search(&query, 10, -1.0).unwrap();

    assert!(!res.is_empty());
}
