use data::db::DbHandle;
use data::crypto::*;
use data::error::DataError;
use iam::key_hierarchy::KeyHierarchy;

#[test]
fn test_writer_first_dbhandle() {
    let tmp = std::env::temp_dir().join("test_writer.sqlite");
    let _ = std::fs::remove_file(&tmp);
    let ddl = "CREATE TABLE test(id INTEGER PRIMARY KEY);";
    let db = DbHandle::new(tmp.to_str().unwrap(), ddl).expect("DbHandle new");

    // Writer initialized
    let conn = db.writer.lock().unwrap();
    let mode: String = conn.pragma_query_value(None, "journal_mode", |r| r.get(0)).unwrap();
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
