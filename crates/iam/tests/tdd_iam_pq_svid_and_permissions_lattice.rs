use iam::KeyHierarchy;

#[test]
fn test_key_hierarchy() {
    let mut kek = [0u8; 32];
    for i in 0..32 { kek[i] = i as u8; }
    let kh = KeyHierarchy::new(kek);

    let mut epoch_salt = [0u8; 32];
    epoch_salt[0] = 1;
    let mut thread_salt = [0u8; 32];
    thread_salt[0] = 2;

    let _dek = kh.derive_dek_from_salts(1, &epoch_salt, "t1", &thread_salt).unwrap();

    kh.crypto_shred_thread("t1");
    let result = kh.derive_dek_from_salts(1, &epoch_salt, "t1", &thread_salt);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_sovereign_ca_and_audits() {
    // Tests for Phase 3 requirements.
}
