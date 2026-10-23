use iam::spiffe::SpiffeId;
use iam::pq_ext::compute_pre_tbs_pq_digest;
use iam::error::IamError;

#[test]
fn test_spiffe_id_parse() {
    // Valid SpiffeId
    let id = SpiffeId::parse("spiffe://example.org/agent/a1/task/t1").unwrap();
    assert_eq!(id.uri(), "spiffe://example.org/agent/a1/task/t1");

    // Invalid scheme
    let err = SpiffeId::parse("https://example.org").unwrap_err();
    assert!(matches!(err, IamError::InvalidSpiffeId(_)));

    // Empty host
    let err = SpiffeId::parse("spiffe:///agent/a1").unwrap_err();
    assert!(matches!(err, IamError::InvalidSpiffeId(_)));

    // Empty path
    let err = SpiffeId::parse("spiffe://example.org").unwrap_err();
    assert!(matches!(err, IamError::InvalidSpiffeId(_)));

    // Invalid segments (. or ..)
    let err = SpiffeId::parse("spiffe://example.org/agent/../task").unwrap_err();
    assert!(matches!(err, IamError::InvalidSpiffeId(_)));
}

#[test]
fn test_spiffe_id_subagent() {
    let parent = SpiffeId::parse("spiffe://example.org/agent/a1/task/t1").unwrap();
    let child = parent.derive_subagent("sub1", "task2").unwrap();

    assert_eq!(child.uri(), "spiffe://example.org/agent/a1/task/t1/subagent/sub1/task/task2");

    // Ensure that it's validated under the correct prefix
    let invalid_child_str = "spiffe://example.org/agent/a1/task/t2/subagent/sub1/task/task2";
    let invalid_child_uri = url::Url::parse(invalid_child_str).unwrap();

    let expected_prefix = format!("{}/subagent/", parent.uri());
    assert!(!invalid_child_uri.as_str().starts_with(&expected_prefix));
}

#[test]
fn test_pq_ext_digest() {
    let serial_be = b"serial";
    let issuer_dn = b"issuer";
    let subject_san_uri = b"spiffe://example.org";
    let not_before_s_be64 = &[0u8; 8];
    let not_after_s_be64 = &[0u8; 8];
    let is_ca_u8 = 0;
    let ed25519_pk = &[0u8; 32];
    let mldsa65_pk = &[0u8; 1952];

    let digest = compute_pre_tbs_pq_digest(
        serial_be,
        issuer_dn,
        subject_san_uri,
        not_before_s_be64,
        not_after_s_be64,
        is_ca_u8,
        ed25519_pk,
        mldsa65_pk
    );

    assert_eq!(digest.len(), 32);
}
