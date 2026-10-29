use ml_dsa::KeyExport;
use ml_dsa::SignatureEncoding;
use ml_dsa::signature::Verifier;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorInclusionProof {
    pub log_index: u64,
    pub tree_size: u64,
    pub root_hash_hex: String,
    pub hashes_hex: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorTransparencyLogEntry {
    pub integrated_time: i64,
    pub canonicalized_body_b64: String,
    pub inclusion_proof: RekorInclusionProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FulcioCertificateDescriptor {
    pub leaf_cert_der_b64: Option<String>,
    pub subject_public_key_ed25519_hex: String,
    pub issuer_signature_ed25519_hex: String,
    pub oidc_issuer: String,
    pub san_uri: String,
    pub not_before: i64,
    pub not_after: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigstoreBundle {
    pub media_type: String,
    pub artifact_blake3_hex: String,
    pub artifact_sha256_hex: String,
    pub signature_ed25519_hex: String,
    pub fulcio_cert: FulcioCertificateDescriptor,
    pub rekor_entry: RekorTransparencyLogEntry,
    pub pq_public_key_mldsa65_b64: Option<String>,
    pub pq_signature_mldsa65_b64: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigstoreVerificationReport {
    pub artifact_blake3: [u8; 32],
    pub artifact_sha256: [u8; 32],
    pub oidc_issuer: String,
    pub san_uri: String,
    pub rekor_log_index: u64,
    pub integrated_time: i64,
    pub pq_verified: bool,
}

pub fn build_fulcio_leaf_transcript(
    subject_public_key_ed25519_bytes: &[u8; 32],
    oidc_issuer: &str,
    san_uri: &str,
    not_before: i64,
    not_after: i64,
) -> Vec<u8> {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"tantry:fulcio:leaf:v3:");
    transcript.extend_from_slice(subject_public_key_ed25519_bytes);
    transcript.extend_from_slice(b":");
    transcript.extend_from_slice(oidc_issuer.as_bytes());
    transcript.extend_from_slice(b":");
    transcript.extend_from_slice(san_uri.as_bytes());
    transcript.extend_from_slice(b":");
    transcript.extend_from_slice(&not_before.to_be_bytes());
    transcript.extend_from_slice(&not_after.to_be_bytes());
    transcript
}

pub fn build_hybrid_pq_signing_transcript(
    artifact_blake3_32: &[u8; 32],
    artifact_sha256_32: &[u8; 32],
) -> Vec<u8> {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"tantry:sigstore:pq:v3:");
    transcript.extend_from_slice(artifact_blake3_32);
    transcript.extend_from_slice(artifact_sha256_32);
    transcript
}

use crate::error::ProfileError;
use sha2::{Digest, Sha256};

pub fn verify_rfc6962_inclusion_proof(
    leaf_bytes: &[u8],
    log_index: u64,
    tree_size: u64,
    proof_hashes: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> Result<(), ProfileError> {
    if tree_size == 0 || log_index >= tree_size {
        return Err(ProfileError::SigstoreMerkleProofInvalid(
            "log_index out of bounds".into(),
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(leaf_bytes);
    let mut r: [u8; 32] = hasher.finalize().into();

    let mut fn_idx = log_index;
    let mut sn = tree_size - 1;

    for p in proof_hashes {
        if sn == 0 {
            return Err(ProfileError::SigstoreMerkleProofInvalid(
                "proof too long; sn reached 0 early".into(),
            ));
        }

        if (fn_idx & 1) == 1 || fn_idx == sn {
            let mut hasher = Sha256::new();
            hasher.update([0x01]);
            hasher.update(p);
            hasher.update(r);
            r = hasher.finalize().into();

            while (fn_idx & 1) == 0 && fn_idx != 0 {
                fn_idx >>= 1;
                sn >>= 1;
            }
        } else {
            let mut hasher = Sha256::new();
            hasher.update([0x01]);
            hasher.update(r);
            hasher.update(p);
            r = hasher.finalize().into();
        }
        fn_idx >>= 1;
        sn >>= 1;
    }

    if sn != 0 || r != *expected_root {
        return Err(ProfileError::SigstoreMerkleProofInvalid(
            "computed root hash mismatch".into(),
        ));
    }

    Ok(())
}

pub struct SigstoreVerifier {
    pub trusted_fulcio_root_pk: [u8; 32],
    pub expected_oidc_issuer: Option<String>,
}

impl SigstoreVerifier {
    pub fn verify_bundle(
        &self,
        artifact_bytes: &[u8],
        bundle_json: &str,
        require_pq: bool,
    ) -> Result<SigstoreVerificationReport, ProfileError> {
        let bundle: SigstoreBundle = serde_json::from_str(bundle_json)
            .map_err(|e| ProfileError::SigstoreBundleParseError(e.to_string()))?;

        // Stage 1
        let actual_blake3_arr = *blake3::hash(artifact_bytes).as_bytes();
        let mut hasher = Sha256::new();
        hasher.update(artifact_bytes);
        let actual_sha256_arr: [u8; 32] = hasher.finalize().into();

        let bundle_blake3 = hex::decode(&bundle.artifact_blake3_hex).map_err(|_| {
            ProfileError::SigstoreDigestMismatch {
                expected: "hex".into(),
                actual: "invalid".into(),
            }
        })?;
        let bundle_sha256 = hex::decode(&bundle.artifact_sha256_hex).map_err(|_| {
            ProfileError::SigstoreDigestMismatch {
                expected: "hex".into(),
                actual: "invalid".into(),
            }
        })?;

        if bundle_blake3 != actual_blake3_arr || bundle_sha256 != actual_sha256_arr {
            return Err(ProfileError::SigstoreDigestMismatch {
                expected: bundle.artifact_blake3_hex,
                actual: hex::encode(actual_blake3_arr),
            });
        }

        // Stage 2
        if let Some(ref der_b64) = bundle.fulcio_cert.leaf_cert_der_b64 {
            let der_bytes =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, der_b64)
                    .map_err(|_| ProfileError::SigstoreCertificateInvalid("invalid b64".into()))?;
            x509_parser::parse_x509_certificate(&der_bytes)
                .map_err(|_| ProfileError::SigstoreCertificateInvalid("invalid der".into()))?;
        }

        let san = &bundle.fulcio_cert.san_uri;
        if !(san.starts_with("spiffe://") || san.starts_with("https://") || san.contains('@')) {
            return Err(ProfileError::SigstoreCertificateInvalid(
                "invalid SAN URI".into(),
            ));
        }
        if let Some(ref expected) = self.expected_oidc_issuer {
            if &bundle.fulcio_cert.oidc_issuer != expected {
                return Err(ProfileError::SigstoreCertificateInvalid(
                    "issuer mismatch".into(),
                ));
            }
        }

        let leaf_pub_hex = hex::decode(&bundle.fulcio_cert.subject_public_key_ed25519_hex)
            .map_err(|_| ProfileError::SigstoreCertificateInvalid("invalid leaf pub hex".into()))?;
        let mut leaf_pub = [0u8; 32];
        if leaf_pub_hex.len() != 32 {
            return Err(ProfileError::SigstoreCertificateInvalid(
                "leaf pub wrong len".into(),
            ));
        }
        leaf_pub.copy_from_slice(&leaf_pub_hex);

        let transcript = build_fulcio_leaf_transcript(
            &leaf_pub,
            &bundle.fulcio_cert.oidc_issuer,
            &bundle.fulcio_cert.san_uri,
            bundle.fulcio_cert.not_before,
            bundle.fulcio_cert.not_after,
        );

        let fulcio_root_key = ed25519_dalek::VerifyingKey::from_bytes(&self.trusted_fulcio_root_pk)
            .map_err(|_| ProfileError::SigstoreCertificateInvalid("invalid root pk".into()))?;
        let issuer_sig_hex = hex::decode(&bundle.fulcio_cert.issuer_signature_ed25519_hex)
            .map_err(|_| {
                ProfileError::SigstoreCertificateInvalid("invalid issuer sig hex".into())
            })?;
        let issuer_sig = ed25519_dalek::Signature::from_slice(&issuer_sig_hex).map_err(|_| {
            ProfileError::SigstoreCertificateInvalid("invalid issuer sig len".into())
        })?;
        fulcio_root_key
            .verify_strict(&transcript, &issuer_sig)
            .map_err(|_| {
                ProfileError::SigstoreCertificateInvalid("issuer sig verify failed".into())
            })?;

        let leaf_key = ed25519_dalek::VerifyingKey::from_bytes(&leaf_pub)
            .map_err(|_| ProfileError::SigstoreCertificateInvalid("invalid leaf key".into()))?;
        let art_sig_hex = hex::decode(&bundle.signature_ed25519_hex)
            .map_err(|_| ProfileError::SigstoreSignatureInvalid("invalid art sig hex".into()))?;
        let art_sig = ed25519_dalek::Signature::from_slice(&art_sig_hex)
            .map_err(|_| ProfileError::SigstoreSignatureInvalid("invalid art sig len".into()))?;
        leaf_key
            .verify_strict(artifact_bytes, &art_sig)
            .map_err(|_| ProfileError::SigstoreSignatureInvalid("art sig verify failed".into()))?;

        // Stage 3
        let it = bundle.rekor_entry.integrated_time;
        if it < bundle.fulcio_cert.not_before || it > bundle.fulcio_cert.not_after {
            return Err(ProfileError::SigstoreTimestampOutOfRange {
                integrated_time: it,
                not_before: bundle.fulcio_cert.not_before,
                not_after: bundle.fulcio_cert.not_after,
            });
        }

        // Stage 4
        let can_body = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &bundle.rekor_entry.canonicalized_body_b64,
        )
        .map_err(|_| ProfileError::SigstoreMerkleProofInvalid("invalid can_body b64".into()))?;
        let can_body_str = String::from_utf8(can_body).map_err(|_| {
            ProfileError::SigstoreMerkleProofInvalid("invalid can_body utf8".into())
        })?;
        if !can_body_str.contains(&hex::encode(actual_sha256_arr)) {
            return Err(ProfileError::SigstoreMerkleProofInvalid(
                "rekor missing sha256".into(),
            ));
        }

        let mut root_hash = [0u8; 32];
        let root_hex =
            hex::decode(&bundle.rekor_entry.inclusion_proof.root_hash_hex).map_err(|_| {
                ProfileError::SigstoreMerkleProofInvalid("invalid root_hash hex".into())
            })?;
        if root_hex.len() != 32 {
            return Err(ProfileError::SigstoreMerkleProofInvalid(
                "invalid root len".into(),
            ));
        }
        root_hash.copy_from_slice(&root_hex);

        let mut hashes = Vec::new();
        for h in &bundle.rekor_entry.inclusion_proof.hashes_hex {
            let hb = hex::decode(h)
                .map_err(|_| ProfileError::SigstoreMerkleProofInvalid("invalid hash hex".into()))?;
            if hb.len() != 32 {
                return Err(ProfileError::SigstoreMerkleProofInvalid(
                    "invalid hash len".into(),
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hb);
            hashes.push(arr);
        }

        let leaf_can = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &bundle.rekor_entry.canonicalized_body_b64,
        )
        .unwrap(); // We just parsed it successfully

        verify_rfc6962_inclusion_proof(
            &leaf_can,
            bundle.rekor_entry.inclusion_proof.log_index,
            bundle.rekor_entry.inclusion_proof.tree_size,
            &hashes,
            &root_hash,
        )?;

        // Stage 5
        let mut pq_verified = false;
        if let (Some(pk_b64), Some(sig_b64)) = (
            &bundle.pq_public_key_mldsa65_b64,
            &bundle.pq_signature_mldsa65_b64,
        ) {
            let pk_bytes =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, pk_b64)
                    .map_err(|_| ProfileError::SigstorePqSignatureInvalid("b64 pk".into()))?;
            let sig_bytes =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig_b64)
                    .map_err(|_| ProfileError::SigstorePqSignatureInvalid("b64 sig".into()))?;

            if pk_bytes.len() != 1952 {
                return Err(ProfileError::SigstorePqSignatureInvalid(
                    "pk len != 1952".into(),
                ));
            }
            if sig_bytes.len() != 3309 {
                return Err(ProfileError::SigstorePqSignatureInvalid(
                    "sig len != 3309".into(),
                ));
            }

            let transcript =
                build_hybrid_pq_signing_transcript(&actual_blake3_arr, &actual_sha256_arr);

            let pk_arr: &[u8; 1952] = pk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| ProfileError::SigstorePqSignatureInvalid("invalid pk arr".into()))?;
            let sig_arr: &[u8; 3309] = sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| ProfileError::SigstorePqSignatureInvalid("invalid sig arr".into()))?;

            let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(pk_arr.into());

            let pq_sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(sig_arr.into()).ok_or(
                ProfileError::SigstorePqSignatureInvalid("decode fail".into()),
            )?;
            vk.verify(&transcript, &pq_sig)
                .map_err(|_| ProfileError::SigstorePqSignatureInvalid("pq verify failed".into()))?;

            pq_verified = true;
        } else if require_pq {
            return Err(ProfileError::SigstoreMissingPqSignature);
        }

        Ok(SigstoreVerificationReport {
            artifact_blake3: actual_blake3_arr,
            artifact_sha256: actual_sha256_arr,
            oidc_issuer: bundle.fulcio_cert.oidc_issuer.clone(),
            san_uri: bundle.fulcio_cert.san_uri.clone(),
            rekor_log_index: bundle.rekor_entry.inclusion_proof.log_index,
            integrated_time: bundle.rekor_entry.integrated_time,
            pq_verified,
        })
    }
}

impl SigstoreVerifier {
    #[allow(clippy::too_many_arguments)]
    pub fn sign_artifact_bundle(
        artifact_bytes: &[u8],
        oidc_issuer: &str,
        san_uri: &str,
        not_before: i64,
        not_after: i64,
        fulcio_root_sk: &ed25519_dalek::SigningKey,
        leaf_sk: &ed25519_dalek::SigningKey,
        pq_sk: Option<&ml_dsa::SigningKey<ml_dsa::MlDsa65>>,
    ) -> Result<String, ProfileError> {
        use ed25519_dalek::{Signer, VerifyingKey};

        let actual_blake3_arr = *blake3::hash(artifact_bytes).as_bytes();
        let mut hasher = Sha256::new();
        hasher.update(artifact_bytes);
        let actual_sha256_arr: [u8; 32] = hasher.finalize().into();

        let leaf_vk = VerifyingKey::from(leaf_sk);
        let transcript = build_fulcio_leaf_transcript(
            leaf_vk.as_bytes(),
            oidc_issuer,
            san_uri,
            not_before,
            not_after,
        );

        let issuer_sig = fulcio_root_sk.sign(&transcript);
        let art_sig = leaf_sk.sign(artifact_bytes);

        // create fake rekor log using the sha256 inclusion
        let mut leaf_can = String::new();
        leaf_can.push_str(&hex::encode(actual_sha256_arr));

        let mut hasher = Sha256::new();
        hasher.update([0x00]);
        hasher.update(leaf_can.as_bytes());
        let root_hash: [u8; 32] = hasher.finalize().into();

        let mut pq_pub = None;
        let mut pq_sig = None;

        if let Some(pq) = pq_sk {
            use ml_dsa::signature::Keypair;
            use ml_dsa::signature::Signer as PqSigner;

            let pq_vk = pq.verifying_key();
            // MLDsa65 verifying key is 1952 bytes. EncodedVerifyingKey is the raw bytes.

            let raw_vk_bytes = pq_vk.to_bytes();
            pq_pub = Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                raw_vk_bytes.as_slice(),
            ));

            let pq_transcript =
                build_hybrid_pq_signing_transcript(&actual_blake3_arr, &actual_sha256_arr);
            let sig = pq.sign(&pq_transcript);
            pq_sig = Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                sig.to_bytes().as_slice(),
            ));
        }

        let bundle = SigstoreBundle {
            media_type: "application/vnd.dev.sigstore.bundle+json;version=0.1".into(),
            artifact_blake3_hex: hex::encode(actual_blake3_arr),
            artifact_sha256_hex: hex::encode(actual_sha256_arr),
            signature_ed25519_hex: hex::encode(art_sig.to_bytes()),
            fulcio_cert: FulcioCertificateDescriptor {
                leaf_cert_der_b64: None,
                subject_public_key_ed25519_hex: hex::encode(leaf_vk.as_bytes()),
                issuer_signature_ed25519_hex: hex::encode(issuer_sig.to_bytes()),
                oidc_issuer: oidc_issuer.into(),
                san_uri: san_uri.into(),
                not_before,
                not_after,
            },
            rekor_entry: RekorTransparencyLogEntry {
                integrated_time: not_before + 1,
                canonicalized_body_b64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    leaf_can.as_bytes(),
                ),
                inclusion_proof: RekorInclusionProof {
                    log_index: 0,
                    tree_size: 1,
                    root_hash_hex: hex::encode(root_hash),
                    hashes_hex: vec![],
                },
            },
            pq_public_key_mldsa65_b64: pq_pub,
            pq_signature_mldsa65_b64: pq_sig,
        };

        serde_json::to_string(&bundle)
            .map_err(|e| ProfileError::SigstoreBundleParseError(e.to_string()))
    }
}
