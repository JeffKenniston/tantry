use crate::error::IamError;
use rand::RngCore;
use std::env;
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;
use serde::{Serialize, Deserialize};
use base64::Engine as _;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditSthSignature {
    pub tree_size: u64,
    pub timestamp_ms: i64,
    pub mmr_root_blake3: [u8; 32],
    pub ed25519_sig: Vec<u8>,
    pub mldsa65_sig: Vec<u8>,
}

#[allow(dead_code)]
pub struct SovereignCaIdentityManager {
    master_key: Zeroizing<[u8; 32]>,
}

impl SovereignCaIdentityManager {
    pub fn new(master_key: [u8; 32]) -> Self {
        Self {
            master_key: Zeroizing::new(master_key),
        }
    }
}

pub fn acquire_or_init_master_key(data_dir: &Path) -> Result<Zeroizing<[u8; 32]>, IamError> {
    if let Ok(env_key) = env::var("TANTRY_MASTER_KEY") {
        let mut key = [0u8; 32];
        if env_key.len() == 64 {
            if let Ok(decoded) = hex::decode(&env_key) {
                key.copy_from_slice(&decoded[0..32]);
                return Ok(Zeroizing::new(key));
            }
        } else if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&env_key) {
             if decoded.len() == 32 {
                 key.copy_from_slice(&decoded);
                 return Ok(Zeroizing::new(key));
             }
        }
    }

    let keystore_path = data_dir.join(".keystore_master.sealed");
    if keystore_path.exists() {
        return Err(IamError::MasterKeyUnavailable);
    }

    let seed_path = data_dir.join(".master_key.seed");
    if seed_path.exists() {
        if let Ok(contents) = fs::read(&seed_path) {
            if contents.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&contents);
                return Ok(Zeroizing::new(key));
            }
        }
        return Err(IamError::MasterKeyUnavailable);
    }

    let mut new_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut new_key);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).mode(0o600);
        if let Ok(mut file) = options.open(&seed_path) {
            use std::io::Write;
            if file.write_all(&new_key).is_err() {
                return Err(IamError::MasterKeyUnavailable);
            }
        }
    }

    #[cfg(not(unix))]
    {
        if fs::write(&seed_path, &new_key).is_err() {
             return Err(IamError::MasterKeyUnavailable);
        }
    }

    Ok(Zeroizing::new(new_key))
}

pub fn compute_sth_digest(tree_size: u64, timestamp_ms: i64, mmr_root_blake3: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"tantry:audit:sth:v3");
    hasher.update(&tree_size.to_be_bytes());
    hasher.update(&timestamp_ms.to_be_bytes());
    hasher.update(mmr_root_blake3);
    hasher.finalize().into()
}

pub fn sign_audit_sth(
    tree_size: u64,
    timestamp_ms: i64,
    mmr_root_blake3: [u8; 32],
    ed25519_pkcs8_der: &[u8],
    mldsa65_signing_key_bytes: &[u8],
) -> Result<AuditSthSignature, IamError> {
    let digest = compute_sth_digest(tree_size, timestamp_ms, &mmr_root_blake3);

    use ed25519_dalek::{Signer, SigningKey};
    use ed25519_dalek::pkcs8::DecodePrivateKey;

    let ed_sk = SigningKey::from_pkcs8_der(ed25519_pkcs8_der)
        .map_err(|e| IamError::CertificateGenerationError(e.to_string()))?;
    let ed25519_sig = ed_sk.sign(&digest).to_bytes().to_vec();

    use ml_dsa::MlDsa65;
    use ml_dsa::SignatureEncoding;

    let ml_sk = ml_dsa::SigningKey::<MlDsa65>::from_pkcs8_der(mldsa65_signing_key_bytes)
        .map_err(|_| IamError::CertificateGenerationError("invalid mldsa65 secret key".to_string()))?;

    let mldsa65_sig = ml_sk.sign(&digest).to_bytes().to_vec();

    Ok(AuditSthSignature {
        tree_size,
        timestamp_ms,
        mmr_root_blake3,
        ed25519_sig,
        mldsa65_sig,
    })
}

pub fn verify_audit_sth(
    sth: &AuditSthSignature,
    ed25519_public_key: &[u8; 32],
    mldsa65_verifying_key_bytes: &[u8],
) -> Result<(), IamError> {
    let digest = compute_sth_digest(sth.tree_size, sth.timestamp_ms, &sth.mmr_root_blake3);

    use ed25519_dalek::{Verifier, VerifyingKey, Signature};
    let ed_vk = VerifyingKey::from_bytes(ed25519_public_key)
        .map_err(|_| IamError::Ed25519VerificationFailed)?;
    let ed_sig = Signature::from_slice(&sth.ed25519_sig)
        .map_err(|_| IamError::Ed25519VerificationFailed)?;

    ed_vk.verify(&digest, &ed_sig)
        .map_err(|_| IamError::Ed25519VerificationFailed)?;

    use ml_dsa::MlDsa65;
    use ml_dsa::pkcs8::DecodePublicKey;

    let ml_vk = ml_dsa::VerifyingKey::<MlDsa65>::from_public_key_der(mldsa65_verifying_key_bytes)
        .map_err(|_| IamError::PqSignatureVerificationFailed)?;

    if sth.mldsa65_sig.len() != 3309 {
         return Err(IamError::PqSignatureVerificationFailed);
    }
    let mut sig_array = [0u8; 3309];
    sig_array.copy_from_slice(&sth.mldsa65_sig);

    let pq_sig = ml_dsa::Signature::<MlDsa65>::decode((&sig_array).into()).ok_or(IamError::PqSignatureVerificationFailed)?;

    ml_vk.verify(&digest, &pq_sig)
        .map_err(|_| IamError::PqSignatureVerificationFailed)?;

    Ok(())
}
