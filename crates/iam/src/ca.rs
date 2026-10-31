use crate::error::IamError;
use base64::Engine as _;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    ed25519_pkcs8_der: Zeroizing<Vec<u8>>,
    ed25519_public_key: [u8; 32],
    mldsa65_signing_key_bytes: Zeroizing<Vec<u8>>,
    mldsa65_verifying_key_bytes: Vec<u8>,
    key_hierarchy: std::sync::Arc<crate::key_hierarchy::KeyHierarchy>,
}

impl SovereignCaIdentityManager {
    pub fn new(master_key: Zeroizing<[u8; 32]>, data_dir: &Path) -> Result<Self, IamError> {
        let sealed_path = data_dir.join("sovereign_ca.sealed");

        use chacha20poly1305::{
            KeyInit, XChaCha20Poly1305,
            aead::{Aead, AeadCore, Payload},
        };

        let cipher = XChaCha20Poly1305::new_from_slice(master_key.as_ref())
            .map_err(|_| IamError::MasterKeyUnavailable)?;

        let (
            ed25519_pkcs8_der,
            ed25519_public_key,
            mldsa65_signing_key_bytes,
            mldsa65_verifying_key_bytes,
        ) = if sealed_path.exists() {
            let sealed_data =
                std::fs::read(&sealed_path).map_err(|_| IamError::MasterKeyUnavailable)?;
            if sealed_data.len() < 24 {
                return Err(IamError::MasterKeyUnavailable);
            }
            let (nonce_bytes, ciphertext) = sealed_data.split_at(24);
            let nonce = chacha20poly1305::XNonce::from_slice(nonce_bytes);

            let payload = Payload {
                msg: ciphertext,
                aad: b"tantry:sovereign-ca:v3",
            };

            let plaintext = cipher
                .decrypt(nonce, payload)
                .map_err(|_| IamError::MasterKeyUnavailable)?;

            #[derive(Deserialize)]
            struct CaKeys {
                ed_priv: Vec<u8>,
                ed_pub: [u8; 32],
                ml_priv: Vec<u8>,
                ml_pub: Vec<u8>,
            }

            let keys: CaKeys =
                rmp_serde::from_slice(&plaintext).map_err(|_| IamError::MasterKeyUnavailable)?;
            (keys.ed_priv, keys.ed_pub, keys.ml_priv, keys.ml_pub)
        } else {
            use ed25519_dalek::SigningKey;

            let mut secret = [0u8; 32];
            OsRng.fill_bytes(&mut secret);
            let ed_sk = SigningKey::from_bytes(&secret);
            let ed_pub = ed_sk.verifying_key().to_bytes();

            let mut ed_pkcs8 = vec![
                0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
                0x04, 0x20,
            ];
            ed_pkcs8.extend_from_slice(&secret);
            let ed_priv = ed_pkcs8;

            use ml_dsa::MlDsa65;
            use ml_dsa::signature::Keypair;

            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);

            let ml_sk = ml_dsa::SigningKey::<MlDsa65>::from_seed((&seed).into());

            let ml_pk = ml_sk.verifying_key();

            use ml_dsa::pkcs8::{
                EncodePrivateKey as MlEncodePrivateKey, EncodePublicKey as MlEncodePublicKey,
            };
            let ml_pkcs8 = ml_sk
                .to_pkcs8_der()
                .map_err(|_| IamError::CertificateGenerationError("ml_dsa pkcs8 err".into()))?;
            let ml_priv = ml_pkcs8.to_bytes().to_vec();

            let ml_spki = ml_pk
                .to_public_key_der()
                .map_err(|_| IamError::CertificateGenerationError("ml_dsa spki err".into()))?;
            let ml_pub = ml_spki.to_vec();

            #[derive(Serialize)]
            struct CaKeys<'a> {
                ed_priv: &'a [u8],
                ed_pub: &'a [u8; 32],
                ml_priv: &'a [u8],
                ml_pub: &'a [u8],
            }
            let keys = CaKeys {
                ed_priv: &ed_priv,
                ed_pub: &ed_pub,
                ml_priv: &ml_priv,
                ml_pub: &ml_pub,
            };
            let plaintext = rmp_serde::to_vec_named(&keys)
                .map_err(|e| IamError::CertificateGenerationError(e.to_string()))?;

            let mut csprng2 = OsRng;
            let nonce = XChaCha20Poly1305::generate_nonce(&mut csprng2);
            let payload = Payload {
                msg: &plaintext,
                aad: b"tantry:sovereign-ca:v3",
            };

            let ciphertext = cipher
                .encrypt(&nonce, payload)
                .map_err(|_| IamError::MasterKeyUnavailable)?;

            let mut sealed_data = Vec::new();
            sealed_data.extend_from_slice(nonce.as_slice());
            sealed_data.extend_from_slice(&ciphertext);

            std::fs::write(&sealed_path, sealed_data)
                .map_err(|_| IamError::MasterKeyUnavailable)?;

            (ed_priv, ed_pub, ml_priv, ml_pub)
        };

        let kh = std::sync::Arc::new(crate::key_hierarchy::KeyHierarchy::new(
            master_key.as_ref().try_into().unwrap(),
        ));

        Ok(Self {
            master_key,
            ed25519_pkcs8_der: Zeroizing::new(ed25519_pkcs8_der),
            ed25519_public_key,
            mldsa65_signing_key_bytes: Zeroizing::new(mldsa65_signing_key_bytes),
            mldsa65_verifying_key_bytes,
            key_hierarchy: kh,
        })
    }
}
#[allow(clippy::collapsible_if)]
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
    OsRng.fill_bytes(&mut new_key);

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

pub fn compute_audit_sth_digest(
    tree_size: u64,
    timestamp_ms: i64,
    mmr_root_blake3: &[u8; 32],
) -> [u8; 32] {
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
    let digest = compute_audit_sth_digest(tree_size, timestamp_ms, &mmr_root_blake3);

    use ed25519_dalek::pkcs8::DecodePrivateKey;
    use ed25519_dalek::{Signer, SigningKey};

    let ed_sk = SigningKey::from_pkcs8_der(ed25519_pkcs8_der)
        .map_err(|e| IamError::CertificateGenerationError(e.to_string()))?;
    let ed25519_sig = ed_sk.sign(&digest).to_bytes().to_vec();

    use ml_dsa::MlDsa65;
    use ml_dsa::SignatureEncoding;

    let ml_sk =
        ml_dsa::SigningKey::<MlDsa65>::from_pkcs8_der(mldsa65_signing_key_bytes).map_err(|_| {
            IamError::CertificateGenerationError("invalid mldsa65 secret key".to_string())
        })?;

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
    let digest = compute_audit_sth_digest(sth.tree_size, sth.timestamp_ms, &sth.mmr_root_blake3);

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let ed_vk = VerifyingKey::from_bytes(ed25519_public_key)
        .map_err(|_| IamError::Ed25519VerificationFailed)?;
    let ed_sig =
        Signature::from_slice(&sth.ed25519_sig).map_err(|_| IamError::Ed25519VerificationFailed)?;

    ed_vk
        .verify(&digest, &ed_sig)
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

    let pq_sig = ml_dsa::Signature::<MlDsa65>::decode((&sig_array).into())
        .ok_or(IamError::PqSignatureVerificationFailed)?;

    ml_vk
        .verify(&digest, &pq_sig)
        .map_err(|_| IamError::PqSignatureVerificationFailed)?;

    Ok(())
}

impl crate::IdentityManager for SovereignCaIdentityManager {
    fn key_hierarchy(&self) -> &crate::key_hierarchy::KeyHierarchy {
        &self.key_hierarchy
    }

    fn sign_audit_sth(
        &self,
        tree_size: u64,
        timestamp_ms: i64,
        mmr_root_blake3: &[u8; 32],
    ) -> Result<AuditSthSignature, IamError> {
        sign_audit_sth(
            tree_size,
            timestamp_ms,
            *mmr_root_blake3,
            &self.ed25519_pkcs8_der,
            &self.mldsa65_signing_key_bytes,
        )
    }

    fn verify_audit_sth(&self, sth: &AuditSthSignature) -> Result<(), IamError> {
        verify_audit_sth(
            sth,
            &self.ed25519_public_key,
            &self.mldsa65_verifying_key_bytes,
        )
    }

    fn verify_jwt_svid(&self, token: &str, expected_audience: &str) -> Result<(), IamError> {
        crate::svid::verify_hybrid_jwt_svid(
            token,
            expected_audience,
            &self.ed25519_public_key,
            &self.mldsa65_verifying_key_bytes,
            true,
        )
        .map(|_| ())
    }

    fn current_svid(&self) -> Option<crate::svid::WorkloadSvid> {
        None
    }
}
