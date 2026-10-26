#![allow(deprecated)]
use std::fs;
use std::path::Path;
use std::os::unix::fs::PermissionsExt;
use std::env;
use std::sync::Arc;

use crate::error::IamError;
use crate::keys::MasterKey;
use getrandom::fill;
use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use serde::{Serialize, Deserialize};

pub fn acquire_or_init_master_key(data_dir: &Path) -> Result<MasterKey, IamError> {
    if let Ok(env_key) = env::var("TANTRY_MASTER_KEY") {
        if env_key.len() == 64 {
            if let Ok(bytes) = hex::decode(&env_key) {
                if bytes.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    return Ok(MasterKey(key));
                }
            }
        }
        if let Ok(bytes) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &env_key) {
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                return Ok(MasterKey(key));
            }
        }
    }

    let keystore_path = data_dir.join(".keystore_master.sealed");
    if keystore_path.exists() {
        if let Ok(contents) = fs::read(&keystore_path) {
            if contents.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&contents);
                return Ok(MasterKey(key));
            }
        }
    }

    let seed_path = data_dir.join(".master_key.seed");
    if seed_path.exists() {
        if let Ok(contents) = fs::read(&seed_path) {
            if contents.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&contents);
                return Ok(MasterKey(key));
            }
        }
    }

    let mut new_key = [0u8; 32];
    fill(&mut new_key).unwrap();
    fs::write(&seed_path, &new_key).map_err(|_| IamError::MasterKeyUnavailable)?;
    let mut perms = fs::metadata(&seed_path).map_err(|_| IamError::MasterKeyUnavailable)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&seed_path, perms).map_err(|_| IamError::MasterKeyUnavailable)?;

    Ok(MasterKey(new_key))
}


use crate::tunnel_grant::ScopedTunnelRegistry;
use crate::key_hierarchy::KeyHierarchy;

pub struct SovereignCaIdentityManager {
    _registry: Arc<ScopedTunnelRegistry>,
    keys: Arc<KeyHierarchy>,
}


impl SovereignCaIdentityManager {
    pub fn new(_registry: Arc<ScopedTunnelRegistry>, keys: Arc<KeyHierarchy>) -> Self {
        Self { _registry, keys }
    }

    pub fn seal_keypair(
        data_dir: &Path,
        master_key: &MasterKey,
        keypair: &SovereignCaKeypair,
    ) -> Result<(), IamError> {
        let serialized = bincode::serialize(keypair)
            .map_err(|_| IamError::CertificateGenerationError("Serialization failed".to_string()))?;

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&master_key.0));
        let mut nonce_bytes = [0u8; 24];
        fill(&mut nonce_bytes).unwrap();
        let nonce = XNonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: &serialized,
            aad: b"tantry:sovereign-ca:v3",
        };

        let mut ciphertext = cipher.encrypt(nonce, payload)
            .map_err(|_| IamError::CertificateGenerationError("Encryption failed".to_string()))?;

        let mut final_payload = Vec::with_capacity(24 + ciphertext.len());
        final_payload.extend_from_slice(&nonce_bytes);
        final_payload.append(&mut ciphertext);

        let path = data_dir.join("sovereign_ca.sealed");
        fs::write(&path, final_payload).map_err(|_| IamError::MasterKeyUnavailable)?;
        let mut perms = fs::metadata(&path).map_err(|_| IamError::MasterKeyUnavailable)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms).map_err(|_| IamError::MasterKeyUnavailable)?;

        Ok(())
    }

    pub fn unseal_keypair(
        data_dir: &Path,
        master_key: &MasterKey,
    ) -> Result<SovereignCaKeypair, IamError> {
        let path = data_dir.join("sovereign_ca.sealed");
        if !path.exists() {
            return Err(IamError::MasterKeyUnavailable);
        }

        let contents = fs::read(&path).map_err(|_| IamError::MasterKeyUnavailable)?;
        if contents.len() < 24 {
            return Err(IamError::CertificateGenerationError("Invalid sealed length".to_string()));
        }

        let (nonce_bytes, ciphertext) = contents.split_at(24);
        let nonce = XNonce::from_slice(nonce_bytes);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&master_key.0));

        let payload = Payload {
            msg: ciphertext,
            aad: b"tantry:sovereign-ca:v3",
        };

        let decrypted = cipher.decrypt(nonce, payload)
            .map_err(|_| IamError::CertificateGenerationError("Decryption failed".to_string()))?;

        let keypair: SovereignCaKeypair = bincode::deserialize(&decrypted)
            .map_err(|_| IamError::CertificateGenerationError("Deserialization failed".to_string()))?;

        Ok(keypair)
    }
}

#[derive(Serialize, Deserialize, zeroize::ZeroizeOnDrop, zeroize::Zeroize)]
pub struct SovereignCaKeypair {
    pub ed25519_pkcs8: Vec<u8>,
    pub mldsa65_seed: Vec<u8>,
}

impl crate::IdentityManager for SovereignCaIdentityManager {
    fn current_svid(&self) -> Option<Arc<crate::svid::WorkloadSvid>> {
        None
    }

    fn key_hierarchy(&self) -> Arc<crate::key_hierarchy::KeyHierarchy> {
        self.keys.clone()
    }
}
