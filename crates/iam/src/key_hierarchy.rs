use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;
use crate::error::IamError;
use std::collections::HashSet;
use std::sync::RwLock;

pub const HKDF_DEK_DOMAIN_INFO: &[u8] = b"tantry-sqlite-aead-dek-v3";

pub struct KeyHierarchy {
    shredded_epochs: RwLock<HashSet<(String, u32)>>,
}

impl KeyHierarchy {
    pub fn new() -> Self {
        Self {
            shredded_epochs: RwLock::new(HashSet::new()),
        }
    }

    pub fn derive_dek_from_salts(
        &self,
        kek_root: &[u8],
        epoch_salt_32: &[u8; 32],
        epoch_id_be32: u32,
        thread_salt_32: &[u8; 32],
        thread_id: &str,
    ) -> Result<Zeroizing<[u8; 32]>, IamError> {
        let shredded = self.shredded_epochs.read().unwrap();
        if shredded.contains(&(thread_id.to_string(), epoch_id_be32)) || shredded.contains(&(thread_id.to_string(), u32::MAX)) {
            return Err(IamError::KeyEpochShredded {
                thread_id: thread_id.to_string(),
                epoch: epoch_id_be32,
            });
        }
        drop(shredded);

        let (_, hkdf_epoch) = Hkdf::<Sha256>::extract(Some(epoch_salt_32), kek_root);
        let mut epoch_info = Vec::new();
        epoch_info.extend_from_slice(HKDF_DEK_DOMAIN_INFO);
        epoch_info.extend_from_slice(b":epoch:");
        epoch_info.extend_from_slice(&epoch_id_be32.to_be_bytes());

        let mut dek_epoch = [0u8; 32];
        hkdf_epoch.expand(&epoch_info, &mut dek_epoch).unwrap();

        let (_, hkdf_thread) = Hkdf::<Sha256>::extract(Some(thread_salt_32), &dek_epoch);
        let mut thread_info = Vec::new();
        thread_info.extend_from_slice(HKDF_DEK_DOMAIN_INFO);
        thread_info.extend_from_slice(b":thread:");
        thread_info.extend_from_slice(thread_id.as_bytes());

        let mut dek_thread = [0u8; 32];
        hkdf_thread.expand(&thread_info, &mut dek_thread).unwrap();

        // Zeroize intermediate dek_epoch
        zeroize::Zeroize::zeroize(&mut dek_epoch);

        Ok(Zeroizing::new(dek_thread))
    }

    pub fn crypto_shred_thread(&self, thread_id: &str) {
        let mut shredded = self.shredded_epochs.write().unwrap();
        // Mark thread as shredded using a sentinel epoch of u32::MAX
        // Remove all cached (thread_id, epoch_id) entries
        shredded.retain(|(t, _)| t != thread_id);
        // Mark thread as shredded using a sentinel epoch of u32::MAX
        shredded.insert((thread_id.to_string(), u32::MAX));
}
    }
