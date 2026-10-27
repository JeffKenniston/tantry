use crate::error::IamError;
use dashmap::{DashMap, DashSet};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const HKDF_DEK_DOMAIN_INFO: &[u8] = b"tantry-sqlite-aead-dek-v3";

pub type MasterKey = Zeroizing<[u8; 32]>;
pub type DekKey = Zeroizing<[u8; 32]>;

pub struct KeyHierarchy {
    kek_root: Zeroizing<[u8; 32]>,
    cached_thread_deks: DashMap<(String, u32), Zeroizing<[u8; 32]>>,
    shredded_threads: DashSet<String>,
}

impl KeyHierarchy {
    pub fn new(root_kek: [u8; 32]) -> Self {
        Self {
            kek_root: Zeroizing::new(root_kek),
            cached_thread_deks: DashMap::new(),
            shredded_threads: DashSet::new(),
        }
    }

    pub fn derive_epoch_dek(&self, epoch_id: u32, epoch_salt: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        let (_, hkdf) = Hkdf::<Sha256>::extract(Some(epoch_salt), self.kek_root.as_ref());
        let mut epoch_dek = [0u8; 32];
        let mut epoch_info = Vec::new();
        epoch_info.extend_from_slice(b"tantry:dek:epoch:v3:");
        epoch_info.extend_from_slice(&epoch_id.to_be_bytes());

        let _ = hkdf.expand(&epoch_info, &mut epoch_dek);
        Zeroizing::new(epoch_dek)
    }

    pub fn derive_thread_dek(
        &self,
        thread_id: &str,
        epoch_id: u32,
        epoch_salt: &[u8; 32],
        thread_salt: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, IamError> {
        if self.shredded_threads.contains(thread_id) {
            return Err(IamError::KeyEpochShredded {
                thread_id: thread_id.to_string(),
                epoch: epoch_id,
            });
        }

        let cache_key = (thread_id.to_string(), epoch_id);
        if let Some(cached) = self.cached_thread_deks.get(&cache_key) {
            return Ok(cached.clone());
        }

        let epoch_dek = self.derive_epoch_dek(epoch_id, epoch_salt);
        let (_, thread_hkdf) = Hkdf::<Sha256>::extract(Some(thread_salt), epoch_dek.as_ref());

        let mut thread_dek = [0u8; 32];
        let mut thread_info = Vec::new();
        thread_info.extend_from_slice(HKDF_DEK_DOMAIN_INFO);
        thread_info.extend_from_slice(b":");
        thread_info.extend_from_slice(thread_id.as_bytes());

        let _ = thread_hkdf.expand(&thread_info, &mut thread_dek);

        let derived = Zeroizing::new(thread_dek);
        self.cached_thread_deks.insert(cache_key, derived.clone());

        Ok(derived)
    }

    pub fn crypto_shred_thread(&self, thread_id: &str) {
        self.shredded_threads.insert(thread_id.to_string());

        // Remove/zeroize all entries matching thread_id from cached_thread_deks
        // using retain to iterate and remove in O(N).
        self.cached_thread_deks.retain(|k, _| k.0 != thread_id);
    }
}
