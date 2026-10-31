use crate::error::IamError;
use dashmap::{DashMap, DashSet};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const HKDF_EPOCH_INFO_PREFIX: &[u8] = b"tantry-sqlite-aead-dek-v3:epoch:";
pub const HKDF_THREAD_INFO_PREFIX: &[u8] = b"tantry-sqlite-aead-dek-v3:thread:";

pub type MasterKey = Zeroizing<[u8; 32]>;
pub type DekKey = Zeroizing<[u8; 32]>;

pub struct KeyHierarchy {
    kek_root: Zeroizing<[u8; 32]>,
    cached_thread_deks: DashMap<(String, u32), Zeroizing<[u8; 32]>>,
    shredded_threads: DashSet<String>,
}

impl KeyHierarchy {
    pub fn new(kek_root: [u8; 32]) -> Self {
        Self {
            kek_root: Zeroizing::new(kek_root),
            cached_thread_deks: DashMap::new(),
            shredded_threads: DashSet::new(),
        }
    }

    pub fn derive_epoch_dek(&self, epoch_id: u32, epoch_salt: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        let hkdf = Hkdf::<Sha256>::new(Some(epoch_salt), &*self.kek_root);
        let mut epoch_dek = [0u8; 32];
        let info = [HKDF_EPOCH_INFO_PREFIX, &epoch_id.to_be_bytes()].concat();

        let _ = hkdf.expand(&info, &mut epoch_dek);
        Zeroizing::new(epoch_dek)
    }

    pub fn derive_dek_from_salts(
        &self,
        epoch_id: u32,
        epoch_salt: &[u8; 32],
        thread_id: &str,
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
        let hkdf = Hkdf::<Sha256>::new(Some(thread_salt), &*epoch_dek);

        let mut thread_dek = [0u8; 32];
        let info = [HKDF_THREAD_INFO_PREFIX, thread_id.as_bytes()].concat();

        let _ = hkdf.expand(&info, &mut thread_dek);

        let derived = Zeroizing::new(thread_dek);
        self.cached_thread_deks.insert(cache_key, derived.clone());

        Ok(derived)
    }

    pub fn derive_thread_dek(
        &self,
        thread_id: &str,
        epoch_id: u32,
        epoch_salt: &[u8; 32],
        thread_salt: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, IamError> {
        self.derive_dek_from_salts(epoch_id, epoch_salt, thread_id, thread_salt)
    }

    pub fn crypto_shred_thread(&self, thread_id: &str) {
        self.shredded_threads.insert(thread_id.to_string());

        let keys_to_remove: Vec<_> = self
            .cached_thread_deks
            .iter()
            .filter(|entry| entry.key().0 == thread_id)
            .map(|entry| entry.key().clone())
            .collect();

        for key in keys_to_remove {
            self.cached_thread_deks.remove(&key);
        }
    }

    pub fn is_thread_shredded(&self, thread_id: &str) -> bool {
        self.shredded_threads.contains(thread_id)
    }
}
