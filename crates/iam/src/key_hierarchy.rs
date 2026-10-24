use crate::error::IamError;
use dashmap::DashMap;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const HKDF_DEK_DOMAIN_INFO: &[u8] = b"tantry-sqlite-aead-dek-v3";

pub struct KeyHierarchy {
    root_kek: Zeroizing<[u8; 32]>,
    thread_cache: DashMap<String, DashMap<u32, Zeroizing<[u8; 32]>>>,
    shredded_threads: DashMap<String, bool>,
}

impl KeyHierarchy {
    pub fn new(root_kek: [u8; 32]) -> Self {
        Self {
            root_kek: Zeroizing::new(root_kek),
            thread_cache: DashMap::new(),
            shredded_threads: DashMap::new(),
        }
    }

    pub fn derive_dek_from_salts(
        &self,
        epoch_id: u32,
        epoch_salt: &[u8; 32],
        thread_id: &str,
        thread_salt: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, IamError> {
        if self.shredded_threads.contains_key(thread_id) {
            return Err(IamError::KeyEpochShredded {
                thread_id: thread_id.to_string(),
                epoch: epoch_id,
            });
        }

        // Tier 1 -> 2 (Epoch)
        let epoch_hkdf = Hkdf::<Sha256>::new(Some(epoch_salt), self.root_kek.as_ref());
        let mut epoch_dek = [0u8; 32];

        let mut epoch_info = Vec::new();
        epoch_info.extend_from_slice(HKDF_DEK_DOMAIN_INFO);
        epoch_info.extend_from_slice(b":epoch:");
        epoch_info.extend_from_slice(&epoch_id.to_be_bytes());

        epoch_hkdf
            .expand(&epoch_info, &mut epoch_dek)
            .map_err(|_| IamError::MasterKeyUnavailable)?;

        // Tier 2 -> 3 (Thread)
        let thread_hkdf = Hkdf::<Sha256>::new(Some(thread_salt), &epoch_dek);
        let mut thread_dek = [0u8; 32];

        let mut thread_info = Vec::new();
        thread_info.extend_from_slice(HKDF_DEK_DOMAIN_INFO);
        thread_info.extend_from_slice(b":thread:");
        thread_info.extend_from_slice(thread_id.as_bytes());

        thread_hkdf
            .expand(&thread_info, &mut thread_dek)
            .map_err(|_| IamError::MasterKeyUnavailable)?;

        // Zeroize intermediate key
        use zeroize::Zeroize;
        epoch_dek.zeroize();

        let derived = Zeroizing::new(thread_dek);

        let cache = self.thread_cache.entry(thread_id.to_string()).or_default();
        cache.insert(epoch_id, Zeroizing::new(thread_dek));

        Ok(derived)
    }

    pub fn crypto_shred_thread(&self, thread_id: &str) {
        self.shredded_threads.insert(thread_id.to_string(), true);
        if let Some((_, cache)) = self.thread_cache.remove(thread_id) {
            for mut entry in cache.into_iter() {
                use zeroize::Zeroize;
                entry.1.zeroize();
            }
        }
    }
}
