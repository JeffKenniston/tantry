use std::time::{SystemTime, UNIX_EPOCH};
use crate::error::DataError;
use aes_gcm_siv::Aes256GcmSiv;
use blake3;
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, Key},
};
use core::convert::TryInto;
use rusqlite::Connection;
use std::sync::atomic::{AtomicU64, Ordering};

/// Computes the canonical 32-byte BLAKE3 hash used as Additional Authenticated Data (AAD) to cryptographically bind rows to their thread and epoch.

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize)]
pub enum AeadCipherSuite {
    #[default]
    XChaCha20Poly1305 = 0x01,
    Aes256GcmSiv = 0x02,
}

impl AeadCipherSuite {
    pub const WIRE_VERSION: u8 = 0x03;

    #[inline]
    pub const fn cipher_id(self) -> u8 {
        self as u8
    }

    #[inline]
    pub const fn from_cipher_id(id: u8) -> Option<Self> {
        match id {
            0x01 => Some(Self::XChaCha20Poly1305),
            0x02 => Some(Self::Aes256GcmSiv),
            _ => None,
        }
    }

    #[inline]
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::XChaCha20Poly1305 => 24,
            Self::Aes256GcmSiv => 12,
        }
    }
}

pub fn compute_canonical_aad(
    table_name: &str,
    primary_key: &str,
    thread_id: &str,
    epoch_id: u32,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"tantry:aad:v3");
    hasher.update(table_name.as_bytes());
    hasher.update(primary_key.as_bytes());
    hasher.update(thread_id.as_bytes());
    hasher.update(&epoch_id.to_be_bytes());
    hasher.finalize().into()
}

pub fn build_checkpoint_aad(thread_id: &str, checkpoint_id: &str, step_index: u64, key_epoch: u32) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"tantry:checkpoint:v3:");
    aad.extend_from_slice(thread_id.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(checkpoint_id.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(&step_index.to_be_bytes());
    aad.push(b':');
    aad.extend_from_slice(&key_epoch.to_be_bytes());
    aad
}

pub fn build_archive_aad(thread_id: &str, checkpoint_id: &str, key_epoch: u32) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"tantry:archive:v3:");
    aad.extend_from_slice(thread_id.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(checkpoint_id.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(&key_epoch.to_be_bytes());
    aad
}

pub fn build_semcache_aad(cache_key_hex: &str, model_tier: &str) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"tantry:semcache:v3:");
    aad.extend_from_slice(cache_key_hex.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(model_tier.as_bytes());
    aad
}


static ATOMIC_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generates a 24-byte cryptographically secure nonce using a combination of timestamp, atomic counter, and OS randomness to prevent VM snapshot vulnerabilities.
pub fn generate_xchacha20_nonce() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    nonce[0..8].copy_from_slice(&timestamp_ms.to_be_bytes());
    let counter = ATOMIC_COUNTER.fetch_add(1, Ordering::SeqCst);
    nonce[8..16].copy_from_slice(&counter.to_be_bytes());

    let mut os_csprng = [0u8; 8];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut os_csprng);
    nonce[16..24].copy_from_slice(&os_csprng);
    nonce
}

/// Compresses plaintext using zstd and encrypts it into a canonical envelope using XChaCha20-Poly1305 and the provided DEK/AAD.
pub fn encrypt_envelope_xchacha20(
    plaintext: &[u8],
    dek: &[u8; 32],
    aad: &[u8; 32],
) -> Result<Vec<u8>, DataError> {
    let compressed =
        zstd::encode_all(plaintext, 3).map_err(|e| DataError::Compression(e.to_string()))?;

    let nonce_bytes = generate_xchacha20_nonce();
    let nonce = chacha20poly1305::XNonce::from(nonce_bytes);

    let key = Key::<XChaCha20Poly1305>::from(*dek);
    let cipher = XChaCha20Poly1305::new(&key);

    let payload = chacha20poly1305::aead::Payload {
        msg: &compressed,
        aad,
    };

    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|_| DataError::AeadEncryptionFailed)?;

    let mut wire = Vec::with_capacity(1 + 1 + 24 + ciphertext.len());
    wire.push(0x03);
    wire.push(0x01);
    wire.extend_from_slice(&nonce_bytes);
    wire.extend_from_slice(&ciphertext);

    Ok(wire)
}

/// Authenticates and decrypts a wire-format envelope (supporting XChaCha20-Poly1305 or AES-GCM-SIV) and decompresses the zstd payload.
pub fn decrypt_envelope(
    wire: &[u8],
    dek: &[u8; 32],
    expected_aad: &[u8; 32],
) -> Result<Vec<u8>, DataError> {
    if wire.len() < 2 {
        return Err(DataError::Serialization(
            "Wire format too short".to_string(),
        ));
    }

    if wire[0] != 0x03 {
        return Err(DataError::Serialization("Unknown version".to_string()));
    }

    let compressed = match wire[1] {
        0x01 => {
            // XChaCha20Poly1305
            if wire.len() < 2 + 24 + 16 {
                return Err(DataError::Serialization(
                    "XChaCha wire format too short".to_string(),
                ));
            }
            let nonce_bytes: [u8; 24] = wire[2..26]
                .try_into()
                .map_err(|_| DataError::Serialization("Bad nonce".to_string()))?;
            let ciphertext = &wire[26..];
            let key = Key::<XChaCha20Poly1305>::from(*dek);
            let cipher = XChaCha20Poly1305::new(&key);
            let nonce = chacha20poly1305::XNonce::from(nonce_bytes);
            let payload = chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad: expected_aad,
            };
            cipher
                .decrypt(&nonce, payload)
                .map_err(|_| DataError::AeadDecryptionFailed { context: "AAD mismatch".to_string() })?
        }
        0x02 => {
            // Aes256GcmSiv
            if wire.len() < 2 + 12 + 16 {
                return Err(DataError::Serialization(
                    "AES wire format too short".to_string(),
                ));
            }
            let nonce_bytes: [u8; 12] = wire[2..14]
                .try_into()
                .map_err(|_| DataError::Serialization("Bad nonce".to_string()))?;
            let ciphertext = &wire[14..];
            let key = Key::<Aes256GcmSiv>::from(*dek);
            let cipher = Aes256GcmSiv::new(&key);
            let nonce = aes_gcm_siv::Nonce::from(nonce_bytes);
            let payload = aes_gcm_siv::aead::Payload {
                msg: ciphertext,
                aad: expected_aad,
            };
            cipher
                .decrypt(&nonce, payload)
                .map_err(|_| DataError::AeadDecryptionFailed { context: "AAD mismatch".to_string() })?
        }
        _ => return Err(DataError::Serialization("Unknown cipher ID".to_string())),
    };

    let plaintext =
        zstd::decode_all(compressed.as_slice()).map_err(|e| DataError::Compression(e.to_string()))?;
    Ok(plaintext)
}

/// Retrieves the epoch and thread salts for a given thread and epoch, or securely provisions them with CSPRNG if they do not exist.
use std::sync::Arc;
use zeroize::Zeroizing;

pub const KEY_EPOCH_DDL: &str = "
CREATE TABLE IF NOT EXISTS key_epochs (
    thread_id TEXT NOT NULL,
    epoch_id INTEGER NOT NULL,
    epoch_salt BLOB NOT NULL,
    thread_salt BLOB,
    created_at_ms INTEGER NOT NULL,
    shredded INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (thread_id, epoch_id)
);
";

pub struct KeyEpochStore {
    pub db: Arc<parking_lot::Mutex<Connection>>,
}

impl KeyEpochStore {
    pub fn new(db: Arc<parking_lot::Mutex<Connection>>) -> Self {
        Self { db }
    }

    pub fn resolve_or_init_thread_dek(
        &self,
        iam_keys: &iam::key_hierarchy::KeyHierarchy,
        thread_id: &str,
        epoch_id: u32,
    ) -> Result<Zeroizing<[u8; 32]>, DataError> {
        let conn = self.db.lock();
        let mut stmt = conn.prepare(
            "SELECT epoch_salt, thread_salt, shredded FROM key_epochs WHERE thread_id = ?1 AND epoch_id = ?2",
        )?;
        let mut rows = stmt.query(rusqlite::params![thread_id, epoch_id])?;

        if let Some(row) = rows.next()? {
            let shredded: i32 = row.get(2)?;
            let thread_salt_val: Option<Vec<u8>> = row.get(1)?;
            if shredded != 0 || thread_salt_val.is_none() {
                return Err(DataError::KeyEpochShredded {
                    thread_id: thread_id.to_string(),
                    epoch: epoch_id,
                });
            }

            let epoch_salt_val: Vec<u8> = row.get(0)?;
            let mut epoch_arr = [0u8; 32];
            if epoch_salt_val.len() == 32 {
                epoch_arr.copy_from_slice(&epoch_salt_val);
            }

            let mut thread_arr = [0u8; 32];
            if let Some(salt) = thread_salt_val {
                if salt.len() == 32 {
                    thread_arr.copy_from_slice(&salt);
                }
            }

            return Ok(iam_keys.derive_thread_dek(thread_id, epoch_id, &epoch_arr, &thread_arr)?);
        }

        // If row does not exist, check if any epoch for thread_id has shredded != 0
        let mut check_stmt = conn.prepare(
            "SELECT 1 FROM key_epochs WHERE thread_id = ?1 AND shredded != 0 LIMIT 1",
        )?;
        if check_stmt.exists(rusqlite::params![thread_id])? {
            return Err(DataError::KeyEpochShredded {
                thread_id: thread_id.to_string(),
                epoch: epoch_id,
            });
        }

        let mut epoch_salt = [0u8; 32];
        let mut thread_salt = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut epoch_salt);
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut thread_salt);

        let created_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        conn.execute(
            "INSERT INTO key_epochs (thread_id, epoch_id, epoch_salt, thread_salt, created_at_ms, shredded) VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            rusqlite::params![thread_id, epoch_id, epoch_salt.to_vec(), thread_salt.to_vec(), created_at_ms]
        )?;

        Ok(iam_keys.derive_thread_dek(thread_id, epoch_id, &epoch_salt, &thread_salt)?)
    }

    pub fn crypto_shred_thread(
        &self,
        iam_keys: &iam::key_hierarchy::KeyHierarchy,
        thread_id: &str,
    ) -> Result<(), DataError> {
        let mut conn = self.db.lock();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        tx.execute(
            "UPDATE key_epochs SET thread_salt = zeroblob(32) WHERE thread_id = ?1",
            rusqlite::params![thread_id],
        )?;

        tx.execute(
            "UPDATE key_epochs SET thread_salt = NULL, shredded = 1 WHERE thread_id = ?1",
            rusqlite::params![thread_id],
        )?;

        tx.commit()?;

        conn.pragma_update(None, "wal_checkpoint", "TRUNCATE")?;

        iam_keys.crypto_shred_thread(thread_id);

        Ok(())
    }
}
