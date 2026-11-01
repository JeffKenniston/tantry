use crate::error::DataError;
use aes_gcm_siv::Aes256GcmSiv;
use blake3;
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, Key},
};
use core::convert::TryInto;
use iam::key_hierarchy::KeyHierarchy;
use rusqlite::Connection;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Computes the canonical 32-byte BLAKE3 hash used as Additional Authenticated Data (AAD) to cryptographically bind rows to their thread and epoch.
pub fn compute_canonical_aad(
    table_name: &str,
    primary_key: &str,
    thread_id: &str,
    key_epoch: u32,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"tantry:aad:v3");
    hasher.update(table_name.as_bytes());
    hasher.update(primary_key.as_bytes());
    hasher.update(thread_id.as_bytes());
    hasher.update(&key_epoch.to_be_bytes());
    hasher.finalize().into()
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
pub fn get_or_provision_key_epoch(
    conn: &Connection,
    thread_id: &str,
    key_epoch: u32,
) -> Result<([u8; 32], [u8; 32]), DataError> {
    let mut stmt = conn.prepare(
        "SELECT thread_salt, shredded FROM key_epochs WHERE thread_id = ?1 AND key_epoch = ?2",
    )?;
    let mut rows = stmt.query(rusqlite::params![thread_id, key_epoch])?;

    if let Some(row) = rows.next()? {
        let shredded: i32 = row.get(1)?;
        if shredded != 0 {
            return Err(DataError::KeyEpochShredded { thread_id: thread_id.to_string(), epoch: key_epoch });
        }

        let thread_salt_val: Option<Vec<u8>> = row.get(0)?;
        if let Some(salt) = thread_salt_val {
            if salt.len() != 32 {
                return Err(DataError::Serialization(
                    "Invalid thread salt length".to_string(),
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&salt);

            let mut epoch_stmt = conn.prepare(
                "SELECT epoch_salt FROM key_epochs WHERE thread_id = ?1 AND key_epoch = ?2",
            )?;
            let mut epoch_arr = [0u8; 32];
            #[allow(clippy::collapsible_if)]
            if let Ok(r) = epoch_stmt.query_row(rusqlite::params![thread_id, key_epoch], |r| {
                r.get::<_, Vec<u8>>(0)
            }) {
                if r.len() == 32 {
                    epoch_arr.copy_from_slice(&r);
                }
            }
            return Ok((epoch_arr, arr));
        } else {
            return Err(DataError::KeyEpochShredded { thread_id: thread_id.to_string(), epoch: key_epoch });
        }
    }

    let mut epoch_salt = [0u8; 32];
    let mut thread_salt = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut epoch_salt);
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut thread_salt);

    conn.execute(
        "INSERT INTO key_epochs (thread_id, key_epoch, epoch_salt, thread_salt, shredded) VALUES (?1, ?2, ?3, ?4, 0)",
        rusqlite::params![thread_id, key_epoch, epoch_salt.to_vec(), thread_salt.to_vec()]
    )?;

    Ok((epoch_salt, thread_salt))
}

/// Executes the two-phase cryptographic shredding of a thread's keys by zeroing and nullifying the thread_salt in SQLite and memory.
pub fn crypto_shred_thread(
    conn: &mut Connection,
    thread_id: &str,
    key_hierarchy: &KeyHierarchy,
) -> Result<(), DataError> {
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

    key_hierarchy.crypto_shred_thread(thread_id);

    Ok(())
}
