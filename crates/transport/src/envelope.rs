use bytes::Bytes;
use ed25519_dalek::{Verifier, Signature, SigningKey, VerifyingKey, Signer};
use base::error::ExtensionError;
use uuid::Uuid;
use ml_dsa::MlDsa65;
use ml_dsa::SignatureEncoding;

/// Error type for operations involving `WireEnvelope`, including signature generation
/// and verification failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Indicates that a cryptographic signature attached to the envelope is invalid.
    InvalidSignature,
    /// Indicates that the required post-quantum hybrid signature is missing.
    MissingPqSignature,
}

/// A secure hybrid post-quantum envelope designed for safely transmitting metadata
/// and payload bytes over potentially untrusted transport layers.
#[derive(Debug, Clone)]
pub struct WireEnvelope {
    /// Unique identifier for this envelope.
    pub envelope_id: Uuid,
    /// The SPIFFE ID representing the sender of this envelope.
    pub sender_spiffe_id: String,
    /// The distributed tracing traceparent context.
    pub traceparent: String,
    /// Timestamp of envelope creation, in milliseconds since UNIX epoch.
    pub timestamp_ms: i64,
    /// Arbitrary payload bytes carried within the envelope.
    pub payload_bytes: Bytes,
    /// The Ed25519 classical signature over the envelope hash (64 bytes).
    pub ed25519_sig: Vec<u8>,
    /// The ML-DSA-65 post-quantum signature over the envelope hash, if available (3309 bytes).
    pub mldsa65_sig: Option<Vec<u8>>,
}

impl WireEnvelope {
    /// Computes the BLAKE3 hash over all canonical envelope fields required for signing.
    pub fn compute_hash(
        envelope_id: &Uuid,
        sender_spiffe_id: &str,
        traceparent: &str,
        timestamp_ms: i64,
        payload_bytes: &[u8],
    ) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tantry:wire-env:v3");
        hasher.update(envelope_id.as_bytes());
        hasher.update(sender_spiffe_id.as_bytes());
        hasher.update(traceparent.as_bytes());
        hasher.update(&timestamp_ms.to_be_bytes());
        hasher.update(payload_bytes);
        hasher.finalize()
    }

    /// Constructs and cryptographically signs a new `WireEnvelope` using the provided keys.
    /// If an `mldsa65_key` is provided, a hybrid signature is generated.
    pub fn sign(
        envelope_id: Uuid,
        sender_spiffe_id: String,
        traceparent: String,
        timestamp_ms: i64,
        payload_bytes: Bytes,
        ed25519_key: &SigningKey,
        mldsa65_key: Option<&ml_dsa::SigningKey<MlDsa65>>,
    ) -> Result<Self, base::error::ExtensionError> {
        let hash = Self::compute_hash(
            &envelope_id,
            &sender_spiffe_id,
            &traceparent,
            timestamp_ms,
            &payload_bytes,
        );
        let digest_bytes = hash.as_bytes();

        let ed25519_sig = ed25519_key.sign(digest_bytes).to_bytes().to_vec();

        let mldsa65_sig = match mldsa65_key {
            Some(pq_key) => {
                let sig = pq_key.sign(digest_bytes);
                Some(sig.to_vec())
            }
            None => None,
        };

        Ok(WireEnvelope {
            envelope_id,
            sender_spiffe_id,
            traceparent,
            timestamp_ms,
            payload_bytes,
            ed25519_sig,
            mldsa65_sig,
        })
    }

    /// Verifies the envelope signatures.
    /// Rejects any envelope missing a valid mldsa65_sig when require_pq_hybrid_signatures = true.
    pub fn verify(
        &self,
        ed25519_pub: &VerifyingKey,
        mldsa65_pub: Option<&ml_dsa::VerifyingKey<MlDsa65>>,
        require_pq_hybrid_signatures: bool,
    ) -> Result<(), base::error::ExtensionError> {
        if require_pq_hybrid_signatures && self.mldsa65_sig.is_none() {
            return Err(base::error::ExtensionError::DeserializationFailed("Missing ML-DSA-65 signature when required".to_string()));
        }

        let hash = Self::compute_hash(
            &self.envelope_id,
            &self.sender_spiffe_id,
            &self.traceparent,
            self.timestamp_ms,
            &self.payload_bytes,
        );
        let digest_bytes = hash.as_bytes();

        // Verify Ed25519 signature
        if self.ed25519_sig.len() != 64 {
            return Err(ExtensionError::DeserializationFailed("Invalid Ed25519 signature length".to_string()));
        }
        let mut ed_sig_bytes = [0u8; 64];
        ed_sig_bytes.copy_from_slice(&self.ed25519_sig);
        let ed_sig = Signature::from_bytes(&ed_sig_bytes);
        if ed25519_pub.verify(digest_bytes, &ed_sig).is_err() {
            return Err(ExtensionError::DeserializationFailed("Ed25519 verification failed".to_string()));
        }

        // Verify ML-DSA-65 signature if required or provided
        if require_pq_hybrid_signatures && self.mldsa65_sig.is_none() {
            return Err(ExtensionError::DeserializationFailed("Missing ML-DSA-65 signature when required".to_string()));
        }

        if let Some(sig_bytes) = &self.mldsa65_sig {
            let pq_pub = mldsa65_pub.ok_or_else(|| {
                ExtensionError::DeserializationFailed("Missing ML-DSA-65 public key for verification".to_string())
            })?;
            if sig_bytes.len() != 3309 {
                return Err(ExtensionError::DeserializationFailed("Invalid ML-DSA-65 signature length".to_string()));
            }
            let pq_sig = ml_dsa::Signature::<MlDsa65>::try_from(sig_bytes.as_slice()).map_err(|_| {
                ExtensionError::DeserializationFailed("Failed to parse ML-DSA-65 signature".to_string())
            })?;
            if pq_pub.verify(digest_bytes, &pq_sig).is_err() {
                return Err(ExtensionError::DeserializationFailed("ML-DSA-65 verification failed".to_string()));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use uuid::Uuid;
    use bytes::Bytes;

    #[test]
    fn test_hybrid_envelope_signing_and_verification() {
        let mut csprng = OsRng;
        let mut _ed_seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut csprng, &mut _ed_seed);
        let ed25519_key = SigningKey::from_bytes(&_ed_seed);
        let ed25519_pub = ed25519_key.verifying_key();

        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut csprng, &mut seed);

        // ML-DSA doesn't use RNG directly in this version, so we fallback to testing logic.
        // Bypassing real ML-DSA signature for unit testing serialization path since `generate()` has unstable trait boundaries in tests.
        use ml_dsa::KeyInit;
        let mldsa_priv = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::new_from_slice(&seed).unwrap();
        // create matching pub key via trait
        use ml_dsa::Keypair;
        let mldsa_pub = mldsa_priv.verifying_key();

        let envelope_id = Uuid::new_v4();
        let spiffe_id = "spiffe://example.org/workload".to_string();
        let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string();
        let timestamp = 1634567890;
        let payload = Bytes::from("test payload");

        let env = WireEnvelope::sign(
            envelope_id,
            spiffe_id.clone(),
            traceparent.clone(),
            timestamp,
            payload.clone(),
            &ed25519_key,
            Some(&mldsa_priv),
        ).expect("failed to sign");

        assert!(env.mldsa65_sig.is_some());
        assert_eq!(env.mldsa65_sig.as_ref().unwrap().len(), 3309);
        assert_eq!(env.ed25519_sig.len(), 64);

        assert!(env.verify(&ed25519_pub, Some(&mldsa_pub), true).is_ok());
    }

    #[test]
    fn test_hybrid_envelope_missing_pq_signature_rejection() {
        let mut csprng = OsRng;
        let mut _ed_seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut csprng, &mut _ed_seed);
        let ed25519_key = SigningKey::from_bytes(&_ed_seed);
        let ed25519_pub = ed25519_key.verifying_key();

        let envelope_id = Uuid::new_v4();
        let spiffe_id = "spiffe://example.org/workload".to_string();
        let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string();
        let timestamp = 1634567890;
        let payload = Bytes::from("test payload");

        let env = WireEnvelope::sign(
            envelope_id,
            spiffe_id.clone(),
            traceparent.clone(),
            timestamp,
            payload.clone(),
            &ed25519_key,
            None,
        ).expect("failed to sign");

        assert!(env.mldsa65_sig.is_none());

        // Should reject if PQ is required
        let res = env.verify(&ed25519_pub, None, true);
        assert!(res.is_err());
        if let Err(ExtensionError::DeserializationFailed(msg)) = res {
            assert_eq!(msg, "Missing ML-DSA-65 signature when required");
        } else {
            panic!("Expected DeserializationFailed for missing signature");
        }

        // Should pass if PQ is not required
        assert!(env.verify(&ed25519_pub, None, false).is_ok());
    }
}
