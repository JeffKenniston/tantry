use bytes::Bytes;
use ed25519_dalek::{Verifier, Signature, SigningKey, VerifyingKey};
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
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tantry:wire-env:v3");
        hasher.update(envelope_id.as_bytes());
        hasher.update(sender_spiffe_id.as_bytes());
        hasher.update(traceparent.as_bytes());
        hasher.update(&timestamp_ms.to_be_bytes());
        hasher.update(payload_bytes);
        hasher.finalize().into()
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
    ) -> Self {
        let hash = Self::compute_hash(
            &envelope_id,
            &sender_spiffe_id,
            &traceparent,
            timestamp_ms,
            &payload_bytes,
        );

        use ed25519_dalek::Signer as DalekSigner;
        let ed25519_sig = DalekSigner::sign(ed25519_key, &hash).to_bytes().to_vec();

        let mldsa65_sig = mldsa65_key.map(|k| {
            use ml_dsa::signature::Signer;
            k.sign(&hash).to_bytes().to_vec()
        });

        Self {
            envelope_id,
            sender_spiffe_id,
            traceparent,
            timestamp_ms,
            payload_bytes,
            ed25519_sig,
            mldsa65_sig,
        }
    }

    /// Verifies the cryptographic integrity of this envelope against the given public keys.
    /// Rejects any envelope without a valid `mldsa65_sig` if `require_pq_hybrid_signatures` is enabled.
    pub fn verify(
        &self,
        ed25519_pub: &VerifyingKey,
        mldsa65_pub: Option<&ml_dsa::VerifyingKey<MlDsa65>>,
        require_pq_hybrid_signatures: bool,
    ) -> Result<(), EnvelopeError> {
        if require_pq_hybrid_signatures && self.mldsa65_sig.is_none() {
            return Err(EnvelopeError::MissingPqSignature);
        }

        let hash = Self::compute_hash(
            &self.envelope_id,
            &self.sender_spiffe_id,
            &self.traceparent,
            self.timestamp_ms,
            &self.payload_bytes,
        );

        let mut sig_bytes = [0u8; 64];
        if self.ed25519_sig.len() != 64 {
            return Err(EnvelopeError::InvalidSignature);
        }
        sig_bytes.copy_from_slice(&self.ed25519_sig);

        let sig = Signature::from_bytes(&sig_bytes);
        ed25519_pub.verify(&hash, &sig).map_err(|_| EnvelopeError::InvalidSignature)?;

        if let Some(mldsa_pub) = mldsa65_pub {
            if let Some(mldsa_sig) = &self.mldsa65_sig {
                if mldsa_sig.len() != 3309 {
                    return Err(EnvelopeError::InvalidSignature);
                }
                let mut sig_array = [0u8; 3309];
                sig_array.copy_from_slice(mldsa_sig);

                let pq_sig = ml_dsa::Signature::<MlDsa65>::decode((&sig_array).into()).ok_or(EnvelopeError::InvalidSignature)?;
                use ml_dsa::signature::Verifier;
                mldsa_pub.verify(&hash, &pq_sig).map_err(|_| EnvelopeError::InvalidSignature)?;
            } else if require_pq_hybrid_signatures {
                return Err(EnvelopeError::MissingPqSignature);
            }
        }

        Ok(())
    }
}
