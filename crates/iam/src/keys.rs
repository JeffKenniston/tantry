use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Ed25519Seed(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsa65SigningKey(pub Vec<u8>);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(pub [u8; 32]); // 256-bit

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DekKey(pub Vec<u8>);
