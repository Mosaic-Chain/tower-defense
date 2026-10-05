#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Signature: {0}")]
    Signature(#[from] ed25519_dalek::SignatureError),

    #[error("Invalid timestamp")]
    InvalidTimestamp,

    #[error("SystemTime error: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),

    #[error("TryFromInt error: {0}")]
    TryFromInt(#[from] std::num::TryFromIntError),

    #[error("Hex decoding error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("Base58 decoding error: {0}")]
    Base58(#[from] bs58::decode::Error),

    #[error("Invalid length: expected {expected} bytes, got {got}")]
    InvalidLength { expected: usize, got: usize },

    #[error("Could not parse public key from hex or SS58")]
    Keyparse,
}
