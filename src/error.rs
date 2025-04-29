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
}
