use ed25519_dalek::{self as ed25519, Signer as _, SigningKey, Verifier as _};
use serde::{Deserialize, Serialize};

use crate::error::Error;

pub mod peer_id;
pub use peer_id::PeerId;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Keypair(ed25519::SigningKey);

impl Keypair {
    #[must_use]
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(bytes))
    }

    #[must_use]
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.0.sign(data).into()
    }

    #[must_use]
    pub fn public(&self) -> PublicKey {
        self.0.verifying_key().into()
    }
}

impl From<ed25519::SigningKey> for Keypair {
    fn from(key: ed25519::SigningKey) -> Self {
        Self(key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicKey(ed25519::VerifyingKey);

impl PublicKey {
    /// Verify signature.
    ///
    /// # Errors
    ///
    /// This function will return an error if the verification fails.
    pub fn verify(&self, data: &[u8], signature: &Signature) -> Result<(), Error> {
        self.0.verify(data, &signature.0).map_err(Into::into)
    }
}

impl From<ed25519::VerifyingKey> for PublicKey {
    fn from(key: ed25519::VerifyingKey) -> Self {
        Self(key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Signature(ed25519::Signature);

impl From<ed25519::Signature> for Signature {
    fn from(signature: ed25519::Signature) -> Self {
        Self(signature)
    }
}
