use std::str::FromStr;

use quick_protobuf::Writer;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use super::PublicKey;

const MAX_INLINE_KEY_LENGTH: usize = 42;

const MULTIHASH_IDENTITY_CODE: u64 = 0;
const MULTIHASH_SHA256_CODE: u64 = 0x12;

type Multihash = multihash::Multihash<64>;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PeerId(Multihash);

impl PeerId {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    #[must_use]
    pub fn to_base58(&self) -> String {
        bs58::encode(self.0.to_bytes()).into_string()
    }

    /// Create a `PeerId` from bytes.
    ///
    /// # Errors
    ///
    /// This function will return an error if the bytes do not represent a valid `PeerId`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        Self::from_multihash(Multihash::from_bytes(data)?)
            .map_err(|mh| ParseError::UnsupportedCode(mh.code()))
    }

    /// Create a `PeerId` from a multihash.
    ///
    /// # Errors
    ///
    /// This function will return an error if the multihash code is not supported.
    pub fn from_multihash(multihash: Multihash) -> Result<Self, Multihash> {
        match multihash.code() {
            MULTIHASH_SHA256_CODE => Ok(Self(multihash)),
            MULTIHASH_IDENTITY_CODE if multihash.digest().len() <= MAX_INLINE_KEY_LENGTH => {
                Ok(Self(multihash))
            }
            _ => Err(multihash),
        }
    }
}

impl From<PublicKey> for PeerId {
    fn from(key: PublicKey) -> Self {
        let encided = encode_ed25519(key.0.as_bytes());

        let multihash = if encided.len() <= MAX_INLINE_KEY_LENGTH {
            Multihash::wrap(MULTIHASH_IDENTITY_CODE, &encided)
                .expect("64 byte multihash provides sufficient space")
        } else {
            Multihash::wrap(MULTIHASH_SHA256_CODE, &sha2::Sha256::digest(encided))
                .expect("64 byte multihash provides sufficient space")
        };

        Self(multihash)
    }
}

impl std::fmt::Debug for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PeerId").field(&self.to_base58()).finish()
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_base58().fmt(f)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("base-58 decode error: {0}")]
    B58(#[from] bs58::decode::Error),
    #[error("unsupported multihash code '{0}'")]
    UnsupportedCode(u64),
    #[error("invalid multihash")]
    InvalidMultihash(#[from] multihash::Error),
}

impl FromStr for PeerId {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s).into_vec()?;
        let peer_id = PeerId::from_bytes(&bytes)?;

        Ok(peer_id)
    }
}

impl Serialize for PeerId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_base58())
        } else {
            serializer.serialize_bytes(&self.to_bytes()[..])
        }
    }
}

impl<'de> Deserialize<'de> for PeerId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error, Unexpected, Visitor};

        struct PeerIdVisitor;

        impl Visitor<'_> for PeerIdVisitor {
            type Value = PeerId;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "valid peer id")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: Error,
            {
                PeerId::from_bytes(v).map_err(|_| Error::invalid_value(Unexpected::Bytes(v), &self))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                PeerId::from_str(v).map_err(|_| Error::invalid_value(Unexpected::Str(v), &self))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(PeerIdVisitor)
        } else {
            deserializer.deserialize_bytes(PeerIdVisitor)
        }
    }
}

fn encode_ed25519(pubkey_bytes: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut writer = Writer::new(&mut buf);
        // Write field 1: Tag = (1 << 3) | 0 = 8. Write the enum wariant 1 for ed25519.
        writer
            .write_with_tag(8, |w| w.write_enum(1))
            .expect("could write enum variant");
        // Write field 2: Tag = (2 << 3) | 2 = 18. Write the 32 bytes.
        writer
            .write_with_tag(18, |w| w.write_bytes(&pubkey_bytes[..]))
            .expect("could write all 32 bytes of public key");
    }
    buf
}
