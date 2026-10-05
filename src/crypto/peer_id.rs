use std::str::FromStr;

use ed25519_dalek::VerifyingKey;
use quick_protobuf::{BytesReader, Writer};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use super::PublicKey;

const MAX_INLINE_KEY_LENGTH: usize = 42;

const MULTIHASH_IDENTITY_CODE: u64 = 0;
const MULTIHASH_SHA256_CODE: u64 = 0x12;

const KEY_TYPE_TAG: u32 = 8;
const KEY_DATA_TAG: u32 = 18;
const ED25519_KEY_TYPE: i32 = 1;
const ED25519_PUBLIC_KEY_LENGTH: usize = 32;

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

impl TryFrom<PeerId> for PublicKey {
    type Error = ParseError;

    fn try_from(peer_id: PeerId) -> Result<Self, Self::Error> {
        if peer_id.0.code() != MULTIHASH_IDENTITY_CODE {
            return Err(ParseError::NotIdentity);
        }

        decode_ed25519(peer_id.0.digest()).map(Into::into)
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
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("unsupported multihash code '{0}'")]
    UnsupportedCode(u64),
    #[error("invalid multihash")]
    InvalidMultihash(#[from] multihash::Error),
    #[error("peer id does not use the identity multihash, its public key cannot be recovered")]
    NotIdentity,
    #[error("missing ed25519 public key")]
    MissingKey,
    #[error("unsupported key type, expected ed25519")]
    UnsupportedKeyType,
    #[error("invalid ed25519 public key length: expected 32, got {0}")]
    InvalidKeyLength(usize),
    #[error("protobuf decode error: {0}")]
    Protobuf(#[from] quick_protobuf::Error),
    #[error("invalid ed25519 public key: {0}")]
    InvalidKey(#[from] ed25519_dalek::SignatureError),
    #[error("could not decode as hex or base-58")]
    UnknownEncoding,
}

impl FromStr for PeerId {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = super::str_as_bytes(s).map_err(|_| ParseError::UnknownEncoding)?;

        PeerId::from_bytes(&bytes)
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
            .write_with_tag(KEY_TYPE_TAG, |w| w.write_enum(1))
            .expect("could write enum variant");
        // Write field 2: Tag = (2 << 3) | 2 = 18. Write the 32 bytes.
        writer
            .write_with_tag(KEY_DATA_TAG, |w| w.write_bytes(&pubkey_bytes[..]))
            .expect("could write all 32 bytes of public key");
    }
    buf
}

fn decode_ed25519(digest: &[u8]) -> Result<VerifyingKey, ParseError> {
    let mut reader = BytesReader::from_bytes(digest);
    let mut key_type = None;
    let mut key_data = None;

    while !reader.is_eof() {
        let tag = reader.next_tag(digest)?;

        match tag {
            KEY_TYPE_TAG => key_type = Some(reader.read_enum::<i32>(digest)?),
            KEY_DATA_TAG => key_data = Some(reader.read_bytes(digest)?),
            _ => reader.read_unknown(digest, tag)?,
        }
    }

    if key_type != Some(ED25519_KEY_TYPE) {
        return Err(ParseError::UnsupportedKeyType);
    }

    let key_data = key_data.ok_or(ParseError::MissingKey)?;
    let key_data: &[u8; ED25519_PUBLIC_KEY_LENGTH] = key_data
        .try_into()
        .map_err(|_| ParseError::InvalidKeyLength(key_data.len()))?;

    Ok(VerifyingKey::from_bytes(key_data)?)
}

#[cfg(test)]
mod test {
    use sha2::Sha256;

    use super::*;
    use crate::crypto::Keypair;

    const PEER_ID: &str = "12D3KooWDZy8EabSzFCSSNZFRvUpkhLAb1WCTv3KVEYJuryW9H1N";

    fn keypair() -> Keypair {
        let mut signing_key_raw = [0u8; 32];
        hex::decode_to_slice(
            "87ad5ca4be14d1a97c49b915bc6a33849425469921649f4ec970cad30c0d9a94",
            &mut signing_key_raw,
        )
        .expect("valid key hex");
        Keypair::from_secret_bytes(&signing_key_raw)
    }

    #[test]
    fn example_1() -> Result<(), Box<dyn std::error::Error>> {
        let peer_id = PeerId::from(keypair().public());

        assert_eq!(peer_id.to_base58(), PEER_ID);

        Ok(())
    }

    #[test]
    fn parses_base58_and_hex() -> Result<(), Box<dyn std::error::Error>> {
        let peer_id = PeerId::from(keypair().public());
        let hex = hex::encode(peer_id.to_bytes());

        assert_eq!(PEER_ID.parse::<PeerId>()?, peer_id);
        assert_eq!(hex.parse::<PeerId>()?, peer_id);
        assert_eq!(format!("0x{hex}").parse::<PeerId>()?, peer_id);

        let json = serde_json::to_string(&hex)?;
        assert_eq!(serde_json::from_str::<PeerId>(&json)?, peer_id);

        let json = serde_json::to_string(&peer_id)?;
        assert_eq!(json, serde_json::to_string(PEER_ID)?);
        assert_eq!(serde_json::from_str::<PeerId>(&json)?, peer_id);

        Ok(())
    }

    #[test]
    fn converts_back_to_public_key() -> Result<(), Box<dyn std::error::Error>> {
        let keypair = keypair();
        let peer_id = PeerId::from(keypair.public());
        let public = PublicKey::try_from(peer_id)?;

        assert_eq!(public.0.as_bytes(), keypair.public().0.as_bytes());

        Ok(())
    }

    #[test]
    fn sha256_peer_id_cannot_be_converted() -> Result<(), Box<dyn std::error::Error>> {
        let digest = Sha256::digest([0u8; 32]);
        let multihash = Multihash::wrap(MULTIHASH_SHA256_CODE, &digest)?;
        let peer_id = PeerId::from_multihash(multihash).expect("multihash code works");

        assert!(PublicKey::try_from(peer_id).is_err());

        Ok(())
    }

    #[test]
    fn symmetric_encoding() -> Result<(), Box<dyn std::error::Error>> {
        let public_key = keypair().public();

        let encoded = encode_ed25519(public_key.0.as_bytes());

        let decoded = decode_ed25519(&encoded)?;

        assert_eq!(public_key.0.as_bytes(), decoded.as_bytes());

        Ok(())
    }
}
