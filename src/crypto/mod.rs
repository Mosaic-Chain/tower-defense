use std::fmt;

use ed25519_dalek::{self as ed25519, Signer as _, SigningKey, Verifier as _};
use serde::{
    Deserialize, Serialize,
    de::{self, SeqAccess, Visitor},
};

use crate::error::Error;

pub mod peer_id;
pub use peer_id::PeerId;

const PUBLIC_KEY_LENGTH: usize = 32;
const SIGNATURE_LENGTH: usize = 64;

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

#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct PublicKey(ed25519::VerifyingKey);

impl PublicKey {
    /// Create a public key from raw bytes.
    ///
    /// # Errors
    ///
    /// This function will return an error if the bytes are not a valid ed25519 public key.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> Result<Self, Error> {
        ed25519::VerifyingKey::from_bytes(bytes)
            .map(Into::into)
            .map_err(Into::into)
    }

    /// Create a public key from a byte slice.
    ///
    /// # Errors
    ///
    /// This function will return an error if the slice is not exactly 32 bytes long or is not a
    /// valid ed25519 public key.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; PUBLIC_KEY_LENGTH] =
            bytes.try_into().map_err(|_| Error::InvalidLength {
                expected: PUBLIC_KEY_LENGTH,
                got: bytes.len(),
            })?;

        Self::from_bytes(bytes)
    }

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

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PublicKeyVisitor;

        impl<'de> Visitor<'de> for PublicKeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(
                    "an ed25519 public key as a byte array, a hex string, a base58 public key \
                     or a base58 PeerId",
                )
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = [0u8; PUBLIC_KEY_LENGTH];

                for (i, byte) in bytes.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }

                if seq.next_element::<u8>()?.is_some() {
                    return Err(de::Error::invalid_length(PUBLIC_KEY_LENGTH + 1, &self));
                }

                PublicKey::from_bytes(&bytes).map_err(de::Error::custom)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                PublicKey::from_slice(v).map_err(E::custom)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                decode_public_key(v).map_err(E::custom)
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_any(PublicKeyVisitor)
        } else {
            deserializer.deserialize_bytes(PublicKeyVisitor)
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct Signature(ed25519::Signature);

impl Signature {
    /// Create a signature from a byte slice.
    ///
    /// # Errors
    ///
    /// This function will return an error if the slice is not exactly 64 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; SIGNATURE_LENGTH] =
            bytes.try_into().map_err(|_| Error::InvalidLength {
                expected: SIGNATURE_LENGTH,
                got: bytes.len(),
            })?;

        Ok(ed25519::Signature::from_bytes(bytes).into())
    }
}

impl From<ed25519::Signature> for Signature {
    fn from(signature: ed25519::Signature) -> Self {
        Self(signature)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SignatureVisitor;

        impl<'de> Visitor<'de> for SignatureVisitor {
            type Value = Signature;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(
                    "an ed25519 signature as a byte array, a hex string or a base58 string",
                )
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = [0u8; SIGNATURE_LENGTH];

                for (i, byte) in bytes.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }

                if seq.next_element::<u8>()?.is_some() {
                    return Err(de::Error::invalid_length(SIGNATURE_LENGTH + 1, &self));
                }

                Signature::from_slice(&bytes).map_err(de::Error::custom)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Signature::from_slice(v).map_err(E::custom)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                decode_signature(v).map_err(E::custom)
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_any(SignatureVisitor)
        } else {
            deserializer.deserialize_tuple(SIGNATURE_LENGTH, SignatureVisitor)
        }
    }
}

fn decode_public_key(s: &str) -> Result<PublicKey, Error> {
    if let Ok(key) = str_as_bytes(s).and_then(|bytes| PublicKey::from_slice(&bytes)) {
        return Ok(key);
    }

    s.parse::<PeerId>()
        .and_then(PublicKey::try_from)
        .map_err(|_| Error::Keyparse)
}

fn decode_signature(s: &str) -> Result<Signature, Error> {
    let bytes = str_as_bytes(s)?;

    Signature::from_slice(&bytes)
}

fn str_as_bytes(s: &str) -> Result<Vec<u8>, Error> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");

    Ok(hex::decode(s).or_else(|_| bs58::decode(s).into_vec())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> Keypair {
        let mut raw = [0u8; 32];
        hex::decode_to_slice(
            "87ad5ca4be14d1a97c49b915bc6a33849425469921649f4ec970cad30c0d9a94",
            &mut raw,
        )
        .expect("valid key hex");
        Keypair::from_secret_bytes(&raw)
    }

    #[test]
    fn public_key_serializes_as_byte_array() -> Result<(), Box<dyn std::error::Error>> {
        let public = keypair().public();
        let expected: Vec<u8> = public.0.as_bytes().to_vec();

        assert_eq!(
            serde_json::to_value(&public)?,
            serde_json::to_value(expected)?
        );

        Ok(())
    }

    #[test]
    fn public_key_deserializes_from_supported_formats() -> Result<(), Box<dyn std::error::Error>> {
        let public = keypair().public();
        let raw = public.0.as_bytes();

        let legacy: PublicKey = serde_json::from_str(&serde_json::to_string(&public)?)?;
        assert_eq!(legacy.0.as_bytes(), raw);

        let inputs = [
            hex::encode(raw),
            format!("0x{}", hex::encode(raw)),
            hex::encode(raw).to_uppercase(),
            bs58::encode(raw).into_string(),
            PeerId::from(public.clone()).to_base58(),
        ];

        for input in inputs {
            let decoded: PublicKey = serde_json::from_str(&serde_json::to_string(&input)?)?;
            assert_eq!(decoded.0.as_bytes(), raw, "input: {input}");
        }

        Ok(())
    }

    #[test]
    fn public_key_rejects_invalid_input() {
        for input in ["\"\"", "\"not a key\"", "\"0xzz\"", "[]", "null", "42"] {
            assert!(
                serde_json::from_str::<PublicKey>(input).is_err(),
                "input: {input}"
            );
        }
    }

    #[test]
    fn signature_serializes_as_byte_array() -> Result<(), Box<dyn std::error::Error>> {
        let signature = keypair().sign(b"hello");
        let expected: Vec<u8> = signature.0.to_bytes().to_vec();

        assert_eq!(
            serde_json::to_value(&signature)?,
            serde_json::to_value(expected)?
        );

        Ok(())
    }

    #[test]
    fn signature_deserializes_from_supported_formats() -> Result<(), Box<dyn std::error::Error>> {
        let signature = keypair().sign(b"hello");
        let raw = signature.0.to_bytes();

        let legacy: Signature = serde_json::from_str(&serde_json::to_string(&signature)?)?;
        assert_eq!(legacy.0.to_bytes(), raw);

        let inputs = [
            hex::encode(raw),
            format!("0x{}", hex::encode(raw)),
            hex::encode(raw).to_uppercase(),
            bs58::encode(raw).into_string(),
        ];

        for input in inputs {
            let decoded: Signature = serde_json::from_str(&serde_json::to_string(&input)?)?;
            assert_eq!(decoded.0.to_bytes(), raw, "input: {input}");
        }

        Ok(())
    }

    #[test]
    fn signature_rejects_invalid_input() {
        for input in ["\"\"", "\"0x12\"", "[]", "null", "7"] {
            assert!(
                serde_json::from_str::<Signature>(input).is_err(),
                "input: {input}"
            );
        }
    }
}
