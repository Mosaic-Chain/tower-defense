use std::borrow::Cow;

use jsonrpsee::{
    core::{params::ObjectParams, traits::ToRpcParams},
    types::Id,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::{
    crypto::{Keypair, PeerId, PublicKey, Signature},
    error::Error,
};

pub mod timestamp;
pub use timestamp::VerifyTimestamp;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedParams<'a> {
    pub(crate) signer: PublicKey,
    pub(crate) signature: Signature,
    pub(crate) timestamp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) inner: Option<Cow<'a, RawValue>>,
}

#[derive(Debug, Clone)]
pub struct VerifiedParams<'a> {
    pub peer: PeerId,
    pub inner: Option<Cow<'a, RawValue>>,
}

impl<'a> AuthenticatedParams<'a> {
    /// Prepare authenticated params at a given timestamp.
    #[must_use]
    pub fn prepare(
        keypair: &Keypair,
        id: &Id<'_>,
        method: &str,
        params: Option<Cow<'a, RawValue>>,
        now: u64,
    ) -> Self {
        let signing_metarial = signing_material(now, id, method, params.as_ref());
        let signature = keypair.sign(&signing_metarial);

        Self {
            signer: keypair.public(),
            signature,
            timestamp: now,
            inner: params,
        }
    }

    /// Prepare authenticated params using the current `SystemTime`.
    ///
    /// # Errors
    ///
    /// This function will return an error if current timpestamp generation fails.
    pub fn prepare_now(
        keypair: &Keypair,
        id: &Id<'a>,
        method: &'a str,
        params: Option<Cow<'a, RawValue>>,
    ) -> Result<Self, Error> {
        Ok(Self::prepare(
            keypair,
            id,
            method,
            params,
            timestamp::now()?,
        ))
    }

    /// Verify authenticated params at a given timestamp.
    ///
    /// # Errors
    ///
    /// This function will return an error if the signature or timestamp verification fails.
    pub fn verify<VT: VerifyTimestamp>(
        self,
        id: &Id<'_>,
        method: &str,
        verify_timestamp: &VT,
    ) -> Result<VerifiedParams<'a>, Error> {
        let signing_metarial = signing_material(self.timestamp, id, method, self.inner.as_ref());
        self.signer.verify(&signing_metarial, &self.signature)?;

        let peer = PeerId::from(self.signer);

        if !verify_timestamp.verify(&peer, self.timestamp) {
            return Err(Error::InvalidTimestamp);
        }

        Ok(VerifiedParams {
            peer,
            inner: self.inner,
        })
    }
}

impl ToRpcParams for AuthenticatedParams<'_> {
    fn to_rpc_params(self) -> Result<Option<Box<RawValue>>, serde_json::Error> {
        let serde_json::Value::Object(obj) = serde_json::to_value(self)? else {
            unreachable!("this type will always be serialize as a map");
        };

        let mut p = ObjectParams::new();
        for (k, v) in obj {
            p.insert(&k, v)?;
        }

        p.to_rpc_params()
    }
}

fn signing_material(
    ts: u64,
    id: &Id<'_>,
    method: &str,
    params: Option<&Cow<'_, RawValue>>,
) -> Vec<u8> {
    // The raw json str or "" as bytes.
    let param_bytes = params.map(|i| i.get()).unwrap_or_default().as_bytes();
    [
        id.to_string().as_bytes(),
        ts.to_be_bytes().as_slice(),
        method.as_bytes(),
        param_bytes,
    ]
    .concat()
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use jsonrpsee::types::Id;
    use serde_json::value::RawValue;

    use super::*;
    use crate::auth::VerifyTimestamp;

    struct AcceptAll;

    impl VerifyTimestamp for AcceptAll {
        fn verify(&self, _peer: &PeerId, _timestamp: u64) -> bool {
            true
        }
    }

    fn keypair() -> Keypair {
        let mut raw = [0u8; 32];
        hex::decode_to_slice(
            "87ad5ca4be14d1a97c49b915bc6a33849425469921649f4ec970cad30c0d9a94",
            &mut raw,
        )
        .expect("valid key hex");
        Keypair::from_secret_bytes(&raw)
    }

    fn prepared() -> Result<AuthenticatedParams<'static>, Box<dyn std::error::Error>> {
        let params = Some(Cow::Owned(RawValue::from_string("[\"foo\"]".to_owned())?));

        Ok(AuthenticatedParams::prepare(
            &keypair(),
            &Id::Number(1),
            "echo",
            params,
            1_700_000_000_000,
        ))
    }

    fn verify(params: AuthenticatedParams<'_>) -> Result<(), Box<dyn std::error::Error>> {
        let verified = params.verify(&Id::Number(1), "echo", &AcceptAll)?;

        assert_eq!(verified.peer, PeerId::from(keypair().public()));

        Ok(())
    }

    #[test]
    fn legacy_byte_array_envelope_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
        verify(prepared()?)?;

        Ok(())
    }

    #[test]
    fn hex_and_base58_envelope_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
        let mut value = serde_json::to_value(prepared()?)?;
        let signer = Vec::<u8>::deserialize(&value["signer"])?;
        let signature = Vec::<u8>::deserialize(&value["signature"])?;

        value["signer"] = hex::encode(&signer).into();
        value["signature"] = format!("0x{}", hex::encode(&signature)).into();
        verify(serde_json::from_str(&serde_json::to_string(&value)?)?)?;

        value["signer"] = bs58::encode(&signer).into_string().into();
        value["signature"] = bs58::encode(&signature).into_string().into();
        verify(serde_json::from_str(&serde_json::to_string(&value)?)?)?;

        Ok(())
    }

    #[test]
    fn peer_id_envelope_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
        let mut value = serde_json::to_value(prepared()?)?;
        let signer = Vec::<u8>::deserialize(&value["signer"])?;
        let public = PublicKey::from_slice(&signer)?;

        value["signer"] = PeerId::from(public).to_base58().into();
        verify(serde_json::from_str(&serde_json::to_string(&value)?)?)?;

        Ok(())
    }
}
