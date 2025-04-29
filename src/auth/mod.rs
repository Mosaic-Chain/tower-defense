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
