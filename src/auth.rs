use std::{
    borrow::Cow,
    time::{Duration, UNIX_EPOCH},
};

use jsonrpsee::{
    core::{params::ObjectParams, traits::ToRpcParams},
    types::Id,
};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::{
    crypto::{Keypair, PublicKey, Signature},
    error::Error,
};

#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticatedParams<'a> {
    pub(crate) signer: PublicKey,
    pub(crate) signature: Signature,
    pub(crate) timestamp: u64,
    pub(crate) inner: Option<Cow<'a, RawValue>>,
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
        Ok(Self::prepare(keypair, id, method, params, now()?))
    }

    /// Verify authenticated params at a given timestamp.
    ///
    /// # Errors
    ///
    /// This function will return an error if the signature or timestamp verification fails.
    pub fn verify(&self, id: &Id<'_>, method: &str, now: u64) -> Result<(), Error> {
        if Duration::from_millis(now.abs_diff(self.timestamp)) > Duration::from_secs(5) {
            return Err(Error::InvalidTimestamp);
        }

        let signing_metarial = signing_material(self.timestamp, id, method, self.inner.as_ref());
        self.signer.verify(&signing_metarial, &self.signature)?;

        Ok(())
    }

    /// Verify authenticated params using the current `SystemTime`.
    ///
    /// # Errors
    ///
    /// This function will return an error if the signature or timestamp verification fails.
    pub fn verify_now(&self, id: &Id<'_>, method: &str) -> Result<(), Error> {
        self.verify(id, method, now()?)
    }
}

impl ToRpcParams for AuthenticatedParams<'_> {
    fn to_rpc_params(self) -> Result<Option<Box<RawValue>>, serde_json::Error> {
        let mut p = ObjectParams::new();
        p.insert("signer", self.signer)?;
        p.insert("signature", self.signature)?;
        p.insert("timestamp", self.timestamp)?;
        p.insert("inner", self.inner)?;

        p.to_rpc_params()
    }
}

/// Number of milliseconds from the unix epoch
fn now() -> Result<u64, Error> {
    let millis = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis();

    Ok(u64::try_from(millis)?)
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
