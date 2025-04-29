use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, UNIX_EPOCH},
};

use crate::{crypto::PeerId, error::Error};

pub trait VerifyTimestamp {
    fn verify(&self, peer: &PeerId, timestamp: u64) -> bool;
}

#[derive(Debug, Clone)]
pub struct WithinDuration(pub Duration);

impl VerifyTimestamp for WithinDuration {
    fn verify(&self, _peer: &PeerId, timestamp: u64) -> bool {
        let Ok(now) = now() else {
            // now is not valid, we cant compare
            return false;
        };

        Duration::from_millis(now.abs_diff(timestamp)) < self.0
    }
}

#[derive(Debug, Clone)]
pub struct LaterThanLast {
    log: Arc<Mutex<HashMap<PeerId, u64>>>,
}

impl Default for LaterThanLast {
    fn default() -> Self {
        Self {
            log: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl VerifyTimestamp for LaterThanLast {
    fn verify(&self, peer: &PeerId, timestamp: u64) -> bool {
        let Ok(mut log) = self.log.lock() else {
            return false;
        };

        let Some(last) = log.get(peer) else {
            log.insert(peer.clone(), timestamp);
            return true;
        };

        if *last >= timestamp {
            return false;
        }

        log.insert(peer.clone(), timestamp);

        true
    }
}

/// Number of milliseconds from the unix epoch
pub(crate) fn now() -> Result<u64, Error> {
    let millis = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis();

    Ok(u64::try_from(millis)?)
}
