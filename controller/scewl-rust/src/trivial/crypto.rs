//! The cryptography module for the trivial implementation of the security features for the
//! controller -- which does absolutely nothing!

use crate::controller::{Message, SCEWL_MAX_DATA_SZ};
use crate::crypto::Handler as CryptoHandler;

/// A trivial crypto handler, which does nothing!
pub struct Handler;

impl CryptoHandler for Handler {
    fn verify(&mut self, _: &[u8; SCEWL_MAX_DATA_SZ], _: Message) -> bool {
        true
    }

    fn verification_len(&self) -> usize {
        0
    }

    fn encrypt(&mut self, _: &mut [u8; SCEWL_MAX_DATA_SZ], msg: Message) -> usize {
        msg.len
    }

    fn decrypt(&mut self, _: &mut [u8; SCEWL_MAX_DATA_SZ], msg: Message) -> Option<usize> {
        Some(msg.len)
    }
}
