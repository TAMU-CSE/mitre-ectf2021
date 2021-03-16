//! The cryptography module for the trivial implementation of the security features for the
//! controller -- which does absolutely nothing!

use crate::controller::{Message, SCEWL_MAX_DATA_SZ};
use crate::crypto::Handler;
use core::option::Option;
use core::option::Option::Some;

/// A trivial crypto handler, which does nothing!
pub struct NopCryptoHandler;

impl Handler for NopCryptoHandler {
    fn encrypt(&mut self, _: &mut [u8; SCEWL_MAX_DATA_SZ], message: Message) -> usize {
        message.len
    }

    fn decrypt(&mut self, _: &mut [u8; SCEWL_MAX_DATA_SZ], message: Message) -> Option<usize> {
        Some(message.len)
    }
}
