use crate::controller::{Message, SCEWL_MAX_DATA_SZ};
use crate::crypto::Handler;
use core::option::Option;
use core::option::Option::Some;

pub struct NopCryptoHandler;

impl Handler for NopCryptoHandler {
    fn encrypt(&mut self, _: &mut [u8; SCEWL_MAX_DATA_SZ], message: Message) -> Message {
        message
    }

    fn decrypt(&mut self, _: &mut [u8; SCEWL_MAX_DATA_SZ], message: Message) -> Option<Message> {
        Some(message)
    }
}
