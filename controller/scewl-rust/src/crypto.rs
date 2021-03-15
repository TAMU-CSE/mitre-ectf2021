use crate::controller::{Message, SCEWL_MAX_DATA_SZ};

pub trait Handler {
    fn encrypt(&mut self, data: &mut [u8; SCEWL_MAX_DATA_SZ], message: Message) -> Message;
    fn decrypt(&mut self, data: &mut [u8; SCEWL_MAX_DATA_SZ], message: Message) -> Option<Message>;
}
