//! Defines the trait for the crypto handler, which encrypts direct messages to other SEDs and
//! broadcasts. This is segmented out in its own module mostly for visual clarity.
//!
//! See [Handler](Handler) for details on how crypto handlers should be defined.

use crate::controller::{Message, SCEWL_MAX_DATA_SZ};

/// Defines the basic methods for decrypting/encrypting messages to/from the CPU and radio where
/// appropriate.
///
/// Your implementation should ensure that:
///  - messages are encrypted/decrypted uniformly (the data buffer will hold the exactly same
///    content between cleartext and encryption + decryption)
///  - broadcasts are handled differently than direct messages, where appropriate for the encryption
///    mechanism chosen
///  - the internal state of the crypto handler is updated, where appropriate for the encryption
///    mechanism chosen
pub trait Handler {
    /// Encrypts a message which is outbound to the radio and is not an FAA message
    ///
    /// Your implementation should modify the data structure in-place such that it may be
    /// immediately sent to the receiving SED(s) and immediately decrypted upon reception. The
    /// return value should be the new length of the message.
    ///
    /// This operation must always succeed.
    fn encrypt(&mut self, data: &mut [u8; SCEWL_MAX_DATA_SZ], message: Message) -> usize;
    /// Decrypts a message which is inbound on the radio and is not an FAA message
    ///
    /// Your implementation should modify the data structure in-place such that it may be
    /// immediately sent to the CPU. The return value should be the new length of the message.
    ///
    /// This operation may fail in the case that decryption (or any other form of message
    /// verification) fails.
    fn decrypt(&mut self, data: &mut [u8; SCEWL_MAX_DATA_SZ], message: Message) -> Option<usize>;
}
