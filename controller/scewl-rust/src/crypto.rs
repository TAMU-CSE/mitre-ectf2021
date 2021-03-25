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
///  - [`encrypt`](Handler::encrypt) writes the verification for the message _first_ so that it may
///    be extracted and used to verify that a message is legitimate in [`verify`](Handler::verify).
///  - broadcasts are handled differently than direct messages, where appropriate for the encryption
///    mechanism chosen
///  - the internal state of the crypto handler is updated, where appropriate for the encryption
///    mechanism chosen
pub trait Handler {
    /// Verifies that a message is correct before continuing to read the message
    ///
    /// Your implementation should read the verification header, the length of which is described in
    /// [`verification_len`](Handler::verification_len) to ensure that a message is legitimate. If
    /// the message is not legitimate, return false and the controller will drop the remainder of
    /// the message. If it is, return true, and the controller will read the rest of the message and
    /// pass the message onto the encryption handler for further processing.
    ///
    /// This operation must always succeed.
    fn verify(&mut self, data: &[u8; SCEWL_MAX_DATA_SZ], msg: Message) -> bool;
    /// Defines the length of the verification header to be read
    ///
    /// This length will be used to inform the controller of how large the verification header is
    /// on the message. If no verification header is present, simply return 0.
    fn verification_len(&self) -> usize;
    /// Encrypts a message which is outbound to the radio and is not an FAA message
    ///
    /// Your implementation should modify the data structure in-place such that it may be
    /// immediately sent to the receiving SED(s) and immediately decrypted upon reception. The
    /// return value should be the new length of the message.
    ///
    /// This operation must always succeed.
    fn encrypt(&mut self, data: &mut [u8; SCEWL_MAX_DATA_SZ], msg: Message) -> usize;
    /// Decrypts a message which is inbound on the radio and is not an FAA message
    ///
    /// Your implementation should modify the data structure in-place such that it may be
    /// immediately sent to the CPU. The return value should be the new length of the message.
    ///
    /// This operation may fail in the case that decryption (or any other form of message
    /// verification) fails.
    fn decrypt(&mut self, data: &mut [u8; SCEWL_MAX_DATA_SZ], msg: Message) -> Option<usize>;
}
