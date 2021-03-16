//! Defines the trait for authentication via SSS. This is segmented out in its own module mostly for
//! visual clarity.
//!
//! See [Handler](Handler) for details on how authentication handlers should be defined.

use crate::controller::Controller;
use crate::crypto::Handler as CryptoHandler;

/// Defines basic methods required for SSS registration and deregistration.
///
/// Your implementation should conform to the data and serialisations defined by your `sss.py`
/// and instantiate an appropriate [crypto handler](crate::crypto::Handler) to handle
/// cryptographic operations during runtime.
///
/// It is expected that your SSS will define values necessary for communications between SEDs.
/// Ensure that your `sss.py` sufficiently provides any secrets necessary for communications to
/// the controller so that they may be used by your crypto handler.
pub trait Handler<C: CryptoHandler>: Copy {
    /// Register with the SSS. If the registration is successful, it should return a filled [Option](core::option::Option)
    /// containing the associated [crypto handler](crate::crypto::Handler). If it is not
    /// successful, the return value should be [None](core::option::Option::None).
    fn sss_register(self, controller: &mut Controller<Self, C>) -> Option<C>;

    /// Deregister with the SSS. Return true if deregistration was successful, false otherwise.
    fn sss_deregister(self, controller: &mut Controller<Self, C>) -> bool;
}
