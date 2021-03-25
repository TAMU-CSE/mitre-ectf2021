//! A theoretically secure implementation of the controller security features, which employs a
//! variety of protections against interception, modification, or replay attacks.
//!
//! See the associated modules for further details.

pub use auth::Handler as AuthHandler;
pub use crypto::Handler as CryptoHandler;
pub use test_auth::Handler as TestAuthHandler;

mod auth;
mod crypto;
mod test_auth;
