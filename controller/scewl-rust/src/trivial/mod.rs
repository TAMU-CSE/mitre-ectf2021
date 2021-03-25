//! A trivial implementation of controller security, as defined by the [original C implementation](https://github.com/mitre-cyber-academy/2021-ectf-insecure-example/blob/master/controller/controller.c)

pub use auth::Handler as AuthHandler;
pub use crypto::Handler as CryptoHandler;

mod auth;
mod crypto;
