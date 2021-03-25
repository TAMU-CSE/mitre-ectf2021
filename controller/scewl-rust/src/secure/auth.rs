//! The authentication module for the secure implementation of the SSS registration for the
//! controller
//!
//! This implementation differs very little from the original design; the only distinctions are:
//!
//!  - a secret (unique per SED) is appended to the end of registration and deregistration messages
//!    from the controller, which is compared by the SSS to confirm a successful registration
//!  - a global AES key, a global HMAC key, and a unique (runtime-generated) seed is sent by the SSS
//!    as the response to a successful registration
//!
//! Otherwise, this implementation matches the original SSS registration pattern nearly identically.

use core::mem::size_of;

use crate::auth::Handler as AuthHandler;
use crate::controller::{Controller, Id, Message, SSSMessage, SSSOp};
use crate::cursor::{ReadCursor, WriteCursor};
use crate::debug;
use crate::interface::INTF;
use crate::secure::crypto::Handler as CryptoHandler;

/// Authentication handler for the secure implementation of the controller
#[derive(Copy, Clone)]
pub struct Handler {
    /// The shared secret used for registration
    secret: &'static [u8; 64],
}

impl Handler {
    /// Instantiates a new authentication handler with the given shared secret for registration
    pub fn new(secret: &'static [u8; 64]) -> Self {
        Self { secret }
    }
}

/// A secure SSS message, to be sent at (de)registration to the SSS
#[derive(Debug, Copy, Clone)]
struct SecureSSSMessage {
    /// The id of the device registering
    dev_id: Id,
    /// The operation being requested
    op: SSSOp,
    /// The shared secret to be verified
    secret: &'static [u8; 64],
}

impl SecureSSSMessage {
    /// Serialises this message to bytes
    fn to_bytes(&self) -> [u8; SecureSSSMessage::size()] {
        let mut buf = [0_u8; SecureSSSMessage::size()];

        WriteCursor::new(&mut buf)
            .write_u16(self.dev_id.into())
            .write_i16(self.op.into())
            .write(self.secret);

        buf
    }

    /// The constant size of a secure SSS message
    const fn size() -> usize {
        size_of::<u16>() + size_of::<i16>() + size_of::<[u8; 64]>()
    }
}

/// A secure SSS response, which is expected as the result of an SSS registration attempt
#[derive(Debug, Copy, Clone)]
struct SecureSSSResponse {
    /// The id of the device registering
    dev_id: Id,
    /// The operation which took place
    op: SSSOp,
    /// The secrets passed as part of the response, if present
    secrets: Option<SecureSSSSecrets>,
}

/// The secrets which are passed as a result of a successful registration
#[derive(Debug, Copy, Clone)]
struct SecureSSSSecrets {
    /// The global AES key
    aes_key: [u8; 16],
    /// The seed to be used for random data generation
    seed: [u8; 32],
    /// The global HMAC key
    hmac_key: [u8; 64],
}

impl SecureSSSResponse {
    /// Deserialise a response from a buffer of bytes
    fn from_bytes(buf: &[u8]) -> Option<SecureSSSResponse> {
        (buf.len() >= size_of::<u16>() + size_of::<i16>()).then(|| {
            let mut cur = ReadCursor::new(&buf);

            SecureSSSResponse {
                dev_id: cur.read_u16().into(),
                op: cur.read_i16().into(),
                secrets: (buf.len() == SecureSSSResponse::size()).then(|| SecureSSSSecrets {
                    aes_key: cur.read_literal(),
                    seed: cur.read_literal(),
                    hmac_key: cur.read_literal(),
                }),
            }
        })
    }

    /// The constant size of a secure SSS response
    const fn size() -> usize {
        size_of::<u16>()
            + size_of::<i16>()
            + size_of::<[u8; 16]>()
            + size_of::<[u8; 32]>()
            + size_of::<[u8; 64]>()
    }
}

impl AuthHandler<CryptoHandler> for Handler {
    fn sss_register(
        self,
        controller: &mut Controller<Self, CryptoHandler>,
    ) -> Option<CryptoHandler> {
        let msg = SecureSSSMessage {
            dev_id: controller.id(),
            op: SSSOp::Register,
            secret: self.secret,
        };
        debug!("Sending secure SSS message: {:?}", msg);

        let msg_buf = msg.to_bytes();
        WriteCursor::new(controller.data()).write(&msg_buf);

        controller
            .send_msg(
                INTF::SSS,
                &Message {
                    tgt_id: Id::SSS,
                    src_id: controller.id(),
                    len: msg_buf.len(),
                },
            )
            .ok()?;

        #[allow(clippy::cast_possible_truncation)]
        // truncation permissible for this response size
        let len = controller
            .read_msg(INTF::SSS, SecureSSSResponse::size() as u16)
            .ok()?
            .len;
        let resp = SecureSSSResponse::from_bytes(&controller.data()[..len])?;

        debug!("Received secure SSS response: {:?}", resp);

        let cpu_notify = SSSMessage {
            dev_id: resp.dev_id,
            op: resp.op,
        };

        debug!("Notifying CPU of response: {:?}", cpu_notify);

        WriteCursor::new(controller.data()).write(&cpu_notify.to_bytes());

        controller
            .send_msg(
                INTF::CPU,
                &Message {
                    tgt_id: controller.id(),
                    src_id: Id::SSS,
                    len: SSSMessage::size(),
                },
            )
            .ok()?;

        debug!("Initialising crypto handler");

        resp.secrets
            .map(|secrets| CryptoHandler::new(secrets.seed, secrets.aes_key, secrets.hmac_key))
    }

    fn sss_deregister(self, controller: &mut Controller<Self, CryptoHandler>) -> bool {
        let msg = SecureSSSMessage {
            dev_id: controller.id(),
            op: SSSOp::Deregister,
            secret: self.secret,
        };
        debug!("Sending secure SSS message: {:?}", msg);

        let msg_buf = msg.to_bytes();
        WriteCursor::new(controller.data()).write(&msg_buf);

        if controller
            .send_msg(
                INTF::SSS,
                &Message {
                    tgt_id: Id::SSS,
                    src_id: controller.id(),
                    len: msg_buf.len(),
                },
            )
            .is_err()
        {
            return false;
        }

        #[allow(clippy::cast_possible_truncation)]
        // truncation permissible for this response size
        let len = match controller.read_msg(INTF::SSS, SecureSSSResponse::size() as u16) {
            Ok(msg) => msg.len,
            Err(_) => return false,
        };

        let resp = match SecureSSSResponse::from_bytes(&controller.data()[..len]) {
            None => return false,
            Some(resp) => resp,
        };

        debug!("Received secure SSS response: {:?}", resp);

        let cpu_notify = SSSMessage {
            dev_id: resp.dev_id,
            op: resp.op,
        };

        debug!("Notifying CPU of response: {:?}", cpu_notify);

        WriteCursor::new(controller.data()).write(&cpu_notify.to_bytes());

        if controller
            .send_msg(
                INTF::CPU,
                &Message {
                    tgt_id: controller.id(),
                    src_id: Id::SSS,
                    len: SSSMessage::size(),
                },
            )
            .is_err()
        {
            return false;
        }

        resp.op == SSSOp::Deregister
    }
}
