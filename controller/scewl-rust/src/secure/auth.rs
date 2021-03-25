//! TODO: document full format of messages, protection mechanisms, etc. for this module and associated implementations

#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use crate::auth::Handler as AuthHandler;
use crate::controller::{Controller, Id, Message, SSSMessage, SSSOp};
use crate::cursor::{ReadCursor, WriteCursor};
use crate::interface::INTF;
use crate::secure::crypto::Handler as CryptoHandler;
use core::mem::size_of;

#[derive(Copy, Clone)]
pub struct Handler {
    private_id: u64,
}

#[derive(Copy, Clone)]
struct SecureSSSMessage {
    dev_id: Id,
    op: SSSOp,
    private_id: u64,
}

impl SecureSSSMessage {
    fn to_bytes(&self) -> [u8; 12] {
        let mut buf = [0_u8; 12];

        WriteCursor::new(&mut buf)
            .write_u16(self.dev_id.into())
            .write_i16(self.op.into())
            .write_u64(self.private_id);

        buf
    }
}

#[derive(Copy, Clone)]
struct SecureSSSResponse {
    dev_id: Id,
    op: SSSOp,
    secrets: Option<SecureSSSSecrets>,
}

#[derive(Copy, Clone)]
struct SecureSSSSecrets {
    seed: [u8; 32],
    aes_key: [u8; 16],
    hmac_key: [u8; 64],
}

impl SecureSSSResponse {
    fn from_bytes(buf: &[u8]) -> Option<SecureSSSResponse> {
        (buf.len() >= size_of::<u16>() + size_of::<i16>()).then(|| {
            let mut cur = ReadCursor::new(&buf);

            SecureSSSResponse {
                dev_id: cur.read_u16().into(),
                op: cur.read_i16().into(),
                secrets: (buf.len() == SecureSSSResponse::size()).then(|| SecureSSSSecrets {
                    seed: cur.read_32_u8(),
                    aes_key: cur.read_16_u8(),
                    hmac_key: cur.read_64_u8(),
                }),
            }
        })
    }

    const fn size() -> usize {
        size_of::<u16>()
            + size_of::<i16>()
            + size_of::<[u8; 32]>()
            + size_of::<[u8; 16]>()
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
            private_id: self.private_id,
        };
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
            .read_msg(INTF::SSS, SecureSSSResponse::size() as u16, true)
            .ok()?
            .len;
        let resp = SecureSSSResponse::from_bytes(&controller.data()[..len])?;

        let cpu_notify = SSSMessage {
            dev_id: resp.dev_id,
            op: resp.op,
        };

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

        let secrets = resp.secrets?;
        Some(CryptoHandler::new(
            secrets.seed,
            secrets.aes_key,
            secrets.hmac_key,
        ))
    }

    fn sss_deregister(self, controller: &mut Controller<Self, CryptoHandler>) -> bool {
        unimplemented!()
    }
}
