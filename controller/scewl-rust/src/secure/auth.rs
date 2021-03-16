//! TODO: document full format of messages, protection mechanisms, etc. for this module and associated implementations

#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use crate::auth::Handler;
use crate::controller::{Controller, Id, Message, SSSMessage, SSSOp};
use crate::cursor::{ReadCursor, WriteCursor};
use crate::interface::INTF;
use crate::secure::crypto::SecureHandler as CryptoHandler;
use core::mem::size_of;
use core::mem::size_of_val;

#[derive(Copy, Clone)]
struct SecureHandler {
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
    seed: Option<[u8; 32]>,
    aes_key: Option<[u8; 16]>,
    hmac_key: Option<[u8; 16]>,
}

impl SecureSSSResponse {
    fn from_bytes(buf: &[u8]) -> Option<SecureSSSResponse> {
        (buf.len() >= size_of::<u16>() + size_of::<i16>()).then(|| {
            let mut cur = ReadCursor::new(&buf);
            let mut resp = SecureSSSResponse {
                dev_id: cur.read_u16().into(),
                op: cur.read_i16().into(),
                seed: None,
                aes_key: None,
                hmac_key: None,
            };

            // TODO: since we either have all 3 crypto values or we don't,
            // it's probably better to use an Option<(T, T, T)> or another
            // wrapper struct instead of separate Options
            if buf.len() == SecureSSSResponse::size() {
                resp.seed = Some(cur.read_32_u8());
                resp.aes_key = Some(cur.read_16_u8());
                resp.hmac_key = Some(cur.read_16_u8());
            }

            resp
        })
    }

    const fn size() -> usize {
        size_of::<u16>()
            + size_of::<i16>()
            + size_of::<[u8; 32]>()
            + size_of::<[u8; 16]>()
            + size_of::<[u8; 16]>()
    }
}

impl Handler<CryptoHandler> for SecureHandler {
    fn sss_register(
        self,
        controller: &mut Controller<Self, CryptoHandler>,
    ) -> Option<CryptoHandler> {
        let message = SecureSSSMessage {
            dev_id: controller.id(),
            op: SSSOp::Register,
            private_id: self.private_id,
        };
        let mesbuf = message.to_bytes();

        controller.data()[0..size_of_val(&mesbuf)].clone_from_slice(&mesbuf);

        controller
            .send_msg(
                &INTF::SSS,
                &Message {
                    tgt_id: Id::SSS,
                    src_id: controller.id(),
                    len: size_of_val(&mesbuf),
                },
            )
            .ok()?;

        #[allow(clippy::cast_possible_truncation)]
        // truncation permissible for this response size
        let len = controller
            .read_msg(&INTF::SSS, SecureSSSResponse::size() as u16, true)
            .ok()?
            .len;
        let resp = SecureSSSResponse::from_bytes(&controller.data()[..len])?;

        let cpu_notify = SSSMessage {
            dev_id: resp.dev_id,
            op: resp.op,
        };
        let cn_buf = cpu_notify.to_bytes();

        controller.data()[0..size_of_val(&cn_buf)].clone_from_slice(&cn_buf);

        controller
            .send_msg(
                &INTF::CPU,
                &Message {
                    tgt_id: controller.id(),
                    src_id: Id::SSS,
                    len: SSSMessage::size(),
                },
            )
            .ok()?;

        Some(CryptoHandler::new(
            resp.seed?,
            resp.aes_key?,
            resp.hmac_key?,
        ))
    }

    fn sss_deregister(self, controller: &mut Controller<Self, CryptoHandler>) -> bool {
        unimplemented!()
    }
}
