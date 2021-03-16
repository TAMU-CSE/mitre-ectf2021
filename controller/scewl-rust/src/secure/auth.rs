//! TODO: document full format of messages, protection mechanisms, etc. for this module and associated implementations

#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use crate::auth::Handler;
use crate::controller::{Controller, Id, Message, SSSMessage, SSSOp};
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
        buf[0..size_of::<u16>()].clone_from_slice(&u16::from(self.dev_id).to_ne_bytes());
        buf[size_of::<u16>()..(size_of::<u16>() + size_of::<i16>())]
            .clone_from_slice(&i16::from(self.op).to_ne_bytes());
        buf[(size_of::<u16>() + size_of::<i16>())
            ..(size_of::<u16>() + size_of::<i16>() + size_of::<u64>())]
            .clone_from_slice(&self.private_id.to_ne_bytes());
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
        if buf.len() >= size_of::<u16>() + size_of::<i16>() {
            let mut min;
            let mut max = 0;

            let mut resp = SecureSSSResponse {
                dev_id: Id::Other(0),
                op: SSSOp::Unknown,
                seed: None,
                aes_key: None,
                hmac_key: None,
            };
            min = max;
            let mut dev_id = [0_u8; size_of::<u16>()];
            max += size_of_val(&dev_id);
            dev_id.clone_from_slice(&buf[min..max]);
            resp.dev_id = u16::from_ne_bytes(dev_id).into();

            min = max;
            let mut op = [0_u8; size_of::<i16>()];
            max += size_of_val(&op);
            op.clone_from_slice(&buf[min..max]);
            resp.op = i16::from_ne_bytes(op).into();

            if buf.len() == SecureSSSResponse::size() {
                min = max;
                let mut seed = [0_u8; size_of::<[u8; 32]>()];
                max += size_of_val(&seed);
                seed.clone_from_slice(&buf[min..max]);
                resp.seed = Some(seed);

                min = max;
                let mut aes_key = [0_u8; size_of::<[u8; 16]>()];
                max += size_of_val(&aes_key);
                aes_key.clone_from_slice(&buf[min..max]);
                resp.aes_key = Some(aes_key);

                min = max;
                let mut hmac_key = [0_u8; size_of::<[u8; 16]>()];
                max += size_of_val(&hmac_key);
                hmac_key.clone_from_slice(&buf[min..max]);
                resp.hmac_key = Some(hmac_key);
            }

            Some(resp)
        } else {
            None
        }
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

        if controller
            .send_msg(
                &INTF::SSS,
                &Message {
                    tgt_id: Id::SSS,
                    src_id: controller.id(),
                    len: size_of_val(&mesbuf),
                },
            )
            .is_err()
        {
            return None;
        }

        #[allow(clippy::cast_possible_truncation)]
        // truncation permissible for this response size
        let resp = if let Ok(resp) =
            controller.read_msg(&INTF::SSS, SecureSSSResponse::size() as u16, true)
        {
            if let Some(resp) = SecureSSSResponse::from_bytes(&controller.data()[..resp.len]) {
                resp
            } else {
                return None;
            }
        } else {
            return None;
        };

        let cpu_notify = SSSMessage {
            dev_id: resp.dev_id,
            op: resp.op,
        };
        let cn_buf = cpu_notify.to_bytes();

        controller.data()[0..size_of_val(&cn_buf)].clone_from_slice(&cn_buf);

        if controller
            .send_msg(
                &INTF::CPU,
                &Message {
                    tgt_id: controller.id(),
                    src_id: Id::SSS,
                    len: SSSMessage::size(),
                },
            )
            .is_err()
        {
            return None;
        }

        if resp.seed.is_some() {
            Some(CryptoHandler::new(
                resp.seed.unwrap(),
                resp.aes_key.unwrap(),
                resp.hmac_key.unwrap(),
            ))
        } else {
            None
        }
    }

    fn sss_deregister(self, controller: &mut Controller<Self, CryptoHandler>) -> bool {
        unimplemented!()
    }
}
