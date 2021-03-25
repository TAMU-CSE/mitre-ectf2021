//! The authentication module for the trivial implementation of the security features for the
//! controller, which emulates the original behaviour of `sss_register` and `sss_deregister` from
//! the [original C implementation](https://github.com/mitre-cyber-academy/2021-ectf-insecure-example/blob/master/controller/controller.c)

use crate::auth::Handler as AuthHandler;
use crate::controller::{Controller, Id, Message, SSSMessage, SSSOp};
use crate::cursor::ReadCursor;
use crate::interface::INTF;
use crate::trivial::CryptoHandler;

/// A trivial authentication handler which simply passes the CPU-formatted SSS message to the SSS
#[derive(Copy, Clone)]
pub struct Handler;

impl AuthHandler<CryptoHandler> for Handler {
    fn sss_register(
        self,
        controller: &mut Controller<Self, CryptoHandler>,
    ) -> Option<CryptoHandler> {
        let msg = SSSMessage {
            dev_id: controller.id(),
            op: SSSOp::Register,
        };
        let len = ReadCursor::new(&msg.to_bytes()).copy_to(controller.data());

        controller
            .send_msg(
                INTF::SSS,
                &Message {
                    src_id: controller.id(),
                    tgt_id: Id::SSS,
                    len,
                },
            )
            .ok()?;

        let res = controller.read_msg(INTF::SSS, 4).ok()?;

        controller.send_msg(INTF::CPU, &res).ok()?;

        (SSSMessage::from_bytes(controller.data()).op == SSSOp::Register).then(|| CryptoHandler)
    }

    fn sss_deregister(self, controller: &mut Controller<Self, CryptoHandler>) -> bool {
        let msg = SSSMessage {
            dev_id: controller.id(),
            op: SSSOp::Deregister,
        };
        let len = ReadCursor::new(&msg.to_bytes()).copy_to(controller.data());

        if controller
            .send_msg(
                INTF::SSS,
                &Message {
                    src_id: controller.id(),
                    tgt_id: Id::SSS,
                    len,
                },
            )
            .is_err()
        {
            return false;
        }

        let res = match controller.read_msg(INTF::SSS, 4) {
            Ok(msg) => msg,
            Err(_) => return false,
        };

        if controller.send_msg(INTF::CPU, &res).is_err() {
            return false;
        }

        SSSMessage::from_bytes(controller.data()).op == SSSOp::Deregister
    }
}
