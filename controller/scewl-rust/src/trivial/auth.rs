//! The authentication module for the trivial implementation of the security features for the
//! controller, which emulates the original behaviour of `sss_register` and `sss_deregister` from
//! the [original C implementation](https://github.com/mitre-cyber-academy/2021-ectf-insecure-example/blob/master/controller/controller.c)

use core::option::Option;
use core::result::Result::{Err, Ok};

use crate::auth::Handler;
use crate::controller::{Controller, Id, Message, SSSMessage, SSSOp};
use crate::cursor::{ReadCursor, WriteCursor};
use crate::interface::INTF::{CPU, SSS};
use crate::trivial::NopCryptoHandler;

/// A trivial authentication handler which simply passes the CPU-formatted SSS message to the SSS
#[derive(Copy, Clone)]
pub struct DefaultHandler;

impl Handler<NopCryptoHandler> for DefaultHandler {
    fn sss_register(
        self,
        controller: &mut Controller<Self, NopCryptoHandler>,
    ) -> Option<NopCryptoHandler> {
        let message = SSSMessage {
            dev_id: controller.id(),
            op: SSSOp::Register,
        };
        let cdata = WriteCursor::new(controller.data());
        let len = ReadCursor::new(&message.to_bytes()).copy_to(cdata);

        if controller
            .send_msg(
                &SSS,
                &Message {
                    src_id: controller.id(),
                    tgt_id: Id::SSS,
                    len,
                },
            )
            .is_err()
        {
            return None;
        }

        let res = match controller.read_msg(&SSS, 4, true) {
            Ok(msg) => msg,
            Err(_) => return None,
        };

        if controller.send_msg(&CPU, &res).is_err() {
            return None;
        }

        (SSSMessage::from_bytes(controller.data()).op == SSSOp::Register).then(|| NopCryptoHandler)
    }

    fn sss_deregister(self, controller: &mut Controller<Self, NopCryptoHandler>) -> bool {
        let message = SSSMessage {
            dev_id: controller.id(),
            op: SSSOp::Deregister,
        };
        let cdata = WriteCursor::new(controller.data());
        let len = ReadCursor::new(&message.to_bytes()).copy_to(cdata);

        if controller
            .send_msg(
                &SSS,
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

        let res = match controller.read_msg(&SSS, 4, true) {
            Ok(msg) => msg,
            Err(_) => return false,
        };

        if controller.send_msg(&CPU, &res).is_err() {
            return false;
        }

        SSSMessage::from_bytes(controller.data()).op == SSSOp::Deregister
    }
}
