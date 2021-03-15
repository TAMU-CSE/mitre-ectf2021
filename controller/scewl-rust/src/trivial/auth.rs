use core::iter::Iterator;
use core::option::Option;
use core::result::Result::{Err, Ok};

use crate::auth::Handler;
use crate::controller::{Controller, Id, Message, SSSMessage, SSSOp};
use crate::interface::INTF::{CPU, SSS};
use crate::trivial::NopCryptoHandler;

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
        for (b1, b2) in controller.data().iter_mut().zip(&message.to_bytes()) {
            *b1 = *b2;
        }

        if controller
            .send_msg(
                &SSS,
                &Message {
                    src_id: controller.id(),
                    tgt_id: Id::SSS,
                    len: 4,
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
        for (b1, b2) in controller.data().iter_mut().zip(&message.to_bytes()) {
            *b1 = *b2;
        }

        if controller
            .send_msg(
                &SSS,
                &Message {
                    src_id: controller.id(),
                    tgt_id: Id::SSS,
                    len: 4,
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
