use core::iter::Iterator;
use core::option::Option;
use core::option::Option::{None, Some};
use core::result::Result::{Err, Ok};

use crate::auth::Handler;
use crate::controller::SSSOp::{Deregister, Register};
use crate::controller::{Controller, KnownId, Message, SSSMessage};
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
            op: Register,
        };
        for (b1, b2) in controller.data().iter_mut().zip(&message.to_bytes()) {
            *b1 = *b2;
        }

        if controller
            .send_msg(
                &SSS,
                &Message {
                    src_id: controller.id(),
                    tgt_id: KnownId::SSS as u16,
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

        if SSSMessage::from_bytes(controller.data()).op == Register {
            Some(NopCryptoHandler)
        } else {
            None
        }
    }

    fn sss_deregister(self, controller: &mut Controller<Self, NopCryptoHandler>) -> bool {
        let message = SSSMessage {
            dev_id: controller.id(),
            op: Deregister,
        };
        for (b1, b2) in controller.data().iter_mut().zip(&message.to_bytes()) {
            *b1 = *b2;
        }

        if controller
            .send_msg(
                &SSS,
                &Message {
                    src_id: controller.id(),
                    tgt_id: KnownId::SSS as u16,
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

        SSSMessage::from_bytes(controller.data()).op == Deregister
    }
}
