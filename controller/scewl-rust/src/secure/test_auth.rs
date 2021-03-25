// for use in testing crypto w/o an SSS implementation; uses the default SSS implementation

#![doc(hidden)]

use crate::auth::Handler as AuthHandler;
use crate::controller::{Controller, Id, Message, SSSMessage, SSSOp};
use crate::cursor::ReadCursor;
use crate::interface::INTF;
use crate::secure::CryptoHandler;

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

        (SSSMessage::from_bytes(controller.data()).op == SSSOp::Register)
            .then(|| CryptoHandler::new([0_u8; 32], [0_u8; 16], [0_u8; 64]))
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
