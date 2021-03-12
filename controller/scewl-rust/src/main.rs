#![no_std]
#![no_main]
#![warn(clippy::pedantic)]

mod controller;
mod crypto;
mod interface;

#[cfg(feature = "semihosted")]
use cortex_m_semihosting::hprintln;
use lm3s6965 as _;
#[cfg(not(feature = "semihosted"))]
use panic_halt as _;
#[cfg(feature = "semihosted")]
use panic_semihosting as _;

use cortex_m_rt::entry;
use cortex_m_rt::exception;

use crate::controller::SCEWLSSSOp::{Deregister, Register};
use crate::controller::SCEWLStatus;
use crate::controller::SCEWLStatus::NoMessage;
use crate::crypto::{AESCryptoHandler, AuthHandler, NopAuthHandler};
use crate::interface::INTF::{CPU, RAD, SSS};
use controller::{
    SCEWLClient, SCEWLHeader, SCEWLKnownId, SCEWLMessage, SCEWLResult, SCEWLSSSMessage, ScewlId,
    SCEWL_MAX_DATA_SZ,
};
use core::cmp::min;
use core::mem::size_of;
use core::str::FromStr;
use interface::{Interface, INTF};

const SCEWL_ID: &str = env!("SCEWL_ID");

struct DefaultClient<'a, T>
where
    T: AuthHandler + Sized,
{
    id: ScewlId,
    cpu: Interface,
    sss: Interface,
    rad: Interface,
    data: &'a mut [u8; SCEWL_MAX_DATA_SZ],
    crypto: T,
    registered: bool,
}

impl<'a> DefaultClient<'a, NopAuthHandler> {
    #[allow(dead_code)]
    fn new(buf: &'a mut [u8; SCEWL_MAX_DATA_SZ]) -> Self {
        DefaultClient {
            id: ScewlId::from_str(SCEWL_ID).unwrap(),
            cpu: Interface::new(CPU),
            sss: Interface::new(SSS),
            rad: Interface::new(RAD),
            data: buf,
            crypto: NopAuthHandler {},
            registered: false,
        }
    }
}

impl<'a, T: AuthHandler + Sized> DefaultClient<'a, T> {
    fn new_with_crypto(buf: &'a mut [u8; SCEWL_MAX_DATA_SZ], crypto: T) -> Self {
        DefaultClient {
            id: ScewlId::from_str(SCEWL_ID).unwrap(),
            cpu: Interface::new(CPU),
            sss: Interface::new(SSS),
            rad: Interface::new(RAD),
            data: buf,
            crypto,
            registered: false,
        }
    }
}

impl<'a, T: AuthHandler + Sized> SCEWLClient for DefaultClient<'a, T> {
    fn get_intf(&self, intf: INTF) -> Interface {
        match intf {
            CPU => &self.cpu,
            SSS => &self.sss,
            RAD => &self.rad,
        }
        .clone()
    }

    fn read_msg(&mut self, intf: INTF, len: u16, blocking: bool) -> SCEWLResult<SCEWLMessage> {
        let mut intf = self.get_intf(intf);
        let mut hdr = SCEWLHeader {
            magic_s: 0,
            magic_c: 0,
            tgt_id: 0,
            src_id: 0,
            len: 0,
        };

        for b in self.data[..len as usize].as_mut() {
            *b = 0
        }

        loop {
            hdr.magic_c = b'S';

            match intf.readb(blocking) {
                Ok(b) => hdr.magic_s = b,
                Err(_) => return Err(NoMessage),
            }

            if hdr.magic_s != b'S' {
                continue;
            }

            while hdr.magic_c == b'S' {
                match intf.readb(blocking) {
                    Ok(b) => hdr.magic_c = b,
                    Err(_) => return Err(NoMessage),
                }
            }

            if hdr.magic_c == b'C' {
                break;
            }
        }

        for item in &mut [&mut hdr.tgt_id, &mut hdr.src_id, &mut hdr.len] {
            let mut buf = [0_u8; size_of::<u16>()];
            if intf.read(&mut buf, size_of::<u16>(), blocking).is_err() {
                return Err(NoMessage);
            }
            **item = u16::from_ne_bytes(buf);
        }

        let len = min(hdr.len, len) as usize;
        let res = intf.read(self.data, len, blocking);

        let actual = if intf.named() == INTF::RAD && hdr.src_id != SCEWLKnownId::FAA as u16 {
            match self.crypto.decrypt(&mut self.data, len) {
                None => return Err(SCEWLStatus::Err),
                Some(len) => len,
            }
        } else {
            len
        };

        if len < hdr.len as usize {
            for _ in len..hdr.len as usize {
                if intf.readb(false).is_err() {
                    break; // fail fast, don't discard new messages
                }
            }
        }

        let message = SCEWLMessage {
            src_id: hdr.src_id,
            tgt_id: hdr.tgt_id,
            len: actual,
        };

        #[cfg(feature = "semihosted")]
        hprintln!(
            "Read: {:?} {:?}: {:?}",
            intf,
            message,
            &self.data[..message.len]
        )
        .ok();

        match res {
            Ok(read) => {
                if read < message.len {
                    Err(NoMessage)
                } else {
                    Ok(message)
                }
            }
            Err(_) => Err(NoMessage),
        }
    }

    fn send_msg(&mut self, intf: INTF, message: &SCEWLMessage) -> SCEWLResult<()> {
        let mut intf = self.get_intf(intf);

        let actual = if intf.named() == INTF::RAD && message.tgt_id != SCEWLKnownId::FAA as u16 {
            self.crypto.encrypt(&mut self.data, message.len)
        } else {
            message.len
        };

        let hdr = SCEWLHeader {
            magic_s: b'S',
            magic_c: b'C',
            tgt_id: message.tgt_id,
            src_id: message.src_id,
            len: actual as u16,
        };

        intf.write(&hdr.to_bytes(), 8); // magic number; size of the header

        intf.write(self.data, hdr.len as usize);

        #[cfg(feature = "semihosted")]
        hprintln!("Send: {:?} {:?}: {:?}", intf, message, &self.data[..actual]).ok();

        Ok(())
    }

    fn handle_scewl_recv(&mut self, src_id: ScewlId, len: usize) -> SCEWLResult<()> {
        self.send_msg(
            CPU,
            &SCEWLMessage {
                src_id,
                tgt_id: self.id,
                len,
            },
        )
    }

    fn handle_scewl_send(&mut self, tgt_id: ScewlId, len: usize) -> SCEWLResult<()> {
        self.send_msg(
            RAD,
            &SCEWLMessage {
                src_id: self.id,
                tgt_id,
                len,
            },
        )
    }

    fn handle_brdcst_recv(&mut self, src_id: ScewlId, len: usize) -> SCEWLResult<()> {
        self.send_msg(
            CPU,
            &SCEWLMessage {
                src_id,
                tgt_id: SCEWLKnownId::Broadcast as u16,
                len,
            },
        )
    }

    fn handle_brdcst_send(&mut self, len: usize) -> SCEWLResult<()> {
        self.send_msg(
            RAD,
            &SCEWLMessage {
                src_id: self.id,
                tgt_id: SCEWLKnownId::Broadcast as u16,
                len,
            },
        )
    }

    fn handle_faa_recv(&mut self, len: usize) -> SCEWLResult<()> {
        self.send_msg(
            CPU,
            &SCEWLMessage {
                src_id: SCEWLKnownId::FAA as u16,
                tgt_id: self.id,
                len,
            },
        )
    }

    fn handle_faa_send(&mut self, len: usize) -> SCEWLResult<()> {
        self.send_msg(
            RAD,
            &SCEWLMessage {
                src_id: self.id,
                tgt_id: SCEWLKnownId::FAA as u16,
                len,
            },
        )
    }

    fn handle_registration(&mut self) -> SCEWLResult<()> {
        let message = SCEWLSSSMessage::from_bytes(self.data);
        if message.op == Register as u16 && self.sss_register() {
            self.registered = true;
        } else if message.op == Deregister as u16 && self.sss_deregister() {
            self.registered = false;
        }
        Ok(())
    }

    fn sss_register(&mut self) -> bool {
        let message = SCEWLSSSMessage {
            dev_id: self.id,
            op: Register as u16,
        };
        for (b1, b2) in self.data.iter_mut().zip(&message.to_bytes()) {
            *b1 = *b2;
        }

        if self
            .send_msg(
                SSS,
                &SCEWLMessage {
                    src_id: self.id,
                    tgt_id: SCEWLKnownId::SSS as u16,
                    len: 4,
                },
            )
            .is_err()
        {
            return false;
        }

        let res = match self.read_msg(SSS, 4, true) {
            Ok(msg) => msg,
            Err(_) => return false,
        };

        if self.send_msg(CPU, &res).is_err() {
            return false;
        }

        SCEWLSSSMessage::from_bytes(self.data).op == Register as u16
    }

    fn sss_deregister(&mut self) -> bool {
        let message = SCEWLSSSMessage {
            dev_id: self.id,
            op: Deregister as u16,
        };
        for (b1, b2) in self.data.iter_mut().zip(&message.to_bytes()) {
            *b1 = *b2;
        }

        if self
            .send_msg(
                SSS,
                &SCEWLMessage {
                    src_id: self.id,
                    tgt_id: SCEWLKnownId::SSS as u16,
                    len: 4,
                },
            )
            .is_err()
        {
            return false;
        }

        let res = match self.read_msg(SSS, 4, true) {
            Ok(msg) => msg,
            Err(_) => return false,
        };

        if self.send_msg(CPU, &res).is_err() {
            return false;
        }

        SCEWLSSSMessage::from_bytes(self.data).op == Deregister as u16
    }
}

#[entry]
fn main() -> ! {
    let mut data = [0_u8; SCEWL_MAX_DATA_SZ];
    // let mut client = DefaultClient::new(&mut data);

    let crypto = AESCryptoHandler::new([0; 16], [0; 32]);
    let mut client = DefaultClient::new_with_crypto(&mut data, crypto);

    loop {
        if let Ok(msg) = client.read_msg(CPU, SCEWL_MAX_DATA_SZ as u16, true) {
            if msg.tgt_id == SCEWLKnownId::SSS as u16 {
                let _ignored = client.handle_registration();
            }
        }

        while client.registered {
            if client.cpu.avail() {
                if let Ok(msg) = client.read_msg(INTF::CPU, SCEWL_MAX_DATA_SZ as u16, true) {
                    let _ignored = if msg.tgt_id == SCEWLKnownId::Broadcast as u16 {
                        client.handle_brdcst_send(msg.len)
                    } else if msg.tgt_id == SCEWLKnownId::SSS as u16 {
                        client.handle_registration()
                    } else if msg.tgt_id == SCEWLKnownId::FAA as u16 {
                        client.handle_faa_send(msg.len)
                    } else {
                        client.handle_scewl_send(msg.tgt_id, msg.len)
                    };

                    continue;
                }
            }

            if client.rad.avail() {
                if let Ok(msg) = client.read_msg(INTF::RAD, SCEWL_MAX_DATA_SZ as u16, true) {
                    let _ignored = if msg.tgt_id == SCEWLKnownId::Broadcast as u16 {
                        client.handle_brdcst_recv(msg.src_id, msg.len)
                    } else if msg.tgt_id == client.id {
                        if msg.src_id == SCEWLKnownId::FAA as u16 {
                            client.handle_faa_recv(msg.len)
                        } else {
                            client.handle_scewl_recv(msg.src_id, msg.len)
                        }
                    } else {
                        continue;
                    };
                }
            }
        }
    }
}

// disable exception handling because we're lazy
#[exception]
#[allow(non_snake_case)]
fn DefaultHandler(_irqn: i16) {}
