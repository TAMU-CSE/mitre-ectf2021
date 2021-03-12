#![no_std]
#![no_main]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub mod controller;
pub mod interface;

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
use crate::controller::SCEWLStatus::NoMessage;
use crate::interface::INTF::*;
use controller::*;
use core::cmp::min;
use core::mem::{size_of, size_of_val};
use core::str::FromStr;
use interface::{Interface, INTF};

const SCEWL_ID: &'static str = env!("SCEWL_ID");

struct DefaultClient<'a> {
    id: scewl_id,
    cpu: Interface,
    sss: Interface,
    rad: Interface,
    data: &'a mut [u8; SCEWL_MAX_DATA_SZ],
    registered: bool,
}

impl<'a> DefaultClient<'a> {
    fn new(buf: &'a mut [u8; SCEWL_MAX_DATA_SZ]) -> Self {
        DefaultClient {
            id: scewl_id::from_str(SCEWL_ID).unwrap(),
            cpu: Interface::new(CPU),
            sss: Interface::new(SSS),
            rad: Interface::new(CPU),
            data: buf,
            registered: false,
        }
    }
}

impl<'a> SCEWLClient for DefaultClient<'a> {
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
            let mut buf = [0u8; size_of::<u16>()];
            if let Err(_) = intf.read(&mut buf, size_of::<u16>(), blocking) {
                return Err(NoMessage);
            }
            **item = u16::from_ne_bytes(buf);
        }

        let len = min(hdr.len, len) as usize;
        let res = intf.read(self.data, len, blocking);

        if len < hdr.len as usize {
            for _ in len..hdr.len as usize {
                if let Err(_) = intf.readb(false) {
                    break; // fail fast, don't discard new messages
                }
            }
        }

        let message = SCEWLMessage {
            src_id: hdr.src_id,
            tgt_id: hdr.tgt_id,
            len,
        };

        #[cfg(feature = "semihosted")]
        hprintln!("Read: {:?}: {:?}", message, &self.data[..message.len]).ok();

        match res {
            Ok(read) => {
                if read < len {
                    Err(NoMessage)
                } else {
                    Ok(message)
                }
            }
            Err(_) => Err(NoMessage),
        }
    }

    fn send_msg(&self, intf: INTF, message: &SCEWLMessage) -> SCEWLResult<()> {
        let mut intf = self.get_intf(intf);
        let hdr = SCEWLHeader {
            magic_s: b'S',
            magic_c: b'C',
            tgt_id: message.tgt_id,
            src_id: message.src_id,
            len: message.len as u16,
        };

        intf.write(&hdr.to_bytes(), 8); // magic number; size of the header

        intf.write(self.data, message.len);

        #[cfg(feature = "semihosted")]
        hprintln!("Read: {:?}: {:?}", message, &self.data[..message.len]).ok();

        Ok(())
    }

    fn handle_scewl_recv(&self, src_id: scewl_id, len: usize) -> SCEWLResult<()> {
        self.send_msg(
            CPU,
            &SCEWLMessage {
                src_id,
                tgt_id: self.id,
                len,
            },
        )
    }

    fn handle_scewl_send(&self, tgt_id: scewl_id, len: usize) -> SCEWLResult<()> {
        self.send_msg(
            RAD,
            &SCEWLMessage {
                src_id: self.id,
                tgt_id,
                len,
            },
        )
    }

    fn handle_brdcst_recv(&self, src_id: scewl_id, len: usize) -> SCEWLResult<()> {
        self.send_msg(
            CPU,
            &SCEWLMessage {
                src_id,
                tgt_id: SCEWLKnownId::Broadcast as u16,
                len,
            },
        )
    }

    fn handle_brdcst_send(&self, len: usize) -> SCEWLResult<()> {
        self.send_msg(
            RAD,
            &SCEWLMessage {
                src_id: self.id,
                tgt_id: SCEWLKnownId::Broadcast as u16,
                len,
            },
        )
    }

    fn handle_faa_recv(&self, len: usize) -> SCEWLResult<()> {
        self.send_msg(
            CPU,
            &SCEWLMessage {
                src_id: SCEWLKnownId::FAA as u16,
                tgt_id: self.id,
                len,
            },
        )
    }

    fn handle_faa_send(&self, len: usize) -> SCEWLResult<()> {
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

        if let Err(_) = self.send_msg(
            SSS,
            &SCEWLMessage {
                src_id: self.id,
                tgt_id: SCEWLKnownId::SSS as u16,
                len: 4,
            },
        ) {
            return false;
        }

        let res = match self.read_msg(SSS, 4, true) {
            Ok(msg) => msg,
            Err(_) => return false,
        };

        if let Err(_) = self.send_msg(CPU, &res) {
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

        if let Err(_) = self.send_msg(
            SSS,
            &SCEWLMessage {
                src_id: self.id,
                tgt_id: SCEWLKnownId::SSS as u16,
                len: 4,
            },
        ) {
            return false;
        }

        let res = match self.read_msg(SSS, 4, true) {
            Ok(msg) => msg,
            Err(_) => return false,
        };

        if let Err(_) = self.send_msg(CPU, &res) {
            return false;
        }

        SCEWLSSSMessage::from_bytes(self.data).op == Deregister as u16
    }
}

#[entry]
fn main() -> ! {
    let mut data = [0u8; SCEWL_MAX_DATA_SZ];
    let mut client = DefaultClient::new(&mut data);

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
fn DefaultHandler(_irqn: i16) {}
