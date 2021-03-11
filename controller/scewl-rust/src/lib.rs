#![no_std]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub mod controller;
pub mod interface;

use lm3s6965::interrupt;
use panic_halt as _;

use crate::controller::SCEWLSSSOp::{Deregister, Register};
use crate::controller::SCEWLStatus::NoMessage;
use crate::interface::INTF::*;
use controller::*;
use core::mem::size_of;
use core::str::FromStr;
use interface::{Interface, INTF};

const SCEWL_ID: &'static str = env!("SCEWL_ID");

struct DefaultClient {
    id: scewl_id,
    cpu: Interface,
    sss: Interface,
    rad: Interface,
    buf: [u8; SCEWL_MAX_DATA_SZ],
    registered: bool,
}

impl DefaultClient {
    fn new() -> Self {
        DefaultClient {
            id: scewl_id::from_str(SCEWL_ID).unwrap(),
            cpu: Interface::new(CPU),
            sss: Interface::new(SSS),
            rad: Interface::new(CPU),
            buf: [0u8; SCEWL_MAX_DATA_SZ],
            registered: false,
        }
    }
}

impl SCEWLClient for DefaultClient {
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

        for b in self.buf[..len as usize].as_mut() {
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

        let len = if hdr.len < len { hdr.len } else { len } as usize;
        let res = intf.read(&mut self.buf, len, blocking);

        if len < hdr.len as usize {
            for _ in len..hdr.len as usize {
                if let Err(_) = intf.readb(false) {
                    break; // fail fast, don't discard new messages
                }
            }
        }

        match res {
            Ok(read) => {
                if read < len {
                    Err(NoMessage)
                } else {
                    Ok(SCEWLMessage {
                        src_id: hdr.src_id,
                        tgt_id: hdr.tgt_id,
                        data: self.buf,
                        len,
                    })
                }
            }
            Err(_) => Err(NoMessage),
        }
    }

    fn send_msg(&self, intf: INTF, message: SCEWLMessage) -> SCEWLResult<()> {
        let mut intf = self.get_intf(intf);
        let hdr = SCEWLHeader {
            magic_s: b'S',
            magic_c: b'C',
            tgt_id: message.tgt_id,
            src_id: message.src_id,
            len: message.len as u16,
        };

        intf.write(&hdr.to_bytes(), 8); // magic number; size of the header

        intf.write(&message.data, message.len);

        Ok(())
    }

    fn handle_scewl_recv(
        &self,
        src_id: scewl_id,
        data: [u8; SCEWL_MAX_DATA_SZ],
        len: usize,
    ) -> SCEWLResult<()> {
        self.send_msg(
            CPU,
            SCEWLMessage {
                src_id,
                tgt_id: self.id,
                data,
                len,
            },
        )
    }

    fn handle_scewl_send(
        &self,
        tgt_id: scewl_id,
        data: [u8; SCEWL_MAX_DATA_SZ],
        len: usize,
    ) -> SCEWLResult<()> {
        self.send_msg(
            RAD,
            SCEWLMessage {
                src_id: self.id,
                tgt_id,
                data: data,
                len,
            },
        )
    }

    fn handle_brdcst_recv(
        &self,
        src_id: scewl_id,
        data: [u8; SCEWL_MAX_DATA_SZ],
        len: usize,
    ) -> SCEWLResult<()> {
        self.send_msg(
            CPU,
            SCEWLMessage {
                src_id,
                tgt_id: SCEWLKnownId::Broadcast as u16,
                data: data,
                len,
            },
        )
    }

    fn handle_brdcst_send(&self, data: [u8; SCEWL_MAX_DATA_SZ], len: usize) -> SCEWLResult<()> {
        self.send_msg(
            RAD,
            SCEWLMessage {
                src_id: self.id,
                tgt_id: SCEWLKnownId::Broadcast as u16,
                data: data,
                len,
            },
        )
    }

    fn handle_faa_recv(&self, data: [u8; SCEWL_MAX_DATA_SZ], len: usize) -> SCEWLResult<()> {
        self.send_msg(
            CPU,
            SCEWLMessage {
                src_id: SCEWLKnownId::FAA as u16,
                tgt_id: self.id,
                data: data,
                len,
            },
        )
    }

    fn handle_faa_send(&self, data: [u8; SCEWL_MAX_DATA_SZ], len: usize) -> SCEWLResult<()> {
        self.send_msg(
            RAD,
            SCEWLMessage {
                src_id: self.id,
                tgt_id: SCEWLKnownId::FAA as u16,
                data,
                len,
            },
        )
    }

    fn handle_registration(&mut self, data: [u8; SCEWL_MAX_DATA_SZ]) -> SCEWLResult<()> {
        let message = SCEWLSSSMessage::from_bytes(data);
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

        let mut data = [0u8; SCEWL_MAX_DATA_SZ];
        data.copy_from_slice(&message.to_bytes());
        if let Err(_) = self.send_msg(
            SSS,
            SCEWLMessage {
                src_id: self.id,
                tgt_id: SCEWLKnownId::SSS as u16,
                data,
                len: 4,
            },
        ) {
            return false;
        }

        let res = match self.read_msg(SSS, 4, true) {
            Ok(msg) => msg,
            Err(_) => return false,
        };

        if let Err(_) = self.send_msg(CPU, res) {
            return false;
        }

        SCEWLSSSMessage::from_bytes(res.data).op == Register as u16
    }

    fn sss_deregister(&mut self) -> bool {
        let message = SCEWLSSSMessage {
            dev_id: self.id,
            op: Deregister as u16,
        };

        let mut data = [0u8; SCEWL_MAX_DATA_SZ];
        data.copy_from_slice(&message.to_bytes());
        if let Err(_) = self.send_msg(
            SSS,
            SCEWLMessage {
                src_id: self.id,
                tgt_id: SCEWLKnownId::SSS as u16,
                data,
                len: 4,
            },
        ) {
            return false;
        }

        let res = match self.read_msg(SSS, 4, true) {
            Ok(msg) => msg,
            Err(_) => return false,
        };

        if let Err(_) = self.send_msg(CPU, res) {
            return false;
        }

        SCEWLSSSMessage::from_bytes(res.data).op == Deregister as u16
    }
}

#[no_mangle]
pub extern "C" fn main() -> ! {
    let mut client = DefaultClient::new();

    loop {
        if let Ok(msg) = client.read_msg(CPU, SCEWL_MAX_DATA_SZ as u16, true) {
            if msg.tgt_id == SCEWLKnownId::SSS as u16 {
                let _ignored = client.handle_registration(msg.data);
            }
        }

        while client.registered {
            if client.cpu.avail() {
                if let Ok(msg) = client.read_msg(INTF::CPU, SCEWL_MAX_DATA_SZ as u16, true) {
                    let _ignored = if msg.tgt_id == SCEWLKnownId::Broadcast as u16 {
                        client.handle_brdcst_send(msg.data, msg.len)
                    } else if msg.tgt_id == SCEWLKnownId::SSS as u16 {
                        client.handle_registration(msg.data)
                    } else if msg.tgt_id == SCEWLKnownId::FAA as u16 {
                        client.handle_faa_send(msg.data, msg.len)
                    } else {
                        client.handle_scewl_recv(msg.src_id, msg.data, msg.len)
                    };

                    continue;
                }
            }

            if client.rad.avail() {
                if let Ok(msg) = client.read_msg(INTF::RAD, SCEWL_MAX_DATA_SZ as u16, true) {
                    let _ignored = if msg.tgt_id == SCEWLKnownId::Broadcast as u16 {
                        client.handle_brdcst_recv(msg.src_id, msg.data, msg.len)
                    } else if msg.tgt_id == client.id {
                        if msg.src_id == SCEWLKnownId::FAA as u16 {
                            client.handle_faa_recv(msg.data, msg.len)
                        } else {
                            client.handle_scewl_recv(msg.src_id, msg.data, msg.len)
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
fn DefaultHandler(irqn: i16) {}
