use core::cmp::min;
use core::mem::size_of;

use crate::auth::Handler as AuthHandler;
use crate::controller::Status::NoMessage;
use crate::crypto::Handler as CryptoHandler;
use crate::interface::INTF::{CPU, RAD, SSS};
use crate::interface::{Interface, INTF};
use core::result::Result as CoreResult;
#[cfg(feature = "semihosted")]
use cortex_m_semihosting::hprintln;

pub const SCEWL_MAX_DATA_SZ: usize = 0x4000 * 2;

pub type Id = u16;

#[derive(Debug)]
pub struct SCEWLHeader {
    pub magic_s: u8,
    pub magic_c: u8,
    pub tgt_id: Id,
    pub src_id: Id,
    pub len: u16,
}

impl SCEWLHeader {
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0_u8; 8];
        bytes[0] = self.magic_s;
        bytes[1] = self.magic_c;
        bytes[2..(2 + size_of::<Id>())].clone_from_slice(&self.tgt_id.to_ne_bytes());
        bytes[(2 + size_of::<Id>())..(2 + size_of::<Id>() * 2)]
            .clone_from_slice(&self.src_id.to_ne_bytes());
        bytes[(2 + size_of::<Id>() * 2)..(2 + size_of::<Id>() * 3)]
            .clone_from_slice(&self.len.to_ne_bytes());
        bytes
    }
}

pub struct SSSMessage {
    pub dev_id: Id,
    pub op: SSSOp,
}

impl SSSMessage {
    pub fn to_bytes(&self) -> [u8; 4] {
        let mut bytes = [0_u8; 4];
        bytes[..size_of::<Id>()].clone_from_slice(&self.dev_id.to_ne_bytes());
        bytes[size_of::<Id>()..(size_of::<Id>() * 2)]
            .clone_from_slice(&(self.op as i32).to_ne_bytes());
        bytes
    }

    pub fn from_bytes(data: &[u8]) -> SSSMessage {
        let mut dev_id = [0_u8; 2];
        dev_id.copy_from_slice(&data[0..2]);
        let mut op = [0_u8; 2];
        op.copy_from_slice(&data[2..4]);
        SSSMessage {
            dev_id: Id::from_ne_bytes(dev_id),
            op: i16::from_ne_bytes(op).into(),
        }
    }
}

#[allow(dead_code)]
pub enum Status {
    Err = -1,
    Ok,
    Already,
    NoMessage,
}

pub type Result<T> = CoreResult<T, Status>;

#[allow(dead_code)]
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
pub enum SSSOp {
    Already = -1,
    Register,
    Deregister,
    Unknown,
}

impl Into<SSSOp> for i16 {
    fn into(self) -> SSSOp {
        match self {
            -1 => SSSOp::Already,
            0 => SSSOp::Register,
            1 => SSSOp::Deregister,
            _ => SSSOp::Unknown,
        }
    }
}

pub enum KnownId {
    Broadcast,
    SSS,
    FAA,
}

#[derive(Debug)]
pub struct Message {
    pub src_id: Id,
    pub tgt_id: Id,
    pub len: usize,
}

pub struct Controller<'a, A, C>
where
    A: AuthHandler<C> + Sized,
    C: CryptoHandler + Sized,
{
    id: Id,
    cpu: Interface,
    sss: Interface,
    rad: Interface,
    data: &'a mut [u8; SCEWL_MAX_DATA_SZ],
    auth: A,
    crypto: Option<C>,
}

impl<'a, A: AuthHandler<C> + Sized, C: CryptoHandler + Sized> Controller<'a, A, C> {
    pub fn new(id: Id, buf: &'a mut [u8; SCEWL_MAX_DATA_SZ], auth: A) -> Self {
        Controller {
            id,
            cpu: Interface::new(CPU),
            sss: Interface::new(SSS),
            rad: Interface::new(RAD),
            data: buf,
            auth,
            crypto: None,
        }
    }
}

impl<'a, A: AuthHandler<C> + Sized, C: CryptoHandler + Sized> Controller<'a, A, C> {
    fn get_intf(&self, intf: &INTF) -> Interface {
        match intf {
            CPU => &self.cpu,
            SSS => &self.sss,
            RAD => &self.rad,
        }
        .clone()
    }

    pub fn id(&self) -> Id {
        self.id
    }

    pub fn registered(&self) -> bool {
        self.crypto.is_some()
    }

    pub fn data(&mut self) -> &mut [u8] {
        self.data
    }

    pub fn read_msg(&mut self, intf: &INTF, len: u16, blocking: bool) -> Result<Message> {
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

        if len < hdr.len as usize {
            for _ in len..hdr.len as usize {
                if intf.readb(false).is_err() {
                    break; // fail fast, don't discard new messages
                }
            }
        }

        let message = Message {
            src_id: hdr.src_id,
            tgt_id: hdr.tgt_id,
            len,
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

    pub fn send_msg(&mut self, intf: &INTF, message: &Message) -> Result<()> {
        let mut intf = self.get_intf(intf);

        let hdr = SCEWLHeader {
            magic_s: b'S',
            magic_c: b'C',
            tgt_id: message.tgt_id,
            src_id: message.src_id,
            len: message.len as u16,
        };

        intf.write(&hdr.to_bytes(), 8); // magic number; size of the header

        intf.write(self.data, hdr.len as usize);

        #[cfg(feature = "semihosted")]
        hprintln!(
            "Send: {:?} {:?}: {:?}",
            intf,
            message,
            &self.data[..hdr.len as usize]
        )
        .ok();

        Ok(())
    }

    fn handle_scewl_recv(&mut self, src_id: Id, len: usize) -> Result<()> {
        if self.crypto.is_none() {
            return Err(Status::Err);
        }
        let actual = match self.crypto.as_mut().unwrap().decrypt(&mut self.data, len) {
            None => return Err(Status::Err),
            Some(len) => len,
        };

        self.send_msg(
            &CPU,
            &Message {
                src_id,
                tgt_id: self.id,
                len: actual,
            },
        )
    }

    fn handle_scewl_send(&mut self, tgt_id: Id, len: usize) -> Result<()> {
        if self.crypto.is_none() {
            return Err(Status::Err);
        }
        let actual = self.crypto.as_mut().unwrap().encrypt(&mut self.data, len);
        self.send_msg(
            &RAD,
            &Message {
                src_id: self.id,
                tgt_id,
                len: actual,
            },
        )
    }

    fn handle_brdcst_recv(&mut self, src_id: Id, len: usize) -> Result<()> {
        self.send_msg(
            &CPU,
            &Message {
                src_id,
                tgt_id: KnownId::Broadcast as u16,
                len,
            },
        )
    }

    fn handle_brdcst_send(&mut self, len: usize) -> Result<()> {
        self.send_msg(
            &RAD,
            &Message {
                src_id: self.id,
                tgt_id: KnownId::Broadcast as u16,
                len,
            },
        )
    }

    fn handle_faa_recv(&mut self, len: usize) -> Result<()> {
        self.send_msg(
            &CPU,
            &Message {
                src_id: KnownId::FAA as u16,
                tgt_id: self.id,
                len,
            },
        )
    }

    fn handle_faa_send(&mut self, len: usize) -> Result<()> {
        self.send_msg(
            &RAD,
            &Message {
                src_id: self.id,
                tgt_id: KnownId::FAA as u16,
                len,
            },
        )
    }

    fn handle_registration(&mut self) -> bool {
        let message = SSSMessage::from_bytes(self.data);
        if message.op == SSSOp::Register {
            self.auth.sss_register(self).map_or(false, |c| {
                self.crypto = Some(c);
                true
            })
        } else if message.op == SSSOp::Deregister && self.auth.sss_deregister(self) {
            self.crypto = None;
            true
        } else {
            false
        }
    }

    pub fn run(&mut self) -> ! {
        loop {
            if let Ok(msg) = self.read_msg(&CPU, SCEWL_MAX_DATA_SZ as u16, true) {
                if msg.tgt_id == KnownId::SSS as u16 {
                    let _ignored = self.handle_registration();
                }
            }

            while self.registered() {
                if self.cpu.avail() {
                    if let Ok(msg) = self.read_msg(&CPU, SCEWL_MAX_DATA_SZ as u16, true) {
                        let _ignored = if msg.tgt_id == KnownId::Broadcast as u16 {
                            self.handle_brdcst_send(msg.len).is_ok()
                        } else if msg.tgt_id == KnownId::SSS as u16 {
                            self.handle_registration()
                        } else if msg.tgt_id == KnownId::FAA as u16 {
                            self.handle_faa_send(msg.len).is_ok()
                        } else {
                            self.handle_scewl_send(msg.tgt_id, msg.len).is_ok()
                        };

                        continue;
                    }
                }

                if self.rad.avail() {
                    if let Ok(msg) = self.read_msg(&RAD, SCEWL_MAX_DATA_SZ as u16, true) {
                        let _ignored = if msg.tgt_id == KnownId::Broadcast as u16 {
                            self.handle_brdcst_recv(msg.src_id, msg.len).is_ok()
                        } else if msg.tgt_id == self.id {
                            if msg.src_id == KnownId::FAA as u16 {
                                self.handle_faa_recv(msg.len).is_ok()
                            } else {
                                self.handle_scewl_recv(msg.src_id, msg.len).is_ok()
                            }
                        } else {
                            continue;
                        };
                    }
                }
            }
        }
    }
}
