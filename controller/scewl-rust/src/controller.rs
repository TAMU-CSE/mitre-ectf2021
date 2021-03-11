use crate::interface::{Interface, INTF};
use core::ops::Range;

pub const SCEWL_MAX_DATA_SZ: usize = 0x4000;

pub type scewl_id = u16;

#[repr(C)]
pub struct SCEWLHeader {
    pub magic_s: u8,
    pub magic_c: u8,
    pub tgt_id: scewl_id,
    pub src_id: scewl_id,
    pub len: u16,
}

impl SCEWLHeader {
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0] = self.magic_s;
        bytes[1] = self.magic_c;
        copy_into(&mut bytes, &self.tgt_id.to_ne_bytes(), 2..4);
        copy_into(&mut bytes, &self.src_id.to_ne_bytes(), 4..6);
        copy_into(&mut bytes, &self.len.to_ne_bytes(), 6..8);
        bytes
    }
}

#[repr(C)]
pub struct SCEWLSSSMessage {
    pub dev_id: scewl_id,
    pub op: u16,
}

impl SCEWLSSSMessage {
    pub fn to_bytes(&self) -> [u8; 4] {
        let mut bytes = [0u8; 4];
        copy_into(&mut bytes, &self.dev_id.to_ne_bytes(), 0..2);
        copy_into(&mut bytes, &self.op.to_ne_bytes(), 2..4);
        bytes
    }

    pub fn from_bytes(data: [u8; SCEWL_MAX_DATA_SZ]) -> SCEWLSSSMessage {
        let mut dev_id = [0u8; 2];
        dev_id.copy_from_slice(&data[0..2]);
        let mut op = [0u8; 2];
        op.copy_from_slice(&data[2..4]);
        SCEWLSSSMessage {
            dev_id: scewl_id::from_ne_bytes(dev_id),
            op: u16::from_ne_bytes(op),
        }
    }
}

pub enum SCEWLStatus {
    Err = -1,
    Ok,
    Already,
    NoMessage,
}

pub type SCEWLResult<T> = Result<T, SCEWLStatus>;

pub enum SCEWLSSSOp {
    Already = -1,
    Register,
    Deregister,
}

pub enum SCEWLKnownId {
    Broadcast,
    SSS,
    FAA,
}

#[derive(Copy, Clone)]
pub struct SCEWLMessage {
    pub src_id: scewl_id,
    pub tgt_id: scewl_id,
    pub data: [u8; SCEWL_MAX_DATA_SZ],
    pub len: usize,
}

pub trait SCEWLClient {
    fn get_intf(&self, intf: INTF) -> Interface;

    fn read_msg(&mut self, intf: INTF, len: u16, blocking: bool) -> SCEWLResult<SCEWLMessage>;
    fn send_msg(&self, intf: INTF, message: SCEWLMessage) -> SCEWLResult<()>;

    fn handle_scewl_recv(
        &self,
        src_id: scewl_id,
        data: [u8; SCEWL_MAX_DATA_SZ],
        len: usize,
    ) -> SCEWLResult<()>;
    fn handle_scewl_send(
        &self,
        tgt_id: scewl_id,
        data: [u8; SCEWL_MAX_DATA_SZ],
        len: usize,
    ) -> SCEWLResult<()>;

    fn handle_brdcst_recv(
        &self,
        src_id: scewl_id,
        data: [u8; SCEWL_MAX_DATA_SZ],
        len: usize,
    ) -> SCEWLResult<()>;
    fn handle_brdcst_send(&self, data: [u8; SCEWL_MAX_DATA_SZ], len: usize) -> SCEWLResult<()>;

    fn handle_faa_recv(&self, data: [u8; SCEWL_MAX_DATA_SZ], len: usize) -> SCEWLResult<()>;
    fn handle_faa_send(&self, data: [u8; SCEWL_MAX_DATA_SZ], len: usize) -> SCEWLResult<()>;

    fn handle_registration(&mut self, data: [u8; SCEWL_MAX_DATA_SZ]) -> SCEWLResult<()>;

    fn sss_register(&mut self) -> bool;
    fn sss_deregister(&mut self) -> bool;
}

fn copy_into(buf1: &mut [u8], buf2: &[u8], range: Range<usize>) {
    for (b1, b2) in buf1[range].iter_mut().zip(buf2) {
        *b1 = *b2;
    }
}
