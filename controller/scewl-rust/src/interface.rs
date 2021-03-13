use crate::interface::Error::NoData;
use crate::interface::RWStatusMask::{RXFE, TXFF};
use core::fmt::Formatter;
use core::fmt::{Debug, Result as FmtResult};
use core::result::Result as CoreResult;
use cty::uintptr_t;
use volatile_register::{RO, RW, WO};

#[repr(C)]
struct UART {
    dr: RW<u32>,
    rsr: RW<u32>,
    reserved1: [u8; 16],
    fr: RO<u32>,
    reserved2: [u8; 4],
    ilpr: RW<u32>,
    ibrd: RW<u32>,
    fbrd: RW<u32>,
    lcrh: RW<u32>,
    ctl: RW<u32>,
    ifls: RW<u32>,
    im: RW<u32>,
    ris: RO<u32>,
    mis: RO<u32>,
    icr: WO<u32>,
    dmactl: RW<u32>,
}

pub enum RWStatusMask {
    RXFE = 0x10,
    TXFF = 0x20,
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum INTF {
    CPU = 0x4000_C000,
    SSS = 0x4000_D000,
    RAD = 0x4000_E000,
}

#[allow(dead_code)]
pub enum Error {
    Unknown,
    NoData,
}

pub type Result<T> = CoreResult<T, Error>;

pub struct Interface {
    uart: &'static mut UART,
}

impl Interface {
    pub fn new(intf: INTF) -> Self {
        let uart = unsafe { &mut *(intf as uintptr_t as *mut UART) };
        unsafe {
            uart.ctl.write(uart.ctl.read() & 0xffff_fffe);
            uart.ibrd.write((uart.ibrd.read() & 0xffff_0000) | 0x000a);
            uart.fbrd.write((uart.fbrd.read() & 0xffff_0000) | 0x0036);
            uart.lcrh.write(0x60);
            uart.ctl.write(uart.ctl.read() | 0x01);
        }
        Interface { uart }
    }

    pub fn avail(&self) -> bool {
        self.uart.fr.read() & (RXFE as u32) == 0
    }

    pub fn readb(&mut self, blocking: bool) -> Result<u8> {
        while blocking && !self.avail() {}

        if self.avail() {
            Ok(self.uart.dr.read() as u8)
        } else {
            Err(NoData)
        }
    }

    pub fn read(&mut self, buf: &mut [u8], n: usize, blocking: bool) -> Result<usize> {
        for (i, b) in buf.iter_mut().enumerate().take(n) {
            match self.readb(blocking) {
                Ok(res) => *b = res,
                Err(_) => return Result::Ok(i),
            }
        }
        Ok(n)
    }

    pub fn writeb(&mut self, data: u8) {
        while self.uart.fr.read() & (TXFF as u32) != 0 {}
        unsafe {
            self.uart.dr.write(data.into());
        }
    }

    pub fn write(&mut self, buf: &[u8], len: usize) -> usize {
        for b in buf.iter().take(len) {
            self.writeb(*b);
        }
        len
    }

    pub fn named(&self) -> INTF {
        match self.uart as *const UART as uintptr_t {
            0x4000_C000 => INTF::CPU,
            0x4000_D000 => INTF::SSS,
            0x4000_E000 => INTF::RAD,
            _ => panic!("Impossible branch; only these addresses can be used"),
        }
    }
}

impl Clone for Interface {
    #[allow(clippy::cast_ref_to_mut)]
    fn clone(&self) -> Self {
        let uart = unsafe { &mut *(self.uart as *const UART as *mut UART) };
        Self { uart }
    }
}

impl Debug for Interface {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{:?}", self.named())
    }
}
