use crate::interface::InterfaceError::NoData;
use crate::interface::RWStatusMask::{RXFE, TXFF};
use cortex_m::asm;
use cty::uintptr_t;

include!(concat!(env!("OUT_DIR"), "/cmsis.rs"));

pub enum RWStatusMask {
    RXFE = 0x10,
    TXFF = 0x20,
}

pub enum INTF {
    CPU = 0x4000C000,
    SSS = 0x4000D000,
    RAD = 0x4000E000,
}

pub enum InterfaceError {
    Unknown,
    NoData,
}

pub type InterfaceResult<T> = Result<T, InterfaceError>;

pub struct Interface {
    uart: *mut UART_Type,
}

impl Interface {
    pub fn new(intf: INTF) -> Self {
        let uart = intf as *mut UART_Type;
        unsafe {
            (*uart).CTL &= 0xfffffffe;
            (*uart).IBRD = ((*uart).IBRD & 0xffff0000) | 0x000a;
            (*uart).FBRD = ((*uart).FBRD & 0xffff0000) | 0x0036;
            (*uart).LCRH = 0x60;
            (*uart).CTL |= 0x01;
        }
        Interface { uart }
    }

    pub fn avail(&self) -> bool {
        unsafe { ((*self.uart).FR & (RXFE as u32)) == 0 }
    }

    pub fn readb(&mut self, blocking: bool) -> InterfaceResult<u8> {
        while blocking && !self.avail() {}

        if !self.avail() {
            Err(NoData)
        } else {
            Ok(unsafe { (*self.uart).DR as u8 })
        }
    }

    pub fn read(&mut self, buf: &mut [u8], n: usize, blocking: bool) -> InterfaceResult<usize> {
        for i in 0..n {
            match self.readb(blocking) {
                Ok(b) => buf[i] = b,
                Err(_) => return InterfaceResult::Ok(i),
            }

            // apparently QEMU needs a little time to spin up
            for _ in 0..100000 {
                asm::nop();
            }
        }
        Ok(n)
    }

    pub fn writeb(&mut self, data: u8) -> () {
        while unsafe { (*self.uart).FR } & (TXFF as u32) != 0 {}
        unsafe { (*self.uart).DR = data.into() }
    }

    pub fn write(&mut self, buf: &[u8], len: usize) -> usize {
        for i in 0..len {
            self.writeb(buf[i]);
        }
        len
    }
}

impl Clone for Interface {
    fn clone(&self) -> Self {
        Self { uart: self.uart }
    }
}
