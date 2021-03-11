use crate::interface::InterfaceError::NoData;
use crate::interface::RWStatusMask::{RXFE, TXFF};
use cortex_m::asm;
use cty::uintptr_t;
use volatile_register::*;

#[repr(C)]
struct UART {
    DR: RW<u32>,
    RSR: RW<u32>,
    RESERVED1: [u8; 16],
    FR: RO<u32>,
    RESERVED2: [u8; 4],
    ILPR: RW<u32>,
    IBRD: RW<u32>,
    FBRD: RW<u32>,
    LCRH: RW<u32>,
    CTL: RW<u32>,
    IFLS: RW<u32>,
    IM: RW<u32>,
    RIS: RO<u32>,
    MIS: RO<u32>,
    ICR: WO<u32>,
    DMACTL: RW<u32>,
}

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
    uart: &'static mut UART,
}

impl Interface {
    pub fn new(intf: INTF) -> Self {
        let uart = unsafe { &mut *(intf as uintptr_t as *mut UART) };
        unsafe {
            uart.CTL.write(uart.CTL.read() & 0xfffffffe);
            uart.IBRD.write((uart.IBRD.read() & 0xffff0000) | 0x000a);
            uart.FBRD.write((uart.FBRD.read() & 0xffff0000) | 0x0036);
            uart.LCRH.write(0x60);
            uart.CTL.write(uart.CTL.read() | 0x01);
        }
        Interface { uart }
    }

    pub fn avail(&self) -> bool {
        self.uart.FR.read() & (RXFE as u32) == 0
    }

    pub fn readb(&mut self, blocking: bool) -> InterfaceResult<u8> {
        while blocking && !self.avail() {}

        if !self.avail() {
            Err(NoData)
        } else {
            Ok(self.uart.DR.read() as u8)
        }
    }

    pub fn read(&mut self, buf: &mut [u8], n: usize, blocking: bool) -> InterfaceResult<usize> {
        for i in 0..n {
            match self.readb(blocking) {
                Ok(b) => buf[i] = b,
                Err(_) => return InterfaceResult::Ok(i),
            }

            // apparently QEMU needs a little time to spin up
            for _ in 0..1000000 {
                asm::nop();
            }
        }
        Ok(n)
    }

    pub fn writeb(&mut self, data: u8) -> () {
        while self.uart.FR.read() & (TXFF as u32) != 0 {}
        unsafe {
            self.uart.DR.write(data.into());
        }
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
        let uart = unsafe { &mut *(self.uart as *const UART as *mut UART) };
        Self { uart }
    }
}
