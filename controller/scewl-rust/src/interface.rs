//! A near-exact port of the [original C implementation of interface](https://github.com/mitre-cyber-academy/2021-ectf-insecure-example/blob/master/controller/interface.c),
//! but with some better typing to make the interface a little more ergonomic to use
//!
//! This interface is written as a result of some investigation of the original [`lm3s_cmsis.h`](https://github.com/mitre-cyber-academy/2021-ectf-insecure-example/blob/master/controller/lm3s/lm3s_cmsis.h)
//! implementation, where some amount of code review was used to extract the [UART{0,1,2} addresses](https://github.com/mitre-cyber-academy/2021-ectf-insecure-example/blob/master/controller/lm3s/lm3s_cmsis.h#L876)
//! (later confirmed by reviewing the [original specification](https://www.ti.com/lit/ds/symlink/lm3s6965.pdf))
//! as well as the [struct defining the UART peripheral](https://github.com/mitre-cyber-academy/2021-ectf-insecure-example/blob/master/controller/lm3s/lm3s_cmsis.h#L620).
//! The addresses for the memory-mapped UART peripherals were stored in the [INTF](INTF) enum and
//! these addresses were upcasted to mutable [UART](UART) references for use internally. Further
//! details, including the research that went into defining each type, can be found in their
//! respective type documentation.
//!
//! It was unnecessary to provide the device vector table or interrupt bindings as these are
//! helpfully defined for us by the [lm3s6965 crate](https://github.com/japaric/lm3s6965/blob/master/src/lib.rs)
//! (thanks, [Jorge Aparicio](https://github.com/japaric)!).

use core::fmt::Formatter;
use core::fmt::{Debug, Result as FmtResult};
use core::result::Result as CoreResult;

use cortex_m::asm;
use volatile_register::{RO, RW, WO};

use crate::interface::Error::{NoData, SomeData};
use crate::interface::RWStatusMask::{RXFE, TXFF};

/// The UART struct as specified by the CMSIS specification (and, more specifically, [line 620 of `lm3s_cmsis.h`](https://github.com/mitre-cyber-academy/2021-ectf-insecure-example/blob/master/controller/lm3s/lm3s_cmsis.h#L620))
///
/// This implementation differs slightly in that [volatile registers](https://docs.rs/volatile-register/0.2.0/volatile_register/)
/// are used in place of type metadata [as defined in `core_cm3.h`](https://github.com/mitre-cyber-academy/2021-ectf-insecure-example/blob/master/controller/CMSIS/Include/core_cm3.h#L197)
/// to compile-time enforce appropriate reading and writing to these registers.
///
/// Otherwise, this struct should never be instantiated, but instead static mutable references to
/// raw pointers (which point to the [various memory-mapped UART peripherals](https://github.com/mitre-cyber-academy/2021-ectf-insecure-example/blob/master/controller/lm3s/lm3s_cmsis.h#L876))
/// should be derived via [raw pointer to reference casting](https://docs.rust-embedded.org/book/c-tips/index.html#references-vs-pointers).
#[repr(C)]
struct UART {
    /// Data register
    dr: RW<u32>,
    /// Receive status register
    rsr: RW<u32>,
    /// A reserved region with no explicit use
    reserved1: [u8; 16],
    /// Flag register
    fr: RO<u32>,
    /// A reserved region with no explicit use
    reserved2: [u8; 4],
    /// UART IrDA low-power register
    ilpr: RW<u32>,
    /// Integer baud rate divisor register
    ibrd: RW<u32>,
    /// Fractional baud rate divisor register
    fbrd: RW<u32>,
    /// UART line control
    lcrh: RW<u32>,
    /// Control register
    ctl: RW<u32>,
    /// Interrupt FIFO level select register
    ifls: RW<u32>,
    /// Interrupt mask set/clear register
    im: RW<u32>,
    /// Raw interrupt status register
    ris: RO<u32>,
    /// Masked interrupt status register
    mis: RO<u32>,
    /// Interrupt clear register
    icr: WO<u32>,
    /// UART DMA control
    dmactl: RW<u32>,
}

/// Masks which determine the read/write availability of the data register
pub enum RWStatusMask {
    /// Mask for determining the read availability of the data register
    RXFE = 0x10,
    /// Mask for determining the write availability of the data register
    TXFF = 0x20,
}

/// Memory-mapped UART peripheral addresses for the different serial lines, which will then be
/// copied to the sockets for the respective data lines being emulated
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
pub enum INTF {
    /// Address of the UART which connects to the CPU
    CPU = 0x4000_C000,
    /// Address of the UART which connects to the SSS
    SSS = 0x4000_D000,
    /// Address of the UART which connects to the radio
    RAD = 0x4000_E000,
}

/// Generic error type for interface operations
#[allow(dead_code)]
#[derive(Debug)]
pub enum Error {
    /// An unknown error occurred during the interface operation
    Unknown,
    /// No data was received during the read operation
    NoData,
    /// Only some data was received during the read operation
    SomeData(usize),
}

/// Result type for interface operations
pub type Result<T> = CoreResult<T, Error>;

/// Wrapper type for interfacing with the UART peripherals
///
/// This type is effectively equivalent to the struct defined in the original C implementation, but
/// methods are defined on the interface instead to restrict operations to a theoretically safe
/// subset of operations on the UART peripheral.
pub struct Interface {
    /// The UART adapter to be manipulated by this wrapper
    uart: &'static mut UART,
}

impl Interface {
    /// Instantiate a new interface for the given UART peripheral
    ///
    /// The initialisation of the UART peripheral is ported wholesale from [the original C implementation](https://github.com/mitre-cyber-academy/2021-ectf-insecure-example/blob/master/controller/interface.c#L25),
    /// but additional steps were taken to verify the correctness of this operation by reviewing the
    /// [original specification](https://www.ti.com/lit/ds/symlink/lm3s6965.pdf).
    pub fn new(intf: INTF) -> Self {
        // SAFETY: these addresses have been confirmed as the correct addresses for the
        // memory-mapped UART peripherals, and the struct has been confirmed as the correct per the
        // TI specification linked above
        unsafe {
            let uart = &mut *(intf as usize as *mut UART);
            uart.ctl.write(uart.ctl.read() & 0xffff_fffe);
            uart.ibrd.write((uart.ibrd.read() & 0xffff_0000) | 0x000a);
            uart.fbrd.write((uart.fbrd.read() & 0xffff_0000) | 0x0036);
            uart.lcrh.write(0x60);
            uart.ctl.write(uart.ctl.read() | 0x01);
            Interface { uart }
        }
    }

    /// Determines if data is available to be read
    #[inline]
    pub fn avail(&self) -> bool {
        self.uart.fr.read() & (RXFE as u32) == 0
    }

    /// Reads a byte from the UART data register, optionally blocking
    pub fn readb(&mut self, blocking: bool) -> Result<u8> {
        while blocking && !self.avail() {}

        if self.avail() {
            #[allow(clippy::cast_possible_truncation)]
            // truncation reviewed; this will only ever be a single byte
            Ok(self.uart.dr.read() as u8)
        } else {
            Err(NoData)
        }
    }

    /// Reads a buffer from the UART data register; returns the number of bytes successfully read
    ///
    /// Note that, unlike the original implementation, this does not unnecessarily perform a nop
    /// loop while blocking.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<()> {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = self.readb(true).map_err(|_| SomeData(i))?;
        }

        Ok(())
    }

    /// Discards the given number of bytes, without blocking
    pub fn discard(&mut self, n: usize) {
        for _ in 0..n {
            for _ in 0..10_000 {
                // some delay for buffering
                asm::nop()
            }

            if self.readb(false).is_err() {
                break; // fail fast
            }
        }
    }

    /// Discards bytes that match the supplied predicate; on success, returns the first byte that
    /// does not match the predicate
    pub fn discard_while(&mut self, predicate: impl Fn(u8) -> bool) -> Result<u8> {
        loop {
            let b = self.readb(true)?;

            if !predicate(b) {
                return Ok(b);
            }
        }
    }

    /// Write a byte to the UART data register -- always blocking
    pub fn writeb(&mut self, data: u8) {
        while self.uart.fr.read() & (TXFF as u32) != 0 {}
        // SAFETY: we ensure that the DR register is writable by checking the write mask above
        unsafe {
            self.uart.dr.write(data.into());
        }
    }

    /// Write a buffer to the UART data register -- always blocking
    pub fn write(&mut self, buf: &[u8]) {
        for b in buf {
            self.writeb(*b);
        }
    }

    /// Converts this interface into its named form instead of a wrapper, allowing references to
    /// specific UARTs without also referencing how to read and write to them
    pub fn named(&self) -> INTF {
        match self.uart as *const UART as usize {
            0x4000_C000 => INTF::CPU,
            0x4000_D000 => INTF::SSS,
            0x4000_E000 => INTF::RAD,
            _ => unreachable!("Impossible branch; only these addresses can be used"),
        }
    }
}

impl Clone for Interface {
    #[allow(clippy::cast_ref_to_mut)]
    fn clone(&self) -> Self {
        // SAFETY: UARTs are cloneable in this manner as they DO NOT MOVE for any reason; they are
        // explicitly mapped to a specific address
        let uart = unsafe { &mut *(self.uart as *const UART as *mut UART) };
        Self { uart }
    }
}

impl Debug for Interface {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{:?}", self.named())
    }
}
