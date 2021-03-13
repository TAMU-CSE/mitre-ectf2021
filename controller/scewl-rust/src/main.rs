#![no_std]
#![no_main]
#![warn(clippy::pedantic)]

use crate::controller::{Controller, SCEWL_MAX_DATA_SZ};
use cortex_m_rt::entry;
use cortex_m_rt::exception;
#[cfg(feature = "semihosted")]
use cortex_m_semihosting::hprintln;
use lm3s6965 as _;
#[cfg(not(feature = "semihosted"))]
use panic_halt as _;
#[cfg(feature = "semihosted")]
use panic_semihosting as _;

mod auth;
mod controller;
mod crypto;
mod interface;
mod secure;
mod trivial;

const SCEWL_ID: &str = env!("SCEWL_ID");

#[entry]
fn main() -> ! {
    let mut data = [0_u8; SCEWL_MAX_DATA_SZ];
    let mut client = Controller::new(&mut data, trivial::DefaultHandler);

    client.run()
}

// disable exception handling because we're lazy
#[exception]
#[allow(non_snake_case)]
fn DefaultHandler(_irqn: i16) {}
