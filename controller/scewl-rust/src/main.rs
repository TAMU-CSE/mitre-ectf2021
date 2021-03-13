#![no_std]
#![no_main]
#![warn(clippy::pedantic)]

use crate::controller::{Controller, Id, SCEWL_MAX_DATA_SZ};
use core::str::FromStr;
use cortex_m_rt::entry;
use cortex_m_rt::exception;
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
    let mut client = Controller::new(
        Id::from_str(SCEWL_ID).unwrap(),
        &mut data,
        trivial::DefaultHandler,
    );

    client.run()
}

// disable exception handling because we're lazy
#[exception]
#[allow(non_snake_case)]
fn DefaultHandler(_irqn: i16) {}
