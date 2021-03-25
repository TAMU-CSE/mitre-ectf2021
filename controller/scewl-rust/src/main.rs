// Generate this documentation in a prettier form with `cargo doc --release --open`

//! CaptureTheFlaggies controller implementation for MITRE eCTF!
//!
//! ## Building
//!
//! To compile this crate by hand, please ensure that you do the following:
//!
//!  - Install the following packages (or equivalent) for your operating system:
//!    - `build-essential`
//!    - `binutils-arm-none-eabi`
//!    - `clang`
//!    - `gcc-arm-none-eabi`
//!  - Install Rust 1.51 via [Rustup](https://rustup.rs/)
//!  - Install the `thumbv7m-none-eabi` target via rustup: `rustup target add thumbv7m-none-eabi`
//!  - Build it! `SCEWL_ID=${SCEWL_ID} cargo build --release`, where `SCEWL_ID` is your intended id
//!    for this instance. Optionally use `--features semihosted` to enable QEMU semihosting for
//!    logging debug information to the host. You can also build without specifying a `SCEWL_ID`,
//!    but this will provide defaults for the ID and the SED SSS registration secret.
//!
//! To run via QEMU, you need to perform an additional objcopy step, the output of which can then be
//! used as a `-kernel` argument: `arm-none-eabi-objcopy -O binary target/thumbv7m-none-eabi/release/controller kernel`
//!
//! Otherwise, this crate can be used via the typical build process for the MITRE eCTF as specified
//! in [getting_started.md](https://github.com/mitre-cyber-academy/2021-ectf-insecure-example/blob/master/getting_started.md).
//!
//! ## Design
//!
//! This implementation of the controller is very similar to the original provided in [MITRE's example implementation](https://github.com/mitre-cyber-academy/2021-ectf-insecure-example)
//! with a few key differences:
//!
//!  - Hopefully, it's not insecure!
//!  - As you probably already know, this implementation is written in Rust and, as such, does _not_
//!    depend on the provided lm3s or CMSIS dependencies. Instead, the [cortex-m](https://docs.rs/cortex-m/0.7.2/cortex_m/)
//!    crate and the [lm3s6965](https://docs.rs/lm3s6965/0.1.3/lm3s6965/) crates provided by the
//!    [Rust Embedded Cortex-M team](https://github.com/rust-embedded/wg#the-cortex-m-team) and
//!    [Jorge Aparicio](https://github.com/japaric), respectively, are used to provide the basic
//!    embedded systems operations necessary to run on the lm3s6965 processor.
//!  - This crate uses _minimal unsafe operations_. All unsafe code is present in [Interface](interface::Interface)
//!    as read/write operations on the UART{0,1,2} peripherals via memory-mapped registers.
//!  - The original implementation defined functions which operated on structs; in this crate, we
//!    define structs with methods to perform the operations, which more idiomatically represents
//!    the controller's operations.
//!
//! ### Structure
//!
//! Where the original implementation used functions which interacted with structs in C, this
//! implementation attempts to more ergonomically represent operations taken by the controller by
//! recognising that the only communications methods which are permitted to be modified are those
//! between the SSS and other SEDs (excluding FAA); otherwise, information is effectively
//! transparently proxied to and from the CPU.
//!
//! To account for this abstraction, we separate the controller into the following modules:
//!
//!  - The controller itself, the driver for communications, which employs an crypto handler and
//!    an authentication handler
//!  - The crypto handler, which decrypts/encrypts information to/from the CPU to other SEDs
//!  - The authentication handler, which interacts with the SSS and generates the crypto handler
//!    specified by that SSS
//!
//! As we wish to test the basic operation of the communications channel as well as the additional
//! security features on top, it behooves us to employ [type generics](https://doc.rust-lang.org/book/ch10-01-syntax.html)
//! to allow for plug-and-play replacements for both the crypto handler and authentication
//! handler. To do so, we define traits for [encryption](crypto::Handler) and
//! [authentication](auth::Handler). The [controller implementation](controller::Controller)
//! is generified to support arbitrary implementations of these handlers, restricting their use to
//! only the permitted changes as defined in the MITRE eCTF specification.
//!
//! ## Implementation
//!
//! ### Interface
//!
//! As we wished to omit C dependencies entirely, some research was done to identify the mechanism
//! by which the [interface](https://github.com/mitre-cyber-academy/2021-ectf-insecure-example/blob/master/controller/interface.c)
//! implemented input/output from/to the sockets over which communication was emulated.
//!
//! To match the behaviour of the original interface code, both the original C implementation and
//! portions of the lm3s dependency were inspected and subsequently ported to Rust. A discussion on
//! the details of this is available in the [interface module documentation](interface).
//!
//! ### Controller
//!
//! As previously discussed, the controller was modularised to support plug-and-play compatibility
//! with various encryption and authentication handlers. The controller implementation in Rust is
//! a near direct port of the C implementation with minor changes to support different handlers;
//! further discussion of these changes are available in the [controller module documentation](controller).
//!
//! ### Handlers
//!
//! Present in this crate are two handler families: a [trivial implementation](trivial), which, as
//! the name suggests, trivially implements the encryption and authentication schemes (read: none)
//! leveraged by the [insecure controller implementation](https://github.com/mitre-cyber-academy/2021-ectf-insecure-example/blob/master/controller/controller.c).
//!
//! The second handler family is the one used in production to be targeted by live adversaries and
//! is denoted as the [secure implementation](secure). This implementation leverages multiple
//! security features to ensure that messages cannot be intercepted, modified, or replayed. A full
//! discussion on those security features can be found in the documentation for that module.

#![no_std]
#![no_main]
#![warn(clippy::pedantic)] // enforce pedantic checks -- false positive prone
#![deny(clippy::missing_docs_in_private_items)] // enforce documentation

use cortex_m_rt::entry;
use cortex_m_rt::exception;
use lm3s6965 as _;
#[cfg(not(feature = "semihosted"))]
use panic_halt as _;
#[cfg(feature = "semihosted")]
use panic_semihosting as _;

use crate::controller::{Controller, SCEWL_MAX_DATA_SZ};

mod auth;
mod controller;
mod crypto;
mod cursor;
mod interface;
mod secure;
mod trivial;

#[macro_export]
macro_rules! debug {
    ($($args: expr),+) => {
        #[cfg(feature = "semihosted")]
        ::cortex_m_semihosting::hprintln!($($args),+).unwrap();
    }
}

// includes the code generated by build.rs; these are the values specified at build time
include!(concat!(env!("OUT_DIR"), "/values.rs"));

/// Entrypoint for the controller embedded software, which instantiates the controller with the
/// selected authentication and crypto handlers, then enters the controller run loop
#[entry]
fn main() -> ! {
    let mut data = [0_u8; SCEWL_MAX_DATA_SZ];
    let mut client = Controller::new(
        SCEWL_ID.into(),
        &mut data,
        secure::AuthHandler::new(&SECRET),
    );

    client.run()
}

/// Handler for exceptions generated by the processor. In our case, we are not handling them as they
/// do not pertain to our use case (we are not asynchronously processing input from UART{0,1,2})
#[exception]
#[allow(non_snake_case)]
fn DefaultHandler(_irqn: i16) {}
