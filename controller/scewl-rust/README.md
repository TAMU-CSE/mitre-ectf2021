# scewl-rust

An implementation of the controller for the MITRE eCTF competition.

## Building by hand

To compile this crate by hand, please ensure that you do the following:

 - Install the following packages (or equivalent) for your operating system:
   - `build-essential`
   - `binutils-arm-none-eabi`
   - `clang`
   - `gcc-arm-none-eabi`
 - Install Rust 1.51 via [Rustup](https://rustup.rs/)
 - Install the `thumbv7m-none-eabi` target via rustup: `rustup target add thumbv7m-none-eabi`
 - Build it! `SCEWL_ID=${SCEWL_ID} cargo build --release`, where `SCEWL_ID` is your intended id
   for this instance. Optionally use `--features semihosted` to enable QEMU semihosting for
   logging debug information to the host. You can also build without specifying a `SCEWL_ID`,
   but this will provide defaults for the ID and the SED SSS registration secret.

## Documentation

If you want to generate documentation for separate viewing from the code, simply use `cargo doc --release --open`.

## Licensing

This software is licensed under the MIT license (see [LICENSE](LICENSE) for a text copy), which is compatible with all 
dependencies excluding [subtle](https://github.com/dalek-cryptography/subtle). Subtle's BSD license is provided locally
in [LICENSE.subtle](LICENSE).

You can use [lichking](https://github.com/Nemo157/cargo-lichking) to verify licensing of this crate and its
dependencies.

This crate and all its dependencies are approved for both private and commercial use.
