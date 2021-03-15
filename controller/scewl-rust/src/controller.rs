//! A near-direct port of the original C implementation, available in the [insecure implementation](https://github.com/mitre-cyber-academy/2021-ectf-insecure-example/blob/master/controller/controller.c).
//!
//! As described in the [crate documentation](..), this implementation is modularised to support
//! changes necessary to secure communications between controller and other SEDs while allowing
//! debugging of the underlying (and very simple) communications channel implemented in [the interface module](crate::interface).
//! To support this, the [controller struct](Controller) utilises a type generic to support
//! arbitrary [authentication handlers](crate::auth::Handler) and [encryption handlers](crate::crypto::Handler).
//!
//! To allow for custom authentication handlers, the [constructor for Controller](Controller::new)
//! requires an [`AuthHandler`](crate::auth::Handler). The controller calls on this `AuthHandler` during
//! the [`handle_registration`](Controller::handle_registration) to register and deregister. See [`handle_registration`](Controller::handle_registration)
//! for details.
//!
//! As the result of a successful registration, the `AuthHandler` instantiates a [`CryptoHandler`](crate::crypto::Handler).
//! This `CryptoHandler` will be used during [`handle_scewl_recv`](Controller::handle_scewl_recv) and
//! [`handle_scewl_send`](Controller::handle_scewl_send) to encrypt and decrypt messages to and from
//! the radio, not including FAA messages. This enforces that FAA and non-radio messages are not
//! encrypted, regardless of the `CryptoHandler` used.
//!
//! When the CPU requests to deregister, the `CryptoHandler` is dropped and both in- and out-bound
//! SCEWL messages are refused (as they can no longer be sent or verified). We use this mechanism
//! of type-assured security throughout.

use core::cmp::min;
use core::mem::{size_of, size_of_val};

use crate::auth::Handler as AuthHandler;
use crate::crypto::Handler as CryptoHandler;
use crate::interface::INTF::{CPU, RAD, SSS};
use crate::interface::{Interface, INTF};
use core::result::Result as CoreResult;
#[cfg(feature = "semihosted")]
use cortex_m_semihosting::hprintln;

/// The max data size for the messages after processing by the `CryptoHandler`.
///
/// This value has been chosen as a reasonable max on the in- and out-bound messages over the radio.
/// In an environment where we are guaranteed to have messages of even larger length sent reasonably
/// quickly with no data corruption worries, this value should be updated or removed.
pub const SCEWL_MAX_DATA_SZ: usize = 0x4000 * 2;

/// A simple type renaming for SCEWL IDs.
///
/// This ensures that ids require explicit coercion to be up/downcasted to u16s. Explicit coercions
/// are checked by clippy and are manually reviewed.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum Id {
    /// Id which denotes a broadcast; (de)serialised to/from 0_u16
    Broadcast,
    /// Id which denotes the SSS; (de)serialised to/from 1_u16
    SSS,
    /// Id which denotes the FAA; (de)serialised to/from 2_u16
    FAA,
    /// Id which denotes any other SED; (de)serialised to/from the u16 contained by this member
    Other(u16),
}

impl From<u16> for Id {
    fn from(num: u16) -> Id {
        match num {
            0 => Id::Broadcast,
            1 => Id::SSS,
            2 => Id::FAA,
            id => Id::Other(id),
        }
    }
}

impl From<Id> for u16 {
    fn from(id: Id) -> u16 {
        match id {
            Id::Broadcast => 0,
            Id::SSS => 1,
            Id::FAA => 2,
            Id::Other(id) => id,
        }
    }
}

impl Default for Id {
    fn default() -> Self {
        Id::Broadcast
    }
}

/// The message header required by the SCEWL specification
///
/// Struct members are marked private to discourage use of this type outside of this module. The
/// only use of this type is internal to this module to ensure that it is used appropriately. Note
/// that magicS and magicC are omitted from the struct declaration itself.
///
/// This type is only serialised with [`to_bytes`](MessageHeader::to_bytes), where it is prefixed
/// with 'S' and 'C' as denoted by the specification.
#[derive(Debug, Default)]
struct MessageHeader {
    /// ID of the SED to receive this message
    tgt_id: Id,
    /// ID of the SED sending this message
    src_id: Id,
    /// The length of this message
    len: u16,
}

impl MessageHeader {
    /// Converts the `MessageHeader` to a correct header according to the specification.
    ///
    /// While the struct itself does not have the magicS and magicC fields from the original
    /// controller code, this method introduces these values explicitly to ensure that this header
    /// possesses the header magic required.
    fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0_u8; 8];
        bytes[0] = b'S';
        bytes[1] = b'C';
        bytes[2..(2 + size_of::<u16>())].clone_from_slice(&u16::from(self.tgt_id).to_ne_bytes());
        bytes[(2 + size_of::<u16>())..(2 + size_of::<u16>() * 2)]
            .clone_from_slice(&u16::from(self.src_id).to_ne_bytes());
        bytes[(2 + size_of::<u16>() * 2)..(2 + size_of::<u16>() * 3)]
            .clone_from_slice(&self.len.to_ne_bytes());
        bytes
    }
}

/// Container for SSS messages, according to the specification for SSS messages between the CPU and
/// the controller.
///
/// This type (and its members) are public as messages received from the CPU are in this format. The
/// `AuthHandler` is permitted (and expected) to implement a different message format to communicate
/// with the SSS and update the SSS accordingly.
pub struct SSSMessage {
    /// The ID of the device attempting to register
    pub dev_id: Id,
    /// The operation attempted; see [`SSSOp`](SSSOp) for details
    pub op: SSSOp,
}

impl SSSMessage {
    /// Serialise the SSS message to a byte array
    pub fn to_bytes(&self) -> [u8; 4] {
        let mut bytes = [0_u8; 4];
        bytes[..size_of::<u16>()].clone_from_slice(&u16::from(self.dev_id).to_ne_bytes());
        bytes[size_of::<u16>()..SSSMessage::size()]
            .clone_from_slice(&i16::from(self.op).to_ne_bytes());
        bytes
    }

    /// Deserialise the SSS message from a byte array
    pub fn from_bytes(data: &[u8]) -> SSSMessage {
        let mut dev_id = [0_u8; 2];
        dev_id.copy_from_slice(&data[0..2]);
        let mut op = [0_u8; 2];
        op.copy_from_slice(&data[2..4]);
        SSSMessage {
            dev_id: u16::from_ne_bytes(dev_id).into(),
            op: i16::from_ne_bytes(op).into(),
        }
    }

    pub const fn size() -> usize {
        size_of::<u16>() + size_of::<i16>()
    }
}

/// A literal port of the status codes used by the controller to indicate message sending/receiving
/// status
#[allow(dead_code)]
pub enum Error {
    /// Indicates that an unknown error occurred
    Err,
    /// Indicates that a message was already sent or received
    Already,
    /// Indicates that no message was sent or received
    NoMessage,
}

/// Simple result type for methods in [`Controller`](Controller), either returning the expected type
/// or an error
pub type Result<T> = CoreResult<T, Error>;

/// SSS operation as listed by the specification for SSS messages to/from the CPU
#[allow(dead_code)]
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
pub enum SSSOp {
    /// Indicates that registration has already occurred for this device
    Already = -1,
    /// Indicates that registration was successful for this device, or that this device is attempting to register
    Register,
    /// Indicates that deregistration was successful for this device, or that this device is attempting to deregister
    Deregister,
    /// An unknown SSS operation, used in the case of a corrupt SSS message (unhandled by the original implementation)
    Unknown,
}

impl From<i16> for SSSOp {
    fn from(op: i16) -> SSSOp {
        match op {
            -1 => SSSOp::Already,
            0 => SSSOp::Register,
            1 => SSSOp::Deregister,
            _ => SSSOp::Unknown,
        }
    }
}

impl From<SSSOp> for i16 {
    fn from(op: SSSOp) -> i16 {
        op as i16
    }
}

/// Message wrapper, for implementations _not_ consistent with the original specification -- for
/// messages which are in- or out-bound on the SSS or radio
#[derive(Debug)]
pub struct Message {
    /// ID of the SED to receive this message
    pub tgt_id: Id,
    /// ID of the SED that sent this message
    pub src_id: Id,
    /// The length of this message, which is explicitly sized as usize and NOT u16 to support larger
    /// messages than those which go to and from the CPU
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
        let mut hdr = MessageHeader::default();

        for b in self.data[..len as usize].as_mut() {
            *b = 0
        }

        loop {
            let s;
            let mut c = b'S';

            match intf.readb(blocking) {
                Ok(b) => s = b,
                Err(_) => return Err(Error::NoMessage),
            }

            if s != b'S' {
                continue;
            }

            while c == b'S' {
                match intf.readb(blocking) {
                    Ok(b) => c = b,
                    Err(_) => return Err(Error::NoMessage),
                }
            }

            if c == b'C' {
                break;
            }
        }

        for item in &mut [&mut hdr.tgt_id.into(), &mut hdr.src_id.into(), &mut hdr.len] {
            let mut buf = [0_u8; size_of::<u16>()];
            if intf.read(&mut buf, size_of::<u16>(), blocking).is_err() {
                return Err(Error::NoMessage);
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
                    Err(Error::NoMessage)
                } else {
                    Ok(message)
                }
            }
            Err(_) => Err(Error::NoMessage),
        }
    }

    pub fn send_msg(&mut self, intf: &INTF, message: &Message) -> Result<()> {
        let mut intf = self.get_intf(intf);

        let hdr = MessageHeader {
            tgt_id: message.tgt_id,
            src_id: message.src_id,
            len: message.len as u16,
        };

        let hdr_bytes = hdr.to_bytes();
        intf.write(&hdr.to_bytes(), size_of_val(&hdr_bytes));

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
            return Err(Error::Err);
        }
        let actual = match self.crypto.as_mut().unwrap().decrypt(
            &mut self.data,
            Message {
                tgt_id: self.id,
                src_id,
                len,
            },
        ) {
            None => return Err(Error::Err),
            Some(message) => message,
        };

        self.send_msg(&CPU, &actual)
    }

    fn handle_scewl_send(&mut self, tgt_id: Id, len: usize) -> Result<()> {
        if self.crypto.is_none() {
            return Err(Error::Err);
        }
        let actual = self.crypto.as_mut().unwrap().encrypt(
            &mut self.data,
            Message {
                tgt_id,
                src_id: self.id,
                len,
            },
        );

        self.send_msg(&RAD, &actual)
    }

    fn handle_brdcst_recv(&mut self, src_id: Id, len: usize) -> Result<()> {
        if self.crypto.is_none() {
            return Err(Error::Err);
        }
        let actual = match self.crypto.as_mut().unwrap().decrypt(
            &mut self.data,
            Message {
                tgt_id: Id::Broadcast,
                src_id,
                len,
            },
        ) {
            None => return Err(Error::Err),
            Some(len) => len,
        };

        self.send_msg(&CPU, &actual)
    }

    fn handle_brdcst_send(&mut self, len: usize) -> Result<()> {
        if self.crypto.is_none() {
            return Err(Error::Err);
        }
        let actual = self.crypto.as_mut().unwrap().encrypt(
            &mut self.data,
            Message {
                tgt_id: Id::Broadcast,
                src_id: self.id,
                len,
            },
        );

        self.send_msg(&RAD, &actual)
    }

    fn handle_faa_recv(&mut self, len: usize) -> Result<()> {
        self.send_msg(
            &CPU,
            &Message {
                src_id: Id::FAA,
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
                tgt_id: Id::FAA,
                len,
            },
        )
    }

    fn handle_registration(&mut self) -> bool {
        let message = SSSMessage::from_bytes(self.data);
        match message.op {
            SSSOp::Register => self.auth.sss_register(self).map_or(false, |c| {
                self.crypto = Some(c);
                true
            }),
            SSSOp::Deregister if self.auth.sss_deregister(self) => {
                self.crypto = None;
                true
            }
            _ => false,
        }
    }

    pub fn run(&mut self) -> ! {
        loop {
            if let Ok(msg) = self.read_msg(&CPU, SCEWL_MAX_DATA_SZ as u16, true) {
                if msg.tgt_id == Id::SSS {
                    let _ignored = self.handle_registration();
                }
            }

            while self.registered() {
                if self.cpu.avail() {
                    if let Ok(msg) = self.read_msg(&CPU, SCEWL_MAX_DATA_SZ as u16, true) {
                        let _ignored = match msg.tgt_id {
                            Id::Broadcast => self.handle_brdcst_send(msg.len).is_ok(),
                            Id::SSS => self.handle_registration(),
                            Id::FAA => self.handle_faa_send(msg.len).is_ok(),
                            id => self.handle_scewl_send(id, msg.len).is_ok(),
                        };

                        continue;
                    }
                }

                if self.rad.avail() {
                    if let Ok(msg) = self.read_msg(&RAD, SCEWL_MAX_DATA_SZ as u16, true) {
                        let _ignored = match (msg.src_id, msg.tgt_id) {
                            (src, Id::Broadcast) => self.handle_brdcst_recv(src, msg.len).is_ok(),
                            (Id::FAA, tgt) if tgt == self.id => {
                                self.handle_faa_recv(msg.len).is_ok()
                            }
                            (src, tgt) if tgt == self.id => {
                                self.handle_scewl_recv(src, msg.len).is_ok()
                            }
                            _ => continue,
                        };
                    }
                }
            }
        }
    }
}
