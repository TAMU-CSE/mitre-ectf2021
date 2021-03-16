//! A near-direct port of the original C implementation, available in the [insecure implementation](https://github.com/mitre-cyber-academy/2021-ectf-insecure-example/blob/master/controller/controller.c).
//!
//! As described in the [crate documentation](..), this implementation is modularised to support
//! changes necessary to secure communications between controller and other SEDs while allowing
//! debugging of the underlying (and very simple) communications channel implemented in [the interface module](crate::interface).
//! To support this, the [controller struct](Controller) utilises a type generic to support
//! arbitrary [authentication handlers](crate::auth::Handler) and [crypto handlers](crate::crypto::Handler).
//!
//! To allow for custom authentication handlers, the [constructor for Controller](Controller::new)
//! requires an [`AuthHandler`](crate::auth::Handler). The controller calls on this `AuthHandler` during
//! the [`handle_registration`](Controller::handle_registration) to register and deregister. See [`handle_registration`](Controller::handle_registration)
//! for details.
//!
//! As the result of a successful registration, the `AuthHandler` instantiates a [`CryptoHandler`](crate::crypto::Handler).
//! This `CryptoHandler` will be used during [`handle_scewl_recv`](Controller::handle_scewl_recv),
//! [`handle_scewl_send`](Controller::handle_scewl_send), [`handle_brdcst_recv`](Controller::handle_brdcst_recv),
//! and [`handle_brdcst_send`](Controller::handle_brdcst_send) to encrypt and decrypt messages to
//! and from the radio, not including FAA messages. This enforces that FAA and non-radio messages
//! are not encrypted, regardless of the `CryptoHandler` used.
//!
//! When the CPU requests to deregister, the `CryptoHandler` is dropped and both in- and out-bound
//! SCEWL messages are refused (as they can no longer be sent or verified). We use this mechanism
//! of type-assured security throughout.

use core::cmp::min;
use core::mem::{size_of, size_of_val};

use crate::auth::Handler as AuthHandler;
use crate::crypto::Handler as CryptoHandler;
use crate::cursor::{ReadCursor, WriteCursor};
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
        WriteCursor::new(&mut bytes)
            .write_u8(b'S')
            .write_u8(b'C')
            .write_u16(self.tgt_id.into())
            .write_u16(self.src_id.into())
            .write_u16(self.len);
        bytes
    }

    /// Instantiates a `MessageHeader` based on the contents of a buffer according to the
    /// specification.
    ///
    /// While this type does not have the magicS and magicC fields, they are assumed to be present
    /// by this method.
    fn from_bytes(buf: [u8; 8]) -> Self {
        let mut cur = ReadCursor::new(&buf);
        // ignore the first two bytes
        cur.advance(2);

        Self {
            tgt_id: cur.read_u16().into(),
            src_id: cur.read_u16().into(),
            len: cur.read_u16(),
        }
    }
}

/// Container for SSS messages, according to the specification for SSS messages between the CPU and
/// the controller.
///
/// This type (and its members) are public as messages received from the CPU are in this format. The
/// `AuthHandler` is permitted (and expected) to implement a different message format to communicate
/// with the SSS and update the SSS accordingly.
#[derive(Copy, Clone)]
pub struct SSSMessage {
    /// The ID of the device attempting to register
    pub dev_id: Id,
    /// The operation attempted; see [`SSSOp`](SSSOp) for details
    pub op: SSSOp,
}

impl SSSMessage {
    /// Serialise the SSS message to a byte array
    pub fn to_bytes(self) -> [u8; 4] {
        let mut bytes = [0_u8; 4];

        WriteCursor::new(&mut bytes)
            .write_u16(self.dev_id.into())
            .write_i16(self.op.into());

        bytes
    }

    /// Deserialise the SSS message from a byte array
    pub fn from_bytes(data: &[u8]) -> SSSMessage {
        let mut cur = ReadCursor::new(&data);

        SSSMessage {
            dev_id: cur.read_u16().into(),
            op: cur.read_i16().into(),
        }
    }

    /// Acquires the (constant) size of the `SSSMessage` type, for convenience when this type is
    /// (de)serialised over a stream.
    pub const fn size() -> usize {
        size_of::<u16>() + size_of::<i16>()
    }
}

/// A literal port of the status codes used by the controller to indicate message sending/receiving
/// status
#[allow(dead_code)]
pub enum Error {
    /// Indicates that an unknown error occurred
    Unknown,
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
#[derive(Debug, Copy, Clone)]
pub struct Message {
    /// ID of the SED to receive this message
    pub tgt_id: Id,
    /// ID of the SED that sent this message
    pub src_id: Id,
    /// The length of this message, which is explicitly sized as usize and NOT u16 to support larger
    /// messages than those which go to and from the CPU
    pub len: usize,
}

/// Main type for the controller, which is a near-direct port of the original C implementation
///
/// The implementation of this type differs in that it can use arbitrary implementations of the
/// security-enhanceable parts of the SCEWL specification rather easily simply by using different
/// type which implements the respective handler types. For further information on how to
/// appropriately develop these handlers, see the documentation for [authentication handlers](crate::auth::Handler)
/// and [crypto handlers](crate::crypto::Handler).
pub struct Controller<'a, A, C>
where
    A: AuthHandler<C>,
    C: CryptoHandler,
{
    /// The ID of this controller; in the original C implementation, this was a macro called
    /// SCEWL_ID
    id: Id,
    /// The interface to the CPU, which more idiomatically manages reading and writing to the serial
    /// UART peripheral
    cpu: Interface,
    /// The interface to the SSS
    sss: Interface,
    /// Th interface to the radio
    rad: Interface,
    /// The data buffer used by Controller to send _all_ messages
    ///
    /// TODO consider returning the buffer and copying instead?
    data: &'a mut [u8; SCEWL_MAX_DATA_SZ],
    /// The authentication handler, which will be used to instantiate the crypto handler for the
    /// controller post-authentication
    auth: A,
    /// The crypto handler, which, when present, will encrypt and decrypt messages over the radio
    crypto: Option<C>,
}

impl<'a, A: AuthHandler<C>, C: CryptoHandler> Controller<'a, A, C> {
    /// Instantiates a new instance of the controller
    ///
    /// As explained in the [module documentation](crate::controller), controllers require an
    /// authentication handler to manage the registration and crypto handler availability
    /// during runtime.
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

impl<'a, A: AuthHandler<C>, C: CryptoHandler> Controller<'a, A, C> {
    /// Acquires a copy of the interface wrapper for a specific interface. This method is used
    /// internally as a shorthand for acquiring interfaces to read/write on.
    fn get_intf(&self, intf: &INTF) -> Interface {
        match intf {
            CPU => &self.cpu,
            SSS => &self.sss,
            RAD => &self.rad,
        }
        .clone()
    }

    /// Gets the ID of this controller, which is necessary for some authentication and cryptographic
    /// operations
    pub fn id(&self) -> Id {
        self.id
    }

    /// Gets the current registration status of this controller
    pub fn registered(&self) -> bool {
        self.crypto.is_some()
    }

    /// Gets a mutable reference to the internal data of this controller
    ///
    /// This method is intended to be used by handlers as a means of accessing the response data of
    /// a particular [`read_msg`](Controller::read_msg) operation
    pub fn data(&mut self) -> &mut [u8] {
        self.data
    }

    /// Reads a message of the given length from the interface specified, optionally blocking
    ///
    /// The content of the message will be written directly to the data buffer allocated for
    /// sending and receiving messages, available to other types via [`data`](Controller::data).
    ///
    /// This method _does not_ perform any cryptographic operations. Instead, if a message is
    /// expected to contain encrypted content (e.g. in the case that a message is received from
    /// another SED via direct message or broadcast), it will be post-processed by the [run loop](Controller::run)
    /// as handled by [`handle_scewl_recv`](Controller::handle_scewl_recv) and [`handle_brdcst_recv`](Controller::handle_brdcst_recv).
    /// See the respective method for details on this post-processing operation.
    pub fn read_msg(&mut self, intf: &INTF, len: u16, blocking: bool) -> Result<Message> {
        let mut intf = self.get_intf(intf);

        self.data[..len as usize].as_mut().fill(0);

        loop {
            let s = intf.readb(blocking).map_err(|_| Error::NoMessage)?;

            if s != b'S' {
                continue;
            }

            let mut c = b'S';

            while c == b'S' {
                c = intf.readb(blocking).map_err(|_| Error::NoMessage)?;
            }

            if c == b'C' {
                break;
            }
        }

        let mut buf: [u8; 8] = [0_u8; 8];
        intf.read(&mut buf[2..], 6, blocking)
            .map_err(|_| Error::NoMessage)?;
        let hdr = MessageHeader::from_bytes(buf);

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

        if res.map_err(|_| Error::NoMessage)? < message.len {
            Err(Error::NoMessage)
        } else {
            Ok(message)
        }
    }

    /// Sends the current content of the data buffer to the specified interface with the provided
    /// message header
    ///
    /// Note that, in particular, the message header specifies the length of the message. It is not
    /// necessary to write the message header to the data buffer in advance, as this method will
    /// send the message header first before sending the content of the data buffer, limited to the
    /// length specified in the provided message header.
    pub fn send_msg(&mut self, intf: &INTF, message: &Message) -> Result<()> {
        let mut intf = self.get_intf(intf);

        #[allow(clippy::cast_possible_truncation)] // length is truncated appropriately
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

    /// Method which is used internally to handle messages received on the radio interface from
    /// other SEDs, disincluding broadcasts (see [`handle_brdcst_recv`](Controller::handle_brdcst_recv))
    ///
    /// This method will be invoked by the [run loop](Controller::run) in the case that a received
    /// message is from another SED and not a broadcast. The crypto handler's [decryption operation](crate::crypto::Handler::decrypt)
    /// will be invoked before this message is passed on to the CPU.
    fn handle_scewl_recv(&mut self, src_id: Id, len: usize) -> Result<()> {
        let mut message = Message {
            tgt_id: self.id,
            src_id,
            len,
        };
        message.len = self
            .crypto
            .as_mut()
            .ok_or(Error::Unknown)?
            .decrypt(&mut self.data, message)
            .ok_or(Error::Unknown)?;

        self.send_msg(&CPU, &message)
    }

    /// Method which is used internally to handle messages received on the CPU interface to be sent
    /// to other SEDs, disincluding broadcasts (see [`handle_brdcst_send`](Controller::handle_brdcst_send))
    ///
    /// This method will be invoked by the [run loop](Controller::run) in the case that a message to
    /// be sent is a direct message to another SED. The crypto handler's [encryption operation](crate::crypto::Handler::encrypt)
    /// will be invoked before this message is passed on to the radio.
    fn handle_scewl_send(&mut self, tgt_id: Id, len: usize) -> Result<()> {
        let mut message = Message {
            tgt_id,
            src_id: self.id,
            len,
        };
        message.len = self
            .crypto
            .as_mut()
            .ok_or(Error::Unknown)?
            .encrypt(&mut self.data, message);

        self.send_msg(&RAD, &message)
    }

    /// Method which is used internally to handle broadcasts received on the radio interface from
    /// other SEDs (see [`handle_scewl_recv`](Controller::handle_scewl_recv) for information on how
    /// direct messages are handled)
    ///
    /// This method will be invoked by the [run loop](Controller::run) in the case that a received
    /// message is from another SED and is a broadcast. The crypto handler's [decryption operation](crate::crypto::Handler::decrypt)
    /// will be invoked before this message is passed on to the CPU.
    fn handle_brdcst_recv(&mut self, src_id: Id, len: usize) -> Result<()> {
        let mut message = Message {
            tgt_id: Id::Broadcast,
            src_id,
            len,
        };
        message.len = self
            .crypto
            .as_mut()
            .ok_or(Error::Unknown)?
            .decrypt(&mut self.data, message)
            .ok_or(Error::Unknown)?;

        self.send_msg(&CPU, &message)
    }

    /// Method which is used internally to handle messages received on the CPU interface to be sent
    /// to other SEDs as a broadcast (see [`handle_scewl_send`](Controller::handle_scewl_send) for
    /// information on how direct messages are handled)
    ///
    /// This method will be invoked by the [run loop](Controller::run) in the case that a message to
    /// be sent is a broadcast. The crypto handler's [encryption operation](crate::crypto::Handler::encrypt)
    /// will be invoked before this message is passed on to the radio.
    fn handle_brdcst_send(&mut self, len: usize) -> Result<()> {
        let mut message = Message {
            tgt_id: Id::Broadcast,
            src_id: self.id,
            len,
        };
        message.len = self
            .crypto
            .as_mut()
            .ok_or(Error::Unknown)?
            .encrypt(&mut self.data, message);

        self.send_msg(&RAD, &message)
    }

    /// Method which is used internally to handle messages received on the radio interface from the
    /// FAA
    ///
    /// As per the specification, FAA messages will _not_ be encrypted by any mechanism. As such,
    /// this method simply forwards the message received on the radio directly to the CPU.
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

    /// Method which is used internally to handle messages to be sent to the FAA from the CPU
    ///
    /// As per the specification, FAA messages will _not_ be encrypted by any mechanism. As such,
    /// this method simply forwards the message to be sent to the radio directly from the CPU.
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

    /// Method which is used internally to manage registration with the SSS.
    ///
    /// The CPU is expected to initiate all (de)registration requests and, as such, this method will
    /// only be invoked by the [run loop](Controller::run) when the CPU requests to register or
    /// deregister. The authentication handler is expected to handle _all_ additional communications
    /// between the controller and the SSS, including any handshakes or exchanges of information.
    ///
    /// Should the CPU request to authenticate with the SSS, the authentication handler will be
    /// requested to perform a registration. Should this registration be successful, the
    /// authentication handler should instantiate a crypto handler appropriate for the SSS's
    /// response. This crypto handler will then be used until deregistration (or another successful
    /// registration) occurs by methods which send/recieve non-FAA messages over the radio.
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

    /// The run loop for the controller, which will never terminate
    ///
    /// This method is a near-exact port of the C implementation's main method, with changes for
    /// expressions that are more idiomatic for Rust.
    pub fn run(&mut self) -> ! {
        loop {
            #[allow(clippy::cast_possible_truncation)]
            // SCEWL_MAX_DATA_SZ is truncated appropriately
            if let Ok(msg) = self.read_msg(&CPU, SCEWL_MAX_DATA_SZ as u16, true) {
                if msg.tgt_id == Id::SSS {
                    let _ignored = self.handle_registration();
                }
            }

            while self.registered() {
                if self.cpu.avail() {
                    #[allow(clippy::cast_possible_truncation)]
                    // SCEWL_MAX_DATA_SZ is truncated appropriately
                    if let Ok(msg) = self.read_msg(&CPU, SCEWL_MAX_DATA_SZ as u16, true) {
                        let _ignored = match msg.tgt_id {
                            Id::Broadcast => self.handle_brdcst_send(msg.len).is_ok(),
                            Id::SSS => self.handle_registration(),
                            Id::FAA => self.handle_faa_send(msg.len).is_ok(),
                            id @ Id::Other(_) => self.handle_scewl_send(id, msg.len).is_ok(),
                        };

                        continue;
                    }
                }

                if self.rad.avail() {
                    #[allow(clippy::cast_possible_truncation)]
                    // SCEWL_MAX_DATA_SZ is truncated appropriately
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
