//! The cryptography module for the secure implementation of the security features for the
//! controller
//!
//! # Design
//!
//! The crypto handler defined in this module constructs messages to other SCEWL devices in the
//! following layout:
//!
//! ```text
//! TRANSPORT
//!  | b'SC'    ; header magic
//!  | tgt_id   ; Target device's ID
//!  | src_id   ; Source device's ID
//!  | len      ; length of the remaining sections
//! VERIFICATION
//!  | iv       ; initialisation vector for the content segment
//!  | ctr      ; message counter
//!  | hmac     ; HMAC(TRANSPORT || iv || ctr)
//! CONTENT (encrypted)
//!  | hash     ; SHA256(msg)
//!  | msg_len  ; length of msg
//!  | msg      ; content intended to be sent by the CPU
//!  | padding  ; PKCS7 generated padding
//! ```
//!
//! ## Transport Segment
//!
//! The transport segment is the message header consistent with the original specification and is
//! not customised or modified by this crypto handler. For further information on this data type,
//! see the [struct's documentation](crate::controller::MessageHeader).
//!
//! ## Verification Segment
//!
//! The verification segment of the header contains three main values: an initialisation vector,
//! a counter, and a HMAC. This is the segment which will be inspected during the [`verify`](crate::crypto::Handler::verify)
//! method for message verification, and will inform the controller to drop the remainder of the
//! message if the message cannot be verified as authentic or processable.
//!
//! ### Counter Verification
//!
//! Each verification segment bears a counter, which identifies the number of messages which have
//! been sent so far to the receiver, including the current message. Should this counter be lower
//! than the last counter seen by this controller, then the message will be discarded.
//!
//! Counters are not falsifiable as they are authenticated by the HMAC.
//!
//! ### HMAC Verification
//!
//! Each verification segment bears an HMAC which both ensures the integrity and authenticity of
//! the transport and verification segments. The crypto handler implements this HMAC using a 64-byte
//! secret and the SHA256 hashing algorithm.
//!
//! The HMAC is calculated in the typical fashion and is the result of:
//!
//! ```
//! HMAC(TRANSPORT || iv || ctr)
//! ```
//!
//! where `||` is the concatenation operator.
//!
//! Should any part of the transport header, the initialisation vector, or the counter be corrupted
//! or modified, the HMAC will not be verifiable. In addition, should the HMAC itself be corrupted
//! or modified, it will not be verifiable.
//!
//! ## Content Segment
//!
//! The content segment of the header contains a hash of the original message, the length of the
//! original message, the original message, and padding as generated by PKCS7. This segment's
//! contents are encrypted using AES128 in the cipher block-chaining (CBC) mode with the
//! initialisation vector specified in the verification segment.
//!
//! ### Hash Verification
//!
//! The hash of the original message is present as the first item in the encrypted segment. Should
//! the original message or the hash be corrupted, the message verification will fail and the
//! message will be dropped.
//!
//! ### Length and Padding Verification
//!
//! Because the message uses CBC mode, if any bit in the encrypted segment is corrupted, that block
//! and all following blocks will also be corrupted during decryption. As such, the length can be
//! corrupted and the hash will attempt to compute the hash of a message which is either shorter
//! or possibly significantly longer than the original message.
//!
//! To ensure that length (and thereby message) corruption does not occur, padding is additionally
//! verified during decryption. This is not sufficient as a message verification, however; in
//! _extremely_ rare cases, the padding values may be correct. As such, the length value is always
//! checked to be correct (less than the maximum possible size of the original message according
//! to the size of the encrypted segment). Should not only padding, but also length be appropriately
//! generated, the message is _still_ verified to be the correct value via the SHA256 hash described
//! above.
//!
//! A failure to verify padding or length will cause the message to be dropped.
//!
//! # Security Requirement Compliance
//!
//! This implementation provides security requirements 5.1-5.4 of the specification. Requirement
//! 5.5 is implemented in the [controller run loop](crate::controller::Controller::run).
//!
//! ## Confidentiality (5.1)
//!
//! The confidentiality of messages is protected as described in Content Segment. No message from a
//! SED to any other SED, including broadcasts, will be sent in cleartext; instead, they will be
//! sent as encrypted by a globally shared AES key, which will only be provisioned to appropriately
//! registered and authenticated SEDs, as guaranteed by the SSS implementation.
//!
//! ## Integrity (5.2)
//!
//! The integrity of messages is verified by the counter and HMAC described in Verification Segment
//! and the hash, length, and padding described in the Content Segment section. Messages which fail
//! integrity checks will be dropped as though no message was ever received.
//!
//! ## Authentication (5.3)
//!
//! Messages are authenticated by both the HMAC described in Verification Segment. Should HMAC
//! verification fail, the remainder of the message is simply dropped. Only properly provisioned
//! SEDs will be able to send an authentic (and non-replayed) HMAC, as ensured by the SSS
//! implementation.
//!
//! ## Replay Protection (5.4)
//!
//! Messages are verified to be new by checking their counter field as described in Verification
//! Segment. If the counter is not greater than the previously observed counter, the message will
//! be dropped. The counter itself is verified by the HMAC as described in Verification Segment.

use core::mem::size_of;

use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use heapless::consts::U256;
use heapless::LinearMap;
use hmac::{Hmac, Mac, NewMac};
use rand::{RngCore, SeedableRng};
use rand_hc::Hc128Rng;
use sha2::{Digest, Sha256};

use crate::controller::{Id, Message, SCEWL_MAX_DATA_SZ};
use crate::crypto::Handler as CryptoHandler;
use crate::cursor::{ReadCursor, WriteCursor};
use crate::debug;

/// Shorthand for the AES mode used by the crypto handler
type Aes128Cbc = Cbc<Aes128, Pkcs7>;
/// Shorthand for the HMAC algorithm used by the crypto handler
type HmacSha256 = Hmac<Sha256>;

/// The secure crypto handler, which performs encryption, decryption, and verification of messages
pub struct Handler {
    /// A CSPRNG which is used to generate random IVs
    rng: Hc128Rng,
    /// The AES key
    aes_key: [u8; 16],
    /// The HMAC key
    hmac_key: [u8; 64],
    /// The outbound direct message counters
    send_dm_ctr: LinearMap<Id, u64, U256>,
    /// The inbound direct message counters
    recv_dm_ctr: LinearMap<Id, u64, U256>,
    /// The broadcast message counters
    brdcst_ctr: LinearMap<Id, u64, U256>,
}

impl Handler {
    /// Instantiates a new instance of the crypto handler, seeding the CSPRNG and setting the keys
    pub fn new(seed: [u8; 32], aes_key: [u8; 16], hmac_key: [u8; 64]) -> Self {
        Self {
            rng: Hc128Rng::from_seed(seed),
            aes_key,
            hmac_key,
            send_dm_ctr: LinearMap::default(),
            recv_dm_ctr: LinearMap::default(),
            brdcst_ctr: LinearMap::default(),
        }
    }
}

/// The verification segment of the message
#[derive(Copy, Clone, Debug)]
struct VerificationSegment {
    /// The IV used for decryption of the message
    iv: [u8; 16],
    /// The counter value of the message
    ctr: u64,
    /// The HMAC to be verified upon receiving the message
    hmac: [u8; 32],
}

impl VerificationSegment {
    /// Serialises this segment to bytes
    fn to_bytes(&self) -> [u8; VerificationSegment::size()] {
        let mut resp = [0_u8; VerificationSegment::size()];
        WriteCursor::new(&mut resp)
            .write(&self.iv)
            .write_u64(self.ctr)
            .write(&self.hmac);
        resp
    }

    /// Deserialises a segment from bytes
    fn from_bytes(data: &[u8]) -> Self {
        let mut cur = ReadCursor::new(&data);

        VerificationSegment {
            iv: cur.read_16_u8(),
            ctr: cur.read_u64(),
            hmac: cur.read_32_u8(),
        }
    }

    /// The constant size of the verification segment in its serialised form
    const fn size() -> usize {
        size_of::<[u8; 16]>() + size_of::<u64>() + size_of::<[u8; 32]>()
    }
}

/// The header of the encrypted content section
#[derive(Copy, Clone, Debug, Default)]
struct ContentHeader {
    /// The SHA256 hash of the cleartext message
    sha: [u8; 32],
    /// The length of the cleartext message
    len: usize,
}

impl ContentHeader {
    /// Serialises this header to bytes (in cleartext)
    fn to_bytes(&self) -> [u8; ContentHeader::size()] {
        let mut buf = [0_u8; ContentHeader::size()];
        WriteCursor::new(&mut buf)
            .write(&self.sha)
            .write_usize(self.len);
        buf
    }

    /// Deserialises a header from bytes (in cleartext)
    fn from_bytes(data: &[u8]) -> Self {
        let mut cur = ReadCursor::new(data);
        Self {
            sha: cur.read_32_u8(),
            len: cur.read_usize(),
        }
    }

    /// The constant size of the content header
    const fn size() -> usize {
        size_of::<[u8; 32]>() + size_of::<usize>()
    }
}

impl CryptoHandler for Handler {
    fn verify(&mut self, data: &[u8; SCEWL_MAX_DATA_SZ], msg: Message) -> bool {
        debug!("Verifying message: {:?}", msg);

        // aes-128 needs a subblock size that's a multiple of 16
        if (msg.len - VerificationSegment::size()) % 16 != 0 {
            debug!("Length is incorrect; bad length: {}", msg.len);
            return false;
        }

        let ct_hdr = VerificationSegment::from_bytes(data);

        let prev_ctr = match msg.tgt_id {
            Id::Broadcast => self.brdcst_ctr.get(&msg.src_id).copied().unwrap_or(0),
            Id::Other(_) => self.recv_dm_ctr.get(&msg.src_id).copied().unwrap_or(0),
            _ => unreachable!("Under NO CIRCUMSTANCES may SSS and FAA messages be encrypted!"),
        };

        if ct_hdr.ctr < prev_ctr {
            debug!("Bad counter received: {} (< {})", ct_hdr.ctr, prev_ctr);
            false // bad counter; this is a replay
        } else {
            // hmac = HMAC(PUBLIC || IV || CTR)
            let mut hmac = HmacSha256::new_varkey(&self.hmac_key)
                .expect("The HMAC key's buffer was insufficiently sized");
            hmac.update(&msg.to_canonical().to_bytes());
            hmac.update(&ct_hdr.iv);
            hmac.update(&ct_hdr.ctr.to_ne_bytes());
            match hmac.verify(&ct_hdr.hmac) {
                Ok(_) => {
                    debug!("HMAC verified; permitting decryption.");
                    true
                }
                Err(_) => {
                    debug!("HMAC not verified; ignoring.");
                    false
                }
            }
        }
    }

    fn verification_len(&self) -> usize {
        VerificationSegment::size()
    }

    fn encrypt(&mut self, data: &mut [u8; SCEWL_MAX_DATA_SZ], mut msg: Message) -> usize {
        debug!("Encrypting message: {:?}", msg);

        // get the hash of the message
        let mut sha = Sha256::new();
        sha.update(&data[..msg.len]);
        let mut enc_hdr = ContentHeader::default();
        enc_hdr.sha.copy_from_slice(&sha.finalize());

        // sets the length of the message
        enc_hdr.len = msg.len;

        // perform shift down
        data.copy_within(
            0..msg.len,
            VerificationSegment::size() + ContentHeader::size(),
        );

        // increment counter and pass it back
        let ctr = match msg.tgt_id {
            Id::Broadcast => {
                let mut ctr = self.brdcst_ctr.get(&msg.src_id).copied().unwrap_or(0);
                ctr += 1;
                self.brdcst_ctr
                    .insert(msg.src_id, ctr)
                    .expect("We don't have that many IDs!");
                ctr
            }
            id @ Id::Other(_) => {
                let mut ctr = self.send_dm_ctr.get(&msg.src_id).copied().unwrap_or(0);
                ctr += 1;
                self.send_dm_ctr
                    .insert(id, ctr)
                    .expect("We don't have that many IDs!");
                ctr
            }
            _ => unreachable!("Under NO CIRCUMSTANCES may SSS and FAA messages be encrypted!"),
        };

        // randomise IV
        let mut iv = [0_u8; 16];
        self.rng.fill_bytes(&mut iv);

        let mut ct_hdr = VerificationSegment {
            iv,
            ctr,
            hmac: [0_u8; 32],
        };

        // data = [ct_hdr, enc(en_hdr, msg)]

        debug!(
            "Range to be encrypted: {:?}..{:?}",
            VerificationSegment::size(),
            VerificationSegment::size() + ContentHeader::size() + enc_hdr.len
        );

        WriteCursor::new(&mut data[VerificationSegment::size()..]).write(&enc_hdr.to_bytes());

        // encrypt
        let aes = Aes128Cbc::new_var(&self.aes_key, &ct_hdr.iv).unwrap();
        let enc_len = aes
            .encrypt(
                &mut data[VerificationSegment::size()..],
                ContentHeader::size() + enc_hdr.len,
            )
            .expect("The controller's data buffer was insufficiently sized")
            .len();

        msg.len = VerificationSegment::size() + enc_len;

        // hmac = HMAC(PUBLIC || IV || CTR)
        let mut hmac = HmacSha256::new_varkey(&self.hmac_key)
            .expect("The HMAC key's buffer was insufficiently sized");
        hmac.update(&msg.to_canonical().to_bytes());
        hmac.update(&ct_hdr.iv);
        hmac.update(&ctr.to_ne_bytes());
        ct_hdr.hmac.copy_from_slice(&hmac.finalize().into_bytes());

        // serialise cleartext header and encrypted header
        WriteCursor::new(data).write(&ct_hdr.to_bytes());

        debug!("Generated cleartext header: {:?}", ct_hdr);
        debug!("Generated encrypted header: {:?}", enc_hdr);
        debug!("Encrypted buffer; prepared for sending.");

        msg.len
    }

    fn decrypt(&mut self, data: &mut [u8; SCEWL_MAX_DATA_SZ], msg: Message) -> Option<usize> {
        debug!("Decrypting message: {:?}", msg);

        let ct_hdr = VerificationSegment::from_bytes(data);

        debug!("Found cleartext header: {:?}", ct_hdr);

        match msg.tgt_id {
            Id::Broadcast => {
                self.brdcst_ctr
                    .insert(msg.src_id, ct_hdr.ctr)
                    .expect("We don't have that many IDs!");
            }
            Id::Other(_) => {
                self.recv_dm_ctr
                    .insert(msg.src_id, ct_hdr.ctr)
                    .expect("We don't have that many IDs!");
            }
            _ => unreachable!("Under NO CIRCUMSTANCES may SSS and FAA messages be encrypted!"),
        };

        debug!(
            "Range to be decrypted: {:?}",
            VerificationSegment::size()..msg.len
        );

        // decrypt
        let aes = Aes128Cbc::new_var(&self.aes_key, &ct_hdr.iv).unwrap();
        if aes
            .decrypt(&mut data[VerificationSegment::size()..msg.len])
            .is_err()
        {
            debug!("Incorrect padding; discarding.");
            return None;
        }

        let enc_hdr = ContentHeader::from_bytes(&data[VerificationSegment::size()..]);

        debug!("Found encrypted header: {:?}", enc_hdr);

        if enc_hdr.len > msg.len - (VerificationSegment::size() - ContentHeader::size()) {
            debug!("Length specified by encrypted header is corrupted; dropping.");
            return None;
        }

        let mut sha = Sha256::new();
        sha.update(&data[(VerificationSegment::size() + ContentHeader::size())..][..enc_hdr.len]);
        if sha.finalize().as_slice() != enc_hdr.sha {
            debug!("SHA integrity check failed.");
            return None;
        }

        data.copy_within(
            (VerificationSegment::size() + ContentHeader::size())
                ..(VerificationSegment::size() + ContentHeader::size() + enc_hdr.len),
            0,
        );

        debug!(
            "Successfully decrypted content: {:?}",
            &data[..(enc_hdr.len)]
        );

        Some(enc_hdr.len)
    }
}
