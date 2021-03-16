//! TODO: document full format of messages, protection mechanisms, etc. for this module and associated implementations

#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use core::mem::size_of;

use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use rand::{RngCore, SeedableRng};
use rand_hc::Hc128Rng;

use crate::controller::{Message, SCEWL_MAX_DATA_SZ};
use crate::crypto::Handler;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

pub struct SecureHandler {
    random: Hc128Rng,
    aes_key: [u8; 16],
    hmac_key: [u8; 16],
}

impl SecureHandler {
    const DEC_HEADER: usize = size_of::<[u8; 16]>();
    const ENC_HEADER: usize = size_of::<usize>();

    pub fn new(seed: [u8; 32], aes_key: [u8; 16], hmac_key: [u8; 16]) -> Self {
        let random = Hc128Rng::from_seed(seed);
        Self {
            random,
            aes_key,
            hmac_key,
        }
    }
}

impl Handler for SecureHandler {
    fn encrypt(&mut self, data: &mut [u8; SCEWL_MAX_DATA_SZ], message: Message) -> usize {
        // TODO: port this over to use a cursor
        let mut iv = [0_u8; 16];
        self.random.fill_bytes(&mut iv);
        let newlen = SecureHandler::DEC_HEADER + SecureHandler::ENC_HEADER + message.len;
        for (from, to) in (0..message.len)
            .zip((SecureHandler::DEC_HEADER + SecureHandler::ENC_HEADER)..newlen)
            .rev()
        {
            data[to] = data[from];
        }
        data[..size_of::<[u8; 16]>()].clone_from_slice(&iv[..size_of::<[u8; 16]>()]);
        for (from, to) in message
            .len
            .to_ne_bytes()
            .iter()
            .zip(data[SecureHandler::DEC_HEADER..][..SecureHandler::ENC_HEADER].iter_mut())
        {
            *to = *from;
        }
        let cbc = Aes128Cbc::new_var(&self.aes_key, &iv).unwrap();
        let actual = block_roundup(newlen);
        cbc.encrypt(
            &mut data[SecureHandler::DEC_HEADER..actual],
            SecureHandler::ENC_HEADER + message.len,
        )
        .unwrap();

        actual
    }

    fn decrypt(&mut self, data: &mut [u8; SCEWL_MAX_DATA_SZ], message: Message) -> Option<usize> {
        // TODO: port this over to use a cursor
        let mut iv = [0_u8; SecureHandler::DEC_HEADER];
        iv.copy_from_slice(&data[..SecureHandler::DEC_HEADER]);
        let cbc = Aes128Cbc::new_var(&self.aes_key, &iv).unwrap();
        cbc.decrypt(&mut data[SecureHandler::DEC_HEADER..message.len])
            .ok()?;
        let mut len = [0_u8; size_of::<usize>()];
        for (to, from) in len
            .iter_mut()
            .zip(data[SecureHandler::DEC_HEADER..][..SecureHandler::ENC_HEADER].iter_mut())
        {
            *to = *from;
        }
        let len = usize::from_ne_bytes(len);
        for (to, from) in (0..len)
            .zip(
                (SecureHandler::DEC_HEADER + SecureHandler::ENC_HEADER)
                    ..(len + (SecureHandler::DEC_HEADER + SecureHandler::ENC_HEADER)),
            )
            .rev()
        {
            data[to] = data[from];
        }

        Some(len)
    }
}

fn block_roundup(len: usize) -> usize {
    if len % 16 == 0 {
        len
    } else {
        len - (len % 16) + 16
    }
}
