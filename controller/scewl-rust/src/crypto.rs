use crate::controller::SCEWL_MAX_DATA_SZ;
use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, BlockModeError, Cbc};
use core::mem::size_of;
use rand::{RngCore, SeedableRng};
use rand_hc::Hc128Rng;

pub trait AuthHandler {
    fn encrypt(&mut self, data: &mut [u8; SCEWL_MAX_DATA_SZ], len: usize) -> usize;
    fn decrypt(&mut self, data: &mut [u8; SCEWL_MAX_DATA_SZ], len: usize) -> usize;
}

pub struct NopAuthHandler;

impl AuthHandler for NopAuthHandler {
    fn encrypt(&mut self, _: &mut [u8; SCEWL_MAX_DATA_SZ], len: usize) -> usize {
        len
    }

    fn decrypt(&mut self, _: &mut [u8; SCEWL_MAX_DATA_SZ], len: usize) -> usize {
        len
    }
}

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

pub struct AESCryptoHandler {
    key: [u8; 16],
    random: Hc128Rng,
}

impl AESCryptoHandler {
    const DEC_HEADER: usize = size_of::<[u8; 16]>();
    const ENC_HEADER: usize = size_of::<usize>();

    pub fn new(key: [u8; 16], seed: [u8; 32]) -> Self {
        let random = Hc128Rng::from_seed(seed);
        Self { key, random }
    }
}

impl AuthHandler for AESCryptoHandler {
    fn encrypt(&mut self, data: &mut [u8; SCEWL_MAX_DATA_SZ], len: usize) -> usize {
        let mut iv = [0_u8; 16];
        self.random.fill_bytes(&mut iv);
        let newlen = AESCryptoHandler::DEC_HEADER + AESCryptoHandler::ENC_HEADER + len;
        for (from, to) in (0..len)
            .zip((AESCryptoHandler::DEC_HEADER + AESCryptoHandler::ENC_HEADER)..newlen)
            .rev()
        {
            data[to] = data[from];
        }
        for i in 0..size_of::<[u8; 16]>() {
            data[i] = iv[i];
        }
        for (from, to) in len.to_ne_bytes().iter().zip(
            data[AESCryptoHandler::DEC_HEADER
                ..(AESCryptoHandler::DEC_HEADER + AESCryptoHandler::ENC_HEADER)]
                .iter_mut(),
        ) {
            *to = *from;
        }
        let cbc = Aes128Cbc::new_var(&self.key, &iv).unwrap();
        let actual = block_roundup(newlen);
        cbc.encrypt(
            &mut data[AESCryptoHandler::DEC_HEADER..actual],
            AESCryptoHandler::ENC_HEADER + len,
        )
        .unwrap();

        actual
    }

    fn decrypt(&mut self, data: &mut [u8; SCEWL_MAX_DATA_SZ], len: usize) -> Option<usize> {
        let mut iv = [0_u8; AESCryptoHandler::DEC_HEADER];
        iv.copy_from_slice(&data[..AESCryptoHandler::DEC_HEADER]);
        let cbc = Aes128Cbc::new_var(&self.key, &iv).unwrap();
        match cbc.decrypt(&mut data[AESCryptoHandler::DEC_HEADER..len]) {
            Ok(_) => {}
            Err(_) => return None,
        }
        let mut len = [0_u8; size_of::<usize>()];
        for (to, from) in len.iter_mut().zip(
            data[AESCryptoHandler::DEC_HEADER
                ..(AESCryptoHandler::DEC_HEADER + AESCryptoHandler::ENC_HEADER)]
                .iter_mut(),
        ) {
            *to = *from;
        }
        let len = usize::from_ne_bytes(len);
        for (to, from) in (0..len)
            .zip(
                (AESCryptoHandler::DEC_HEADER + AESCryptoHandler::ENC_HEADER)
                    ..(len + (AESCryptoHandler::DEC_HEADER + AESCryptoHandler::ENC_HEADER)),
            )
            .rev()
        {
            data[to] = data[from];
        }
        len
    }
}

fn block_roundup(len: usize) -> usize {
    if len % 16 == 0 {
        len
    } else {
        len - (len % 16) + 16
    }
}
