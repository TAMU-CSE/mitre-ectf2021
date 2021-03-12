use crate::controller::SCEWL_MAX_DATA_SZ;

pub trait CryptoHandler {
    fn encrypt(&self, data: &mut [u8; SCEWL_MAX_DATA_SZ], len: usize);
    fn decrypt(&self, data: &mut [u8; SCEWL_MAX_DATA_SZ], len: usize);
}

pub struct NopCryptoHandler;

impl CryptoHandler for NopCryptoHandler {
    fn encrypt(&self, _: &mut [u8; 16384], _: usize) {}

    fn decrypt(&self, _: &mut [u8; 16384], _: usize) {}
}
