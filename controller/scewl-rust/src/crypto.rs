use crate::controller::SCEWL_MAX_DATA_SZ;

pub trait Handler {
    fn encrypt(&mut self, data: &mut [u8; SCEWL_MAX_DATA_SZ], len: usize) -> usize;
    fn decrypt(&mut self, data: &mut [u8; SCEWL_MAX_DATA_SZ], len: usize) -> Option<usize>;
}
