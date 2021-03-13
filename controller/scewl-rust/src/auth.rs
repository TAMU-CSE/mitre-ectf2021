use crate::controller::Controller;
use crate::crypto::Handler as CryptoHandler;

pub trait Handler<C: CryptoHandler + Sized>: Sized + Copy + Clone {
    fn sss_register(self, controller: &mut Controller<Self, C>) -> Option<C>;
    fn sss_deregister(self, controller: &mut Controller<Self, C>) -> bool;
}
