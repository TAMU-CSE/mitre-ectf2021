use byteorder::{ByteOrder, NativeEndian};
use core::cmp::min;
use core::convert::TryInto;
use core::mem::size_of;

pub struct ReadCursor<'a> {
    buf: &'a [u8],
}

impl<'a> ReadCursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub fn advance(&mut self, n: usize) {
        self.buf = &self.buf[n..];
    }

    pub fn limit(&mut self, n: usize) {
        self.buf = &self.buf[..n];
    }

    pub fn read_u16(&mut self) -> u16 {
        let val = NativeEndian::read_u16(self.buf);
        self.advance(size_of::<u16>());
        val
    }

    pub fn read_i16(&mut self) -> i16 {
        let val = NativeEndian::read_i16(self.buf);
        self.advance(size_of::<i16>());
        val
    }

    pub fn read_16_u8(&mut self) -> [u8; 16] {
        let val = self.buf[..16].try_into().unwrap();
        self.advance(16);
        val
    }

    pub fn read_32_u8(&mut self) -> [u8; 32] {
        let val = self.buf[..32].try_into().unwrap();
        self.advance(32);
        val
    }

    pub fn copy_to(&mut self, wc: WriteCursor) -> usize {
        let len = min(wc.buf.len(), self.buf.len());
        if wc.buf.as_ptr() == self.buf.as_ptr() {
        } else if wc.buf[..len]
            .as_ptr_range()
            .contains(&self.buf[(len - 1)..].as_ptr())
        {
            // destination contains the end of source -- so we have to copy reversed
            for (to, from) in wc.buf.iter_mut().zip(self.buf.iter()).take(len).rev() {
                *to = *from;
            }
        } else {
            wc.buf[..len].copy_from_slice(&self.buf[..len]);
        };
        self.advance(len);
        len
    }
}

pub struct WriteCursor<'a> {
    buf: &'a mut [u8],
}

impl<'a> WriteCursor<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf }
    }

    pub fn advance(self, n: usize) -> Self {
        Self {
            buf: &mut self.buf[n..],
        }
    }

    pub fn limit(self, n: usize) -> Self {
        Self {
            buf: &mut self.buf[..n],
        }
    }

    pub fn write_u16(self, n: u16) -> Self {
        NativeEndian::write_u16(self.buf, n);
        self.advance(size_of::<u16>())
    }

    pub fn write_i16(self, n: i16) -> Self {
        NativeEndian::write_i16(self.buf, n);
        self.advance(size_of::<i16>())
    }

    pub fn write_u8(self, n: u8) -> Self {
        self.buf[0] = n;
        self.advance(1)
    }

    pub fn write_u64(self, n: u64) -> Self {
        NativeEndian::write_u64(self.buf, n);
        self.advance(size_of::<u64>())
    }
}
