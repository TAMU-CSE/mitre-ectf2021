//! Implementations of read/write cursors which assist with writing chunks of data to a continuous
//! byte sequence
//!
//! These types are meant for internal use for consistent copying and serialisation between the
//! data buffer of the controller and various types which can be (de)serialised from/to byte arrays.

use byteorder::{ByteOrder, NativeEndian};
use core::cmp::min;
use core::convert::TryInto;
use core::mem::size_of;

/// Cursor which enables reading from a buffer in strictly increasing indices; useful for unpacking
/// data from bytes into types
#[derive(Debug)]
pub struct ReadCursor<'a> {
    /// The buffer being read by the cursor
    buf: &'a [u8],
}

impl<'a> ReadCursor<'a> {
    /// Creates a new read cursor over the referenced buffer
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    /// Advances the cursor `n` bytes on the referenced buffer
    pub fn advance(&mut self, n: usize) {
        self.buf = &self.buf[n..];
    }

    /// Limits the cursor's scanning to a specific range; useful for [`copy_to`](ReadCursor::copy_to)
    pub fn limit(&mut self, n: usize) {
        self.buf = &self.buf[..n];
    }

    /// Reads a u16 from the buffer, then advances by the size of one u16
    pub fn read_u16(&mut self) -> u16 {
        let val = NativeEndian::read_u16(self.buf);
        self.advance(size_of::<u16>());
        val
    }

    /// Reads an i16 from the buffer, then advances by the size of one i16
    pub fn read_i16(&mut self) -> i16 {
        let val = NativeEndian::read_i16(self.buf);
        self.advance(size_of::<i16>());
        val
    }

    /// Reads 16 bytes from the buffer, then advances by 16 bytes
    pub fn read_16_u8(&mut self) -> [u8; 16] {
        let val = self.buf[..16].try_into().unwrap();
        self.advance(16);
        val
    }

    /// Reads 32 bytes from the buffer, then advances by 32 bytes
    pub fn read_32_u8(&mut self) -> [u8; 32] {
        let val = self.buf[..32].try_into().unwrap();
        self.advance(32);
        val
    }

    /// Copies the content of the read cursor into the write cursor, up to either the end of this
    /// cursor or the one being written to, whichever comes first
    pub fn copy_to(&mut self, wc: WriteCursor) -> usize {
        let len = min(wc.buf.len(), self.buf.len());
        wc.buf[..len].copy_from_slice(&self.buf[..len]);
        self.advance(len);
        len
    }
}

/// Cursor which enables writing to a buffer in strictly increasing indices; useful for unpacking
/// data from types into bytes
///
/// Note that, to preserve the consistency of the mutated buffer, the functions here consume the
/// write cursor, returning the updated cursor to allow for chaining of writes
#[derive(Debug)]
pub struct WriteCursor<'a> {
    buf: &'a mut [u8],
}

impl<'a> WriteCursor<'a> {
    /// Creates a new write cursor over the referenced buffer
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf }
    }

    /// Advances the cursor forward `n` bytes on the referenced buffer
    pub fn advance(self, n: usize) -> Self {
        Self {
            buf: &mut self.buf[n..],
        }
    }

    /// Limits the cursor's writing to a specific range; useful for [`write`](WriteCursor::write)
    pub fn limit(self, n: usize) -> Self {
        Self {
            buf: &mut self.buf[..n],
        }
    }

    /// Writes a byte to the buffer, then advances by a byte
    pub fn write_u8(self, n: u8) -> Self {
        self.buf[0] = n;
        self.advance(1)
    }

    /// Writes a u16 to the buffer, then advances by the size of one u16
    pub fn write_u16(self, n: u16) -> Self {
        NativeEndian::write_u16(self.buf, n);
        self.advance(size_of::<u16>())
    }

    /// Writes an i16 to the buffer, then advances by the size of one i16
    pub fn write_i16(self, n: i16) -> Self {
        NativeEndian::write_i16(self.buf, n);
        self.advance(size_of::<i16>())
    }

    /// Writes a usize to the buffer, then advances by the size of one usize
    pub fn write_usize(self, n: usize) -> Self {
        self.buf.copy_from_slice(&n.to_ne_bytes());
        self.advance(size_of::<u64>())
    }

    /// Writes a u64 to the buffer, then advances by the size of one u64
    pub fn write_u64(self, n: u64) -> Self {
        NativeEndian::write_u64(self.buf, n);
        self.advance(size_of::<u64>())
    }

    /// Writes the entire contents of the read cursor provided to this buffer, if possible
    ///
    /// If the read cursors remaining data is larger than the remaining data in this write cursor,
    /// this method returns itself in an `Err` without modifying the underlying buffer or advancing.
    /// Otherwise, this method returns an advanced cursor and writes the content of the provided
    /// read cursor to the underlying buffer.
    pub fn write(self, rc: ReadCursor) -> Result<Self, Self> {
        if self.buf.len() < rc.buf.len() {
            Err(self)
        } else {
            self.buf[..rc.buf.len()].copy_from_slice(rc.buf);
            Ok(self.advance(rc.buf.len()))
        }
    }
}
