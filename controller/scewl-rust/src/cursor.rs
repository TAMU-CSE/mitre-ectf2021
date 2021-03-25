//! Implementations of read/write cursors which assist with writing chunks of data to a continuous
//! byte sequence
//!
//! These types are meant for internal use for consistent copying and serialisation between the
//! data buffer of the controller and various types which can be (de)serialised from/to byte arrays.
//! Note that the cursor methods will **panic** if the respective buffers aren't the correct size.

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

    /// Reads a u16 from the buffer, then advances by the size of one u16
    pub fn read_u16(&mut self) -> u16 {
        let buf = self.buf[..size_of::<u16>()].try_into().unwrap();
        self.advance(size_of::<u16>());
        u16::from_ne_bytes(buf)
    }

    /// Reads an i16 from the buffer, then advances by the size of one i16
    pub fn read_i16(&mut self) -> i16 {
        let buf = self.buf[..size_of::<i16>()].try_into().unwrap();
        self.advance(size_of::<i16>());
        i16::from_ne_bytes(buf)
    }

    /// Reads a u64 from the buffer, then advances by the size of one u64
    pub fn read_u64(&mut self) -> u64 {
        let buf = self.buf[..size_of::<u64>()].try_into().unwrap();
        self.advance(size_of::<u64>());
        u64::from_ne_bytes(buf)
    }

    /// Reads a usize from the buffer, then advances by the size of one usize
    pub fn read_usize(&mut self) -> usize {
        let buf = self.buf[..size_of::<usize>()].try_into().unwrap();
        self.advance(size_of::<usize>());
        usize::from_ne_bytes(buf)
    }

    /// Reads an N-byte array from the buffer, then advances by N bytes
    pub fn read_literal<const N: usize>(&mut self) -> [u8; N] {
        let val = self.buf[..N].try_into().unwrap();
        self.advance(N);
        val
    }

    /// Copies the content of the read cursor into the write cursor, up to either the end of this
    /// cursor or the one being written to, whichever comes first
    pub fn copy_to(&mut self, dst: &mut [u8]) -> usize {
        let len = min(dst.len(), self.buf.len());
        dst[..len].copy_from_slice(&self.buf[..len]);
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
    /// Buffer which is written to by this cursor
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

    /// Writes a u16 to the buffer, then advances by the size of one u16
    pub fn write_u16(self, n: u16) -> Self {
        self.buf[..size_of::<u16>()].copy_from_slice(&n.to_ne_bytes());
        self.advance(size_of::<u16>())
    }

    /// Writes an i16 to the buffer, then advances by the size of one i16
    pub fn write_i16(self, n: i16) -> Self {
        self.buf[..size_of::<i16>()].copy_from_slice(&n.to_ne_bytes());
        self.advance(size_of::<i16>())
    }

    /// Writes a usize to the buffer, then advances by the size of one usize
    pub fn write_usize(self, n: usize) -> Self {
        self.buf[..size_of::<usize>()].copy_from_slice(&n.to_ne_bytes());
        self.advance(size_of::<usize>())
    }

    /// Writes a u64 to the buffer, then advances by the size of one u64
    pub fn write_u64(self, n: u64) -> Self {
        self.buf[..size_of::<u64>()].copy_from_slice(&n.to_ne_bytes());
        self.advance(size_of::<u64>())
    }

    /// Writes the entire source buffer to the underlying buffer,
    /// then advances by the length of the source buffer
    pub fn write(self, src: &[u8]) -> Self {
        self.buf[..src.len()].copy_from_slice(src);
        self.advance(src.len())
    }
}
