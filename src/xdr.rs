//! Minimal XDR (RFC 4506) reader/writer for the gmond wire protocol.
//!
//! Strings on the wire are raw bytes. We carry them as Rust `String`s decoded
//! as Latin-1 (one byte -> one char U+0000..U+00FF), which round-trips every
//! byte losslessly and matches the ISO-8859-1 encoding gmond's XML declares.

use anyhow::{Result, bail};

pub fn latin1_decode(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

/// Inverse of `latin1_decode`. Chars above U+00FF (which only arise from
/// strings we build ourselves) are replaced with '?'.
pub fn latin1_encode(s: &str) -> Vec<u8> {
    s.chars().map(|c| if (c as u32) < 256 { c as u8 } else { b'?' }).collect()
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() - self.pos < n {
            bail!("xdr: short buffer (need {n} at {}, have {})", self.pos, self.buf.len());
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }

    pub fn bool(&mut self) -> Result<bool> {
        match self.u32()? {
            0 => Ok(false),
            1 => Ok(true),
            v => bail!("xdr: bad bool {v}"),
        }
    }

    pub fn f32(&mut self) -> Result<f32> {
        Ok(f32::from_bits(self.u32()?))
    }

    pub fn f64(&mut self) -> Result<f64> {
        Ok(f64::from_bits(u64::from_be_bytes(self.take(8)?.try_into().unwrap())))
    }

    pub fn string(&mut self) -> Result<String> {
        let len = self.u32()? as usize;
        let bytes = self.take(len)?;
        self.take((4 - len % 4) % 4)?;
        // C gmond treats strings as NUL-terminated; anything after a NUL is invisible to it.
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Ok(latin1_decode(&bytes[..end]))
    }
}

#[cfg(test)]
#[derive(Default)]
pub struct Writer {
    pub buf: Vec<u8>,
}

#[cfg(test)]
impl Writer {
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn i32(&mut self, v: i32) {
        self.u32(v as u32);
    }

    pub fn bool(&mut self, v: bool) {
        self.u32(v as u32);
    }

    pub fn f32(&mut self, v: f32) {
        self.u32(v.to_bits());
    }

    pub fn f64(&mut self, v: f64) {
        self.buf.extend_from_slice(&v.to_bits().to_be_bytes());
    }

    pub fn string(&mut self, s: &str) {
        let b = latin1_encode(s);
        self.u32(b.len() as u32);
        self.buf.extend_from_slice(&b);
        self.buf.extend(std::iter::repeat_n(0, (4 - b.len() % 4) % 4));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_round_trip_with_padding() {
        let mut w = Writer::default();
        w.string("abcde");
        assert_eq!(w.buf, b"\0\0\0\x05abcde\0\0\0");
        let mut r = Reader::new(&w.buf);
        assert_eq!(r.string().unwrap(), "abcde");
    }

    #[test]
    fn latin1_is_lossless() {
        let all: Vec<u8> = (1..=255).collect();
        assert_eq!(latin1_encode(&latin1_decode(&all)), all);
    }
}
