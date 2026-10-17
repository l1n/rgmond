//! Just enough pcap parsing to replay captured gmond UDP traffic.

use anyhow::{Result, bail};
use std::net::IpAddr;

pub struct Packet {
    pub ts_micros: i64,
    pub src: IpAddr,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

pub fn read(path: &str) -> Result<Vec<Packet>> {
    let data = std::fs::read(path)?;
    if data.len() < 24 {
        bail!("{path}: not a pcap file");
    }
    let magic = u32::from_le_bytes(data[0..4].try_into()?);
    let (le, nanos) = match magic {
        0xa1b2c3d4 => (true, false),
        0xa1b23c4d => (true, true),
        0xd4c3b2a1 => (false, false),
        0x4d3cb2a1 => (false, true),
        _ => bail!("{path}: bad pcap magic {magic:#x}"),
    };
    let u32at = |b: &[u8], o: usize| {
        let a: [u8; 4] = b[o..o + 4].try_into().unwrap();
        if le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) }
    };
    let linktype = u32at(&data, 20);
    let mut out = Vec::new();
    let mut off = 24;
    while off + 16 <= data.len() {
        let sec = u32at(&data, off) as i64;
        let frac = u32at(&data, off + 4) as i64;
        let caplen = u32at(&data, off + 8) as usize;
        off += 16;
        if off + caplen > data.len() {
            break;
        }
        let frame = &data[off..off + caplen];
        off += caplen;
        let ts = sec * 1_000_000 + if nanos { frac / 1000 } else { frac };
        let l3 = match linktype {
            276 => frame.get(20..),  // LINUX_SLL2
            113 => frame.get(16..),  // LINUX_SLL
            1 => frame.get(14..),    // Ethernet
            101 | 12 => Some(frame), // raw IP
            0 => frame.get(4..),     // BSD loopback
            _ => bail!("unsupported pcap linktype {linktype}"),
        };
        if let Some(p) = l3.and_then(|l3| parse_ip_udp(l3, ts)) {
            out.push(p);
        }
    }
    Ok(out)
}

fn parse_ip_udp(b: &[u8], ts: i64) -> Option<Packet> {
    let (src, udp) = match b.first()? >> 4 {
        4 => {
            let ihl = ((b[0] & 0x0f) as usize) * 4;
            if *b.get(9)? != 17 {
                return None;
            }
            let s: [u8; 4] = b.get(12..16)?.try_into().ok()?;
            (IpAddr::from(s), b.get(ihl..)?)
        }
        6 => {
            if *b.get(6)? != 17 {
                return None; // no extension-header support needed here
            }
            let s: [u8; 16] = b.get(8..24)?.try_into().ok()?;
            (IpAddr::from(s), b.get(40..)?)
        }
        _ => return None,
    };
    let dst_port = u16::from_be_bytes(udp.get(2..4)?.try_into().ok()?);
    let len = u16::from_be_bytes(udp.get(4..6)?.try_into().ok()?) as usize;
    let payload = udp.get(8..len.min(udp.len()))?.to_vec();
    Some(Packet { ts_micros: ts, src, dst_port, payload })
}
