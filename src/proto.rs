//! gmond 3.x UDP message formats (lib/gm_protocol.x).

use crate::xdr::Reader;
#[cfg(test)]
use crate::xdr::Writer;
use anyhow::{Result, bail};

pub const GMETADATA_FULL: u32 = 128;
pub const GMETRIC_USHORT: u32 = 129;
pub const GMETRIC_SHORT: u32 = 130;
pub const GMETRIC_INT: u32 = 131;
pub const GMETRIC_UINT: u32 = 132;
pub const GMETRIC_STRING: u32 = 133;
pub const GMETRIC_FLOAT: u32 = 134;
pub const GMETRIC_DOUBLE: u32 = 135;
pub const GMETADATA_REQUEST: u32 = 136;

/// Largest datagram gmond reads (max_udp_msg_len default).
pub const MAX_UDP_MSG_LEN: usize = 1472;

#[derive(Clone, Debug, PartialEq)]
pub struct MetricId {
    pub host: String,
    pub name: String,
    pub spoof: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Metadata {
    pub type_: String,
    pub name: String,
    pub units: String,
    pub slope: u32,
    pub tmax: u32,
    pub dmax: u32,
    /// In wire order. gmond prints these in reverse in its XML.
    pub extra: Vec<(String, String)>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    UShort(u16),
    Short(i16),
    Int(i32),
    UInt(u32),
    Str(String),
    Float(f32),
    Double(f64),
}

// rgmond only receives; encoding exists to build packets in tests.
#[cfg(test)]
impl Value {
    pub fn msg_id(&self) -> u32 {
        match self {
            Value::UShort(_) => GMETRIC_USHORT,
            Value::Short(_) => GMETRIC_SHORT,
            Value::Int(_) => GMETRIC_INT,
            Value::UInt(_) => GMETRIC_UINT,
            Value::Str(_) => GMETRIC_STRING,
            Value::Float(_) => GMETRIC_FLOAT,
            Value::Double(_) => GMETRIC_DOUBLE,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Msg {
    MetadataFull { id: MetricId, meta: Metadata },
    MetadataRequest { id: MetricId },
    Value { id: MetricId, fmt: String, value: Value },
}

fn read_id(r: &mut Reader) -> Result<MetricId> {
    Ok(MetricId { host: r.string()?, name: r.string()?, spoof: r.bool()? })
}

#[cfg(test)]
fn write_id(w: &mut Writer, id: &MetricId) {
    w.string(&id.host);
    w.string(&id.name);
    w.bool(id.spoof);
}

impl Msg {
    pub fn id(&self) -> &MetricId {
        match self {
            Msg::MetadataFull { id, .. } | Msg::MetadataRequest { id } | Msg::Value { id, .. } => id,
        }
    }

    pub fn decode(buf: &[u8]) -> Result<Msg> {
        let mut r = Reader::new(buf);
        let kind = r.u32()?;
        Ok(match kind {
            GMETADATA_FULL => {
                let id = read_id(&mut r)?;
                let type_ = r.string()?;
                let name = r.string()?;
                let units = r.string()?;
                let slope = r.u32()?;
                let tmax = r.u32()?;
                let dmax = r.u32()?;
                let n = r.u32()? as usize;
                if n > buf.len() / 8 {
                    bail!("metadata: {n} extra elements cannot fit in {} bytes", buf.len());
                }
                let mut extra = Vec::with_capacity(n);
                for _ in 0..n {
                    extra.push((r.string()?, r.string()?));
                }
                Msg::MetadataFull { id, meta: Metadata { type_, name, units, slope, tmax, dmax, extra } }
            }
            GMETADATA_REQUEST => Msg::MetadataRequest { id: read_id(&mut r)? },
            GMETRIC_USHORT..=GMETRIC_DOUBLE => {
                let id = read_id(&mut r)?;
                let fmt = r.string()?;
                let value = match kind {
                    GMETRIC_USHORT => Value::UShort(r.u32()? as u16),
                    GMETRIC_SHORT => Value::Short(r.i32()? as i16),
                    GMETRIC_INT => Value::Int(r.i32()?),
                    GMETRIC_UINT => Value::UInt(r.u32()?),
                    GMETRIC_STRING => Value::Str(r.string()?),
                    GMETRIC_FLOAT => Value::Float(r.f32()?),
                    _ => Value::Double(r.f64()?),
                };
                Msg::Value { id, fmt, value }
            }
            other => bail!("unknown message format {other}"),
        })
    }

    #[cfg(test)]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        match self {
            Msg::MetadataFull { id, meta } => {
                w.u32(GMETADATA_FULL);
                write_id(&mut w, id);
                w.string(&meta.type_);
                w.string(&meta.name);
                w.string(&meta.units);
                w.u32(meta.slope);
                w.u32(meta.tmax);
                w.u32(meta.dmax);
                w.u32(meta.extra.len() as u32);
                for (k, v) in &meta.extra {
                    w.string(k);
                    w.string(v);
                }
            }
            Msg::MetadataRequest { id } => {
                w.u32(GMETADATA_REQUEST);
                write_id(&mut w, id);
            }
            Msg::Value { id, fmt, value } => {
                w.u32(value.msg_id());
                write_id(&mut w, id);
                w.string(fmt);
                match value {
                    Value::UShort(v) => w.u32(*v as u32),
                    Value::Short(v) => w.i32(*v as i32),
                    Value::Int(v) => w.i32(*v),
                    Value::UInt(v) => w.u32(*v),
                    Value::Str(s) => w.string(s),
                    Value::Float(v) => w.f32(*v),
                    Value::Double(v) => w.f64(*v),
                }
            }
        }
        w.buf
    }
}

pub fn slope_to_str(slope: u32) -> &'static str {
    match slope {
        0 => "zero",
        1 => "positive",
        2 => "negative",
        3 => "both",
        5 => "derivative",
        _ => "unspecified",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let id = MetricId { host: "h".into(), name: "load_one".into(), spoof: false };
        let msgs = [
            Msg::MetadataFull {
                id: id.clone(),
                meta: Metadata {
                    type_: "float".into(),
                    name: "load_one".into(),
                    units: " ".into(),
                    slope: 3,
                    tmax: 70,
                    dmax: 0,
                    extra: vec![("GROUP".into(), "load".into())],
                },
            },
            Msg::MetadataRequest { id: id.clone() },
            Msg::Value { id: id.clone(), fmt: "%.2f".into(), value: Value::Float(0.25) },
            Msg::Value { id, fmt: "%s".into(), value: Value::Str("Linux".into()) },
        ];
        for m in msgs {
            assert_eq!(Msg::decode(&m.encode()).unwrap(), m);
        }
    }

    /// Anyone can send us UDP: decoding (and storing) arbitrary bytes must never panic.
    #[test]
    fn hostile_packets_do_not_panic() {
        let pcap = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/capture_restart/udp.pcap");
        // Real packets when the (local-only) capture is present; random bytes always.
        let real: Vec<Vec<u8>> = crate::pcap::read(pcap)
            .map(|v| v.into_iter().map(|p| p.payload).take(400).collect())
            .unwrap_or_default();
        let mut rng: u64 = 0x9e3779b97f4a7c15;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let mut store = crate::store::Store::default();
        let mut feed = |b: &[u8]| {
            if let Ok(m) = Msg::decode(b) {
                store.handle(m, "192.0.2.1", 1, &mut |_| None);
            }
        };
        for p in &real {
            for cut in 0..p.len() {
                feed(&p[..cut]);
            }
            for _ in 0..50 {
                let mut q = p.clone();
                for _ in 0..1 + next() % 4 {
                    let i = (next() as usize) % q.len();
                    q[i] = next() as u8;
                }
                feed(&q);
            }
        }
        for _ in 0..20000 {
            let n = (next() % 200) as usize;
            let b: Vec<u8> = (0..n).map(|_| next() as u8).collect();
            feed(&b);
        }
        // and the XML still renders
        let c = crate::xml::Cluster { name: None, owner: None, latlong: None, url: None };
        let p = crate::xml::XmlParams { cluster: &c, tags: "", host_tmax: 20, host_dmax: 0, allow_extra_data: true };
        crate::xml::render(&store, &p, 2);
    }
}
