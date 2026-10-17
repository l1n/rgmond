//! Port of Ganglia's `network/multi_interface.py`: per-interface receive and
//! transmit rates (`rx_bytes_<if>`, `rx_pkts_`, `rx_errs_`, `rx_drops_`, and the
//! same for `tx_`).
//!
//! The Python module parses /proc/net/dev; this reads the same counters from an
//! rtnetlink `RTM_GETLINK` dump (`IFLA_STATS64`), rebuilt into /proc/net/dev's
//! sixteen columns with the kernel's arithmetic (`dev_seq_printf_stats`), so the
//! values are the ones Python sees. Semantics follow the Python module:
//!
//! * Interfaces are chosen once, at construction: the `interfaces` param split on
//!   single spaces if non-empty, else every interface whose name is not
//!   `re.match`ed (anchored at the start only) by a pattern in
//!   `excluded_interfaces`. Python crashes when both are empty; so does `new`.
//! * Snapshots are cached for `METRICS_CACHE_MAX` (5 s); a refresh moves the
//!   current snapshot to "last". Rates divide by the two snapshots' times.
//! * An interface missing from either snapshot (always on the first sample)
//!   gives 0.0; a negative delta (counter wrap or reset) gives 0.
//! * `get_delta` finds the interface as `name.split("_")[2]`, so an interface
//!   with `_` in its name (`ip_vti0`, `ip6_vti0`) is looked up as `ip` / `ip6`
//!   and always reads 0.0.
//! * The aggregate `bytes_in`/`bytes_out`/`pkts_in`/`pkts_out` callbacks are not
//!   ported: they are only collected when uncommented in the pyconf, and those
//!   names belong to the built-in network metrics.
#![cfg_attr(not(test), allow(dead_code))] // constructed once the scheduler wires sources in

use super::{Reading, Source};
use anyhow::{Context, Result, bail};
use std::collections::HashMap;

const METRICS_CACHE_MAX: f64 = 5.0;

/// `stats_tab`: metric stem -> /proc/net/dev column, in descriptor order.
const STATS_TAB: [(&str, usize); 8] = [
    ("rx_bytes", 0),
    ("rx_pkts", 1),
    ("rx_errs", 2),
    ("rx_drops", 3),
    ("tx_bytes", 8),
    ("tx_pkts", 9),
    ("tx_errs", 10),
    ("tx_drops", 11),
];

/// The sixteen numeric columns of one /proc/net/dev line.
pub type DevColumns = [u64; 16];

/// Raw rtnetlink, just enough for an `RTM_GETLINK` dump.
pub mod rtnl {
    use super::DevColumns;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    const NLMSG_HDRLEN: usize = 16;
    const IFINFOMSG_LEN: usize = 16;
    const NLMSG_NOOP: u16 = 1;
    const NLMSG_ERROR: u16 = 2;
    const NLMSG_DONE: u16 = 3;
    const RTM_NEWLINK: u16 = 16;
    const RTM_GETLINK: u16 = 18;
    const NLM_F_REQUEST: u16 = 0x1;
    const NLM_F_DUMP_INTR: u16 = 0x10;
    const NLM_F_DUMP: u16 = 0x300;
    const NLA_TYPE_MASK: u16 = 0x3fff;
    const IFLA_IFNAME: u16 = 3;
    const IFLA_STATS64: u16 = 23;
    /// Fields of the original `struct rtnl_link_stats64` (up to tx_compressed).
    const STATS64_MIN_FIELDS: usize = 23;

    fn align4(n: usize) -> usize {
        (n + 3) & !3
    }

    fn u16_at(b: &[u8], off: usize) -> u16 {
        u16::from_ne_bytes([b[off], b[off + 1]])
    }

    fn u32_at(b: &[u8], off: usize) -> u32 {
        u32::from_ne_bytes(b[off..off + 4].try_into().unwrap())
    }

    /// `struct rtnl_link_stats64` field indices.
    mod f {
        pub const RX_PACKETS: usize = 0;
        pub const TX_PACKETS: usize = 1;
        pub const RX_BYTES: usize = 2;
        pub const TX_BYTES: usize = 3;
        pub const RX_ERRORS: usize = 4;
        pub const TX_ERRORS: usize = 5;
        pub const RX_DROPPED: usize = 6;
        pub const TX_DROPPED: usize = 7;
        pub const MULTICAST: usize = 8;
        pub const COLLISIONS: usize = 9;
        pub const RX_LENGTH_ERRORS: usize = 10;
        pub const RX_OVER_ERRORS: usize = 11;
        pub const RX_CRC_ERRORS: usize = 12;
        pub const RX_FRAME_ERRORS: usize = 13;
        pub const RX_FIFO_ERRORS: usize = 14;
        pub const RX_MISSED_ERRORS: usize = 15;
        pub const TX_ABORTED_ERRORS: usize = 16;
        pub const TX_CARRIER_ERRORS: usize = 17;
        pub const TX_FIFO_ERRORS: usize = 18;
        pub const TX_HEARTBEAT_ERRORS: usize = 19;
        pub const TX_WINDOW_ERRORS: usize = 20;
        pub const RX_COMPRESSED: usize = 21;
        pub const TX_COMPRESSED: usize = 22;
    }

    /// The /proc/net/dev columns the kernel prints for these stats
    /// (net/core/net-procfs.c `dev_seq_printf_stats`; sums wrap as u64).
    pub fn proc_columns(s: &[u64]) -> DevColumns {
        let sum = |ix: &[usize]| ix.iter().fold(0u64, |a, &i| a.wrapping_add(s[i]));
        [
            s[f::RX_BYTES],
            s[f::RX_PACKETS],
            s[f::RX_ERRORS],
            sum(&[f::RX_DROPPED, f::RX_MISSED_ERRORS]),
            s[f::RX_FIFO_ERRORS],
            sum(&[f::RX_LENGTH_ERRORS, f::RX_OVER_ERRORS, f::RX_CRC_ERRORS, f::RX_FRAME_ERRORS]),
            s[f::RX_COMPRESSED],
            s[f::MULTICAST],
            s[f::TX_BYTES],
            s[f::TX_PACKETS],
            s[f::TX_ERRORS],
            s[f::TX_DROPPED],
            s[f::TX_FIFO_ERRORS],
            s[f::COLLISIONS],
            sum(&[f::TX_CARRIER_ERRORS, f::TX_ABORTED_ERRORS, f::TX_WINDOW_ERRORS, f::TX_HEARTBEAT_ERRORS]),
            s[f::TX_COMPRESSED],
        ]
    }

    /// One `RTM_NEWLINK` message of a dump.
    #[derive(Debug, Clone, PartialEq)]
    pub struct Link {
        pub index: i32,
        pub name: String,
        /// `IFLA_STATS64` as u64s; None if the kernel left it out.
        pub stats64: Option<Vec<u64>>,
    }

    /// What a run of netlink messages held.
    #[derive(Debug, Default, PartialEq)]
    pub struct Parsed {
        pub links: Vec<Link>,
        /// NLMSG_DONE was seen.
        pub done: bool,
        /// Some message carried NLM_F_DUMP_INTR (the dump raced a change).
        pub interrupted: bool,
    }

    fn bad(msg: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, format!("rtnetlink: {msg}"))
    }

    /// Parse the messages in `buf` (one or more whole datagrams) answering
    /// sequence number `seq`. Messages for other sequence numbers are skipped.
    pub fn parse(buf: &[u8], seq: u32, out: &mut Parsed) -> io::Result<()> {
        let mut off = 0;
        while off + NLMSG_HDRLEN <= buf.len() {
            let len = u32_at(buf, off) as usize;
            let ty = u16_at(buf, off + 4);
            let flags = u16_at(buf, off + 6);
            let mseq = u32_at(buf, off + 8);
            if len < NLMSG_HDRLEN || off + len > buf.len() {
                return Err(bad("truncated message"));
            }
            let msg = &buf[off..off + len];
            off += align4(len);
            if mseq != seq {
                continue;
            }
            if flags & NLM_F_DUMP_INTR != 0 {
                out.interrupted = true;
            }
            match ty {
                NLMSG_NOOP => {}
                NLMSG_DONE => {
                    out.done = true;
                    return Ok(());
                }
                NLMSG_ERROR => {
                    if msg.len() < NLMSG_HDRLEN + 4 {
                        return Err(bad("short NLMSG_ERROR"));
                    }
                    let errno = -(u32_at(msg, NLMSG_HDRLEN) as i32);
                    if errno != 0 {
                        return Err(io::Error::from_raw_os_error(errno));
                    }
                }
                RTM_NEWLINK => out.links.push(parse_link(msg)?),
                _ => {}
            }
        }
        Ok(())
    }

    fn parse_link(msg: &[u8]) -> io::Result<Link> {
        let body = align4(NLMSG_HDRLEN);
        if msg.len() < body + IFINFOMSG_LEN {
            return Err(bad("short ifinfomsg"));
        }
        let index = u32_at(msg, body + 4) as i32;
        let mut name = None;
        let mut stats64 = None;
        let mut off = body + align4(IFINFOMSG_LEN);
        while off + 4 <= msg.len() {
            let alen = u16_at(msg, off) as usize;
            let aty = u16_at(msg, off + 2) & NLA_TYPE_MASK;
            if alen < 4 || off + alen > msg.len() {
                return Err(bad("bad attribute length"));
            }
            let data = &msg[off + 4..off + alen];
            match aty {
                IFLA_IFNAME => {
                    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
                    name = Some(String::from_utf8_lossy(&data[..end]).into_owned());
                }
                IFLA_STATS64 if data.len() >= STATS64_MIN_FIELDS * 8 => {
                    stats64 = Some(data.chunks_exact(8).map(|c| u64::from_ne_bytes(c.try_into().unwrap())).collect());
                }
                _ => {}
            }
            off += align4(alen);
        }
        let name = name.ok_or_else(|| bad("link without IFLA_IFNAME"))?;
        Ok(Link { index, name, stats64 })
    }

    /// The `RTM_GETLINK` dump request.
    pub fn request(seq: u32) -> [u8; NLMSG_HDRLEN + IFINFOMSG_LEN] {
        let mut b = [0u8; NLMSG_HDRLEN + IFINFOMSG_LEN];
        b[0..4].copy_from_slice(&((NLMSG_HDRLEN + IFINFOMSG_LEN) as u32).to_ne_bytes());
        b[4..6].copy_from_slice(&RTM_GETLINK.to_ne_bytes());
        b[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        b[8..12].copy_from_slice(&seq.to_ne_bytes());
        // nlmsg_pid 0, ifinfomsg all zero: AF_UNSPEC, every interface.
        b
    }

    fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
        if r < 0 { Err(io::Error::last_os_error()) } else { Ok(r) }
    }

    fn cvt_size(r: libc::ssize_t) -> io::Result<usize> {
        if r < 0 { Err(io::Error::last_os_error()) } else { Ok(r as usize) }
    }

    /// Run one dump and return every reply datagram, concatenated, plus the
    /// sequence number used.
    pub fn dump_raw() -> io::Result<(Vec<u8>, u32)> {
        // SAFETY: plain socket(2); the fd is owned immediately.
        let fd = unsafe {
            OwnedFd::from_raw_fd(cvt(libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            ))?)
        };
        let tv = libc::timeval { tv_sec: 2, tv_usec: 0 };
        // SAFETY: tv outlives the call and the length matches.
        cvt(unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const tv).cast(),
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        })?;
        // SAFETY: an all-zero sockaddr_nl is valid; then the kernel's address.
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let seq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() | 1)
            .unwrap_or(1);
        let req = request(seq);
        // SAFETY: req and kernel are valid for the lengths given.
        let sent = cvt_size(unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                req.as_ptr().cast(),
                req.len(),
                0,
                (&raw const kernel).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        })?;
        if sent != req.len() {
            return Err(bad("short send"));
        }
        let mut all = Vec::new();
        let mut buf = vec![0u8; 32768];
        loop {
            // Peek with MSG_TRUNC for the datagram's real size, then read it.
            // SAFETY: buf is valid for buf.len() bytes.
            let need = cvt_size(unsafe {
                libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), libc::MSG_PEEK | libc::MSG_TRUNC)
            })?;
            if need > buf.len() {
                buf.resize(need, 0);
            }
            // SAFETY: as above.
            let n = cvt_size(unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) })?;
            let dgram = &buf[..n];
            all.extend_from_slice(dgram);
            let mut p = Parsed::default();
            parse(dgram, seq, &mut p)?;
            if p.done {
                return Ok((all, seq));
            }
        }
    }

    /// Every interface's name and /proc/net/dev columns, in dump (ifindex) order.
    pub fn link_columns() -> io::Result<Vec<(String, DevColumns)>> {
        for _ in 0..3 {
            let (raw, seq) = dump_raw()?;
            let mut p = Parsed::default();
            parse(&raw, seq, &mut p)?;
            if p.interrupted {
                continue;
            }
            return Ok(columns_of(&p.links));
        }
        Err(bad("dump interrupted three times"))
    }

    /// Links with stats, as (name, columns). A link without IFLA_STATS64 is
    /// left out (the kernel only omits it when asked to).
    pub fn columns_of(links: &[Link]) -> Vec<(String, DevColumns)> {
        links.iter().filter_map(|l| Some((l.name.clone(), proc_columns(l.stats64.as_ref()?)))).collect()
    }
}

#[derive(Default)]
struct Snapshot {
    time: f64,
    data: HashMap<String, DevColumns>,
}

pub struct MultiInterface {
    names: Vec<String>,
    /// metric name -> (/proc/net/dev column, interface key `get_delta` uses).
    lookup: HashMap<String, (usize, String)>,
    curr: Snapshot,
    last: Snapshot,
    /// The latest refresh failed; Python's callbacks raise until one succeeds.
    failed: bool,
}

/// Python `re.match(pattern, name)`, i.e. a match anchored at the start only.
fn compile_excludes(excluded: &str) -> Result<Vec<regex::Regex>> {
    excluded
        .split(' ')
        .map(|p| regex::Regex::new(&format!("^(?:{p})")).with_context(|| format!("excluded_interfaces pattern {p:?}")))
        .collect()
}

/// `get_interfaces`, given the interface names in /proc/net/dev order.
fn select_interfaces(watch: &str, excluded: &str, present: &[String]) -> Result<Vec<String>> {
    if !watch.is_empty() {
        return Ok(watch.split(' ').map(String::from).collect());
    }
    if excluded.is_empty() {
        // `excluded_if_list` is never bound: UnboundLocalError in metric_init.
        bail!("multi_interface: interfaces and excluded_interfaces are both empty");
    }
    let ex = compile_excludes(excluded)?;
    Ok(present.iter().filter(|d| !ex.iter().any(|r| r.is_match(d))).cloned().collect())
}

impl MultiInterface {
    /// `metric_init` with the module's `interfaces` and `excluded_interfaces`
    /// params, both required as in Python (`send_aggregate_bytes_packets` is
    /// accepted and ignored).
    pub fn from_params(p: &toml::Table) -> Result<Self> {
        let s = |k: &str| -> Result<String> {
            match p.get(k) {
                Some(toml::Value::String(s)) => Ok(s.clone()),
                Some(v) => bail!("multi_interface: param {k} must be a string, got {v}"),
                None => bail!("multi_interface: param {k} is required"),
            }
        };
        Self::new(&s("interfaces")?, &s("excluded_interfaces")?)
    }

    pub fn new(interfaces: &str, excluded_interfaces: &str) -> Result<Self> {
        let present = if interfaces.is_empty() {
            rtnl::link_columns().context("rtnetlink link dump")?.into_iter().map(|(n, _)| n).collect()
        } else {
            Vec::new()
        };
        Ok(Self::with_interfaces(select_interfaces(interfaces, excluded_interfaces, &present)?))
    }

    fn with_interfaces(interfaces: Vec<String>) -> Self {
        let mut names = Vec::new();
        let mut lookup = HashMap::new();
        for dev in &interfaces {
            for (stem, col) in STATS_TAB {
                let name = format!("{stem}_{dev}");
                // get_delta: parts = name.split("_"); iface = parts[2]
                let iface = name.split('_').nth(2).unwrap_or("").to_string();
                lookup.insert(name.clone(), (col, iface));
                names.push(name);
            }
        }
        MultiInterface { names, lookup, curr: Snapshot::default(), last: Snapshot::default(), failed: false }
    }

    fn refresh(&mut self, now: f64, links: Vec<(String, DevColumns)>) {
        // A dict built line by line: a repeated name keeps the last line.
        let data = links.into_iter().collect();
        self.last = std::mem::replace(&mut self.curr, Snapshot { time: now, data });
    }

    fn sample_with(&mut self, now: f64, read: impl FnOnce() -> std::io::Result<Vec<(String, DevColumns)>>) {
        if now - self.curr.time > METRICS_CACHE_MAX {
            match read() {
                Ok(links) => {
                    self.refresh(now, links);
                    self.failed = false;
                }
                Err(e) => {
                    log::warn!("multi_interface: rtnetlink: {e}");
                    self.failed = true;
                }
            }
        }
    }
}

impl Source for MultiInterface {
    fn name(&self) -> &'static str {
        "multi_interface"
    }

    fn names(&self) -> Vec<String> {
        self.names.clone()
    }

    fn sample(&mut self, now: f64) {
        self.sample_with(now, rtnl::link_columns);
    }

    fn value(&self, name: &str) -> Option<Reading> {
        if self.failed {
            return None;
        }
        let (col, iface) = self.lookup.get(name)?;
        let (Some(c), Some(l)) = (self.curr.data.get(iface), self.last.data.get(iface)) else {
            return Some(Reading::Num(0.0)); // KeyError
        };
        let dt = self.curr.time - self.last.time;
        if dt == 0.0 {
            return None; // ZeroDivisionError is not caught
        }
        let delta = (c[*col] as f64 - l[*col] as f64) / dt;
        Some(Reading::Num(if delta < 0.0 { 0.0 } else { delta }))
    }
}

/// Parse /proc/net/dev text the way the Python module does, into the same
/// shape `rtnl::link_columns` returns (for parity checks).
#[cfg(test)]
fn parse_proc_net_dev(text: &str) -> Vec<(String, DevColumns)> {
    let mut out = Vec::new();
    for line in text.split_inclusive('\n') {
        let Some((dev, rest)) = line.split_once(':') else { continue };
        let fields = super::netstats::py_split_ws(rest.trim_start());
        let mut cols = [0u64; 16];
        for (c, f) in cols.iter_mut().zip(fields.iter()) {
            *c = f.parse().unwrap_or(0);
        }
        out.push((dev.trim_start().to_string(), cols));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete `RTM_GETLINK` dump reply from a Linode VM (kernel 7.1.9, MAC replaced),
    /// captured by `capture_netlink_fixture`, with sequence number `FIXTURE_SEQ`.
    const FIXTURE: &[u8] = include_bytes!("../../fixtures/netlink/rtm_getlink_dump.bin");
    const FIXTURE_SEQ: u32 = include!("../../fixtures/netlink/rtm_getlink_dump.seq");
    /// /proc/net/dev read immediately before the capture.
    const FIXTURE_PROC: &str = include_str!("../../fixtures/netlink/proc_net_dev.txt");

    const SPEC_IFACES: [&str; 12] = [
        "dummy0", "erspan0", "eth0", "gre0", "gretap0", "ip6_vti0", "ip6gre0", "ip6tnl0", "ip_vti0", "sit0", "teql0",
        "tunl0",
    ];

    fn num(s: &MultiInterface, n: &str) -> f64 {
        match s.value(n) {
            Some(Reading::Num(v)) => v,
            other => panic!("{n}: {other:?}"),
        }
    }

    fn fixture_links() -> Vec<rtnl::Link> {
        let mut p = rtnl::Parsed::default();
        rtnl::parse(FIXTURE, FIXTURE_SEQ, &mut p).unwrap();
        assert!(p.done && !p.interrupted);
        p.links
    }

    #[test]
    fn parses_captured_dump() {
        let links = fixture_links();
        let names: Vec<&str> = links.iter().map(|l| l.name.as_str()).collect();
        let proc = parse_proc_net_dev(FIXTURE_PROC);
        // Same interfaces, same order as /proc/net/dev.
        assert_eq!(names, proc.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>());
        assert_eq!(links[0].index, 1);
        assert!(links.iter().all(|l| l.stats64.as_ref().is_some_and(|s| s.len() >= 23)));
        let cols = rtnl::columns_of(&links);
        for ((name, nl), (_, pr)) in cols.iter().zip(&proc) {
            if name == "eth0" || name == "lo" {
                // Busy between the two reads: netlink is the later reading.
                for i in 0..16 {
                    assert!(nl[i] >= pr[i], "{name} col {i}");
                }
                assert!(nl[0] - pr[0] < 50_000_000, "{name}");
            } else {
                assert_eq!(nl, pr, "{name}");
            }
        }
    }

    #[test]
    fn proc_columns_arithmetic() {
        let s: Vec<u64> = (1..=25).collect();
        let c = rtnl::proc_columns(&s);
        // bytes packets errs drop(dropped+missed) fifo frame(len+over+crc+frame) compressed multicast
        assert_eq!(&c[..8], &[3, 1, 5, 7 + 16, 15, 11 + 12 + 13 + 14, 22, 9]);
        // bytes packets errs drop fifo colls carrier(carrier+aborted+window+heartbeat) compressed
        assert_eq!(&c[8..], &[4, 2, 6, 8, 19, 10, 18 + 17 + 21 + 20, 23]);
        let mut w = vec![0u64; 23];
        w[6] = u64::MAX;
        w[15] = 2;
        assert_eq!(rtnl::proc_columns(&w)[3], 1);
    }

    #[test]
    fn parse_rejects_errors_and_skips_other_seq() {
        let mut err = vec![0u8; 36];
        err[0..4].copy_from_slice(&36u32.to_ne_bytes());
        err[4..6].copy_from_slice(&2u16.to_ne_bytes());
        err[8..12].copy_from_slice(&7u32.to_ne_bytes());
        err[16..20].copy_from_slice(&(-(libc::EPERM)).to_ne_bytes());
        let mut p = rtnl::Parsed::default();
        assert_eq!(rtnl::parse(&err, 7, &mut p).unwrap_err().raw_os_error(), Some(libc::EPERM));
        let mut p = rtnl::Parsed::default();
        rtnl::parse(&err, 8, &mut p).unwrap();
        assert_eq!(p, rtnl::Parsed::default());
        rtnl::parse(FIXTURE, FIXTURE_SEQ + 1, &mut p).unwrap();
        assert!(p.links.is_empty() && !p.done);
        let mut p = rtnl::Parsed::default();
        assert!(rtnl::parse(&FIXTURE[..FIXTURE.len() - 3], FIXTURE_SEQ, &mut p).is_err());
    }

    #[test]
    fn selection_matches_pyconf() {
        let present: Vec<String> = fixture_links().into_iter().map(|l| l.name).collect();
        let sel = select_interfaces("", "lo vnet[0-9]+", &present).unwrap();
        let mut sorted = sel.clone();
        sorted.sort();
        assert_eq!(sorted, SPEC_IFACES);
        // re.match anchors at the start only; empty pattern matches all.
        let p: Vec<String> = ["lo", "loop1", "vnet3", "xvnet3", "eth0"].map(String::from).into();
        assert_eq!(select_interfaces("", "lo vnet[0-9]+", &p).unwrap(), ["xvnet3", "eth0"]);
        assert!(select_interfaces("", "lo  eth", &p).unwrap().is_empty());
        assert_eq!(select_interfaces("eth0  x", "", &p).unwrap(), ["eth0", "", "x"]);
        assert!(select_interfaces("", "", &p).is_err());
    }

    #[test]
    fn params_are_required_strings() {
        let t: toml::Table = toml::from_str("interfaces = \"eth0 ip_vti0\"\nexcluded_interfaces = \"\"").unwrap();
        let m = MultiInterface::from_params(&t).unwrap();
        assert_eq!(m.names().len(), 16);
        assert_eq!(m.lookup["tx_drops_ip_vti0"], (11, "ip".to_string()));
        let t: toml::Table = toml::from_str("interfaces = \"eth0\"").unwrap();
        assert!(MultiInterface::from_params(&t).is_err());
        let t: toml::Table = toml::from_str("interfaces = \"eth0\"\nexcluded_interfaces = false").unwrap();
        assert!(MultiInterface::from_params(&t).is_err());
    }

    #[test]
    fn names_match_spec() {
        let present: Vec<String> = fixture_links().into_iter().map(|l| l.name).collect();
        let m = MultiInterface::with_interfaces(select_interfaces("", "lo vnet[0-9]+", &present).unwrap());
        let mut ours = m.names();
        ours.sort();
        assert_eq!(ours.len(), 96);
        for n in &ours {
            assert!(super::super::spec::lookup(n).is_some(), "{n}: no metadata");
        }
        // On the capture host, the names must be exactly the ones gmond sent.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/spec-captured.toml");
        if let Ok(text) = std::fs::read_to_string(path) {
            let mut spec: Vec<String> = text
                .lines()
                .filter_map(|l| l.strip_prefix("name = \"")?.strip_suffix('"').map(str::to_string))
                .filter(|n| n.starts_with("rx_") || n.starts_with("tx_"))
                .collect();
            spec.sort();
            assert_eq!(ours, spec);
        }
    }

    fn cols(rx_bytes: u64, tx_pkts: u64) -> DevColumns {
        let mut c = [0u64; 16];
        c[0] = rx_bytes;
        c[9] = tx_pkts;
        c
    }

    #[test]
    fn rates_cache_wrap_and_quirks() {
        let mut m = MultiInterface::with_interfaces(vec!["eth0".into(), "ip_vti0".into(), "gone0".into()]);
        let t0 = vec![("eth0".to_string(), cols(1000, 50)), ("ip_vti0".into(), cols(10, 1)), ("gone0".into(), cols(5, 5))];
        m.sample_with(100.0, || Ok(t0));
        for n in m.names() {
            assert_eq!(num(&m, &n), 0.0, "first sample {n}");
        }
        // Inside the cache window: no read.
        m.sample_with(105.0, || panic!("cache window"));
        let t1 = vec![("eth0".to_string(), cols(16000, 20)), ("ip_vti0".into(), cols(1000, 100))];
        m.sample_with(115.0, || Ok(t1));
        assert_eq!(num(&m, "rx_bytes_eth0"), 1000.0);
        assert_eq!(num(&m, "tx_pkts_eth0"), 0.0); // went backwards
        assert_eq!(num(&m, "rx_pkts_eth0"), 0.0);
        assert_eq!(num(&m, "rx_bytes_ip_vti0"), 0.0); // looked up as "ip"
        assert_eq!(num(&m, "rx_bytes_gone0"), 0.0); // vanished
        assert_eq!(m.value("rx_bytes_nosuch"), None);
        // A failed refresh makes every callback fail until one succeeds.
        m.sample_with(130.0, || Err(std::io::Error::other("x")));
        assert_eq!(m.value("rx_bytes_eth0"), None);
        m.sample_with(131.0, || Ok(vec![("eth0".to_string(), cols(16000 + 3200, 20))]));
        assert_eq!(num(&m, "rx_bytes_eth0"), 200.0);
    }

    /// Refresh the fixture: `RGMOND_CAPTURE=1 cargo test capture_netlink_fixture -- --ignored`.
    #[test]
    #[ignore]
    fn capture_netlink_fixture() {
        if std::env::var_os("RGMOND_CAPTURE").is_none() {
            eprintln!("set RGMOND_CAPTURE=1 to rewrite fixtures/netlink");
            return;
        }
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/netlink");
        std::fs::create_dir_all(dir).unwrap();
        let proc = std::fs::read_to_string("/proc/net/dev").unwrap();
        let (raw, seq) = rtnl::dump_raw().unwrap();
        std::fs::write(format!("{dir}/proc_net_dev.txt"), proc).unwrap();
        std::fs::write(format!("{dir}/rtm_getlink_dump.bin"), raw).unwrap();
        std::fs::write(format!("{dir}/rtm_getlink_dump.seq"), format!("{seq}\n")).unwrap();
    }

    /// Netlink counters equal /proc/net/dev's for every interface, read back to
    /// back: each netlink value lies between a /proc read before and after it.
    #[test]
    #[ignore]
    fn live_netlink_matches_proc_net_dev() {
        let before = parse_proc_net_dev(&std::fs::read_to_string("/proc/net/dev").unwrap());
        let nl = rtnl::link_columns().unwrap();
        let after = parse_proc_net_dev(&std::fs::read_to_string("/proc/net/dev").unwrap());
        let names = |v: &[(String, DevColumns)]| v.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>();
        assert_eq!(names(&nl), names(&before));
        assert_eq!(names(&nl), names(&after));
        for ((name, n), ((_, b), (_, a))) in nl.iter().zip(before.iter().zip(&after)) {
            for i in 0..16 {
                assert!(b[i] <= n[i] && n[i] <= a[i], "{name} column {i}: proc {} / netlink {} / proc {}", b[i], n[i], a[i]);
            }
            if b == a {
                assert_eq!(n, b, "{name}: idle interface must match exactly");
            }
        }
        eprintln!("{} interfaces: netlink counters within /proc/net/dev brackets", nl.len());
    }

    #[test]
    #[ignore]
    fn live_parity_with_python() {
        let pyconf = "/etc/ganglia/conf.d/multi_interface.pyconf";
        let params = super::super::netstats::parity::pyconf_params(pyconf);
        let mut ours = MultiInterface::new(&params["interfaces"], &params["excluded_interfaces"]).unwrap();
        // "False" is a truthy string, so Python also declares the aggregates.
        let aggregates = ["bytes_in", "bytes_out", "pkts_in", "pkts_out"];
        super::super::netstats::parity::run("multi_interface", pyconf, &mut ours, &aggregates, |_| (0.03, 2.0));
    }
}
