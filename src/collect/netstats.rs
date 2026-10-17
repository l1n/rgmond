//! Port of Ganglia's `network/netstats.py`: per-second deltas of every counter
//! in /proc/net/netstat and /proc/net/snmp, plus three percentages.
//!
//! Metric names are `<group>_<counter>`, both lowercased (e.g. `tcp_insegs`,
//! `tcpext_listendrops`). Semantics follow the Python module exactly:
//!
//! * Counter positions are learned once, at construction, from the header lines.
//!   Later samples take values by those positions, so a header that changes
//!   after start (IcmpMsg grows a column) shifts values the way Python does,
//!   and a group that did not exist at start makes every sample fail (Python's
//!   `stats_pos[metric_group]` KeyError escapes `get_metrics`).
//! * Snapshots are cached for `METRICS_CACHE_MAX` (5 s); a refresh moves the
//!   current snapshot to "last". Deltas divide by the two snapshots' times.
//! * A missing counter in either snapshot (always true on the first sample)
//!   gives 0.0; a negative delta or percentage gives 0.
//! * Percentages are `100 * (curr x - last x) / (curr outsegs + curr insegs -
//!   last insegs - last outsegs)`, not divided by time, 0.0 on a missing
//!   counter or a zero denominator. This kernel has no TcpExt `TCPLoss`, so
//!   `tcpext_tcploss_percentage` is always 0.0, as it is under Python.
#![cfg_attr(not(test), allow(dead_code))] // constructed once the scheduler wires sources in

use super::{Reading, Source};
use anyhow::{Context, Result};
use std::collections::HashMap;

const STATS_FILES: [&str; 2] = ["/proc/net/netstat", "/proc/net/snmp"];
const METRICS_CACHE_MAX: f64 = 5.0;

const PCT_TCPLOSS: &str = "tcpext_tcploss_percentage";
const PCT_ATTEMPTFAILS: &str = "tcp_attemptfails_percentage";
const PCT_RETRANS: &str = "tcp_retrans_percentage";

/// group -> counter -> raw text value, as Python's `METRICS['data']`.
type Data = HashMap<String, HashMap<String, String>>;

#[derive(Default)]
struct Snapshot {
    time: f64,
    data: Data,
}

/// `re.split(r"\s+", s)` for Python 3 `str`: runs of whitespace separate
/// fields, and leading/trailing whitespace produces empty first/last fields.
pub(crate) fn py_split_ws(s: &str) -> Vec<&str> {
    // str.isspace(): Unicode White_Space plus the ASCII separators 0x1c-0x1f.
    let ws = |c: char| c.is_whitespace() || ('\x1c'..='\x1f').contains(&c);
    let mut out = Vec::new();
    let mut start = 0;
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if ws(c) {
            out.push(&s[start..i]);
            let mut end = i + c.len_utf8();
            while let Some(&(j, d)) = chars.peek() {
                if !ws(d) {
                    break;
                }
                end = j + d.len_utf8();
                chars.next();
            }
            start = end;
        }
    }
    out.push(&s[start..]);
    out
}

/// `re.match("(.*): [0-9]", line)`: somewhere on the line a ": " is followed
/// by an ASCII digit (`.` cannot cross a newline).
fn is_value_line(line: &str) -> bool {
    let first_line = line.split('\n').next().unwrap_or("");
    first_line.as_bytes().windows(3).any(|w| w[0] == b':' && w[1] == b' ' && w[2].is_ascii_digit())
}

/// Python iterates a file by lines that keep their trailing "\n".
fn py_lines(text: &str) -> impl Iterator<Item = &str> {
    text.split_inclusive('\n')
}

/// Counter positions per group, in Python dict insertion order.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct StatsPos {
    groups: Vec<(String, Vec<(usize, String)>)>,
}

impl StatsPos {
    fn get(&self, group: &str) -> Option<&Vec<(usize, String)>> {
        self.groups.iter().find(|(g, _)| g == group).map(|(_, p)| p)
    }

    /// The header-line pass of `metric_init`, applied to one file's text.
    pub(crate) fn learn(&mut self, text: &str) {
        for line in py_lines(text) {
            if is_value_line(line) {
                continue;
            }
            let mapping = py_split_ws(line);
            let group = mapping[0].replace(':', "").to_lowercase();
            let mut pos = Vec::new();
            for (count, metric) in mapping.iter().enumerate() {
                if count > 0 && !metric.is_empty() {
                    pos.push((count, metric.to_lowercase()));
                }
            }
            // `stats_pos[group] = dict()` keeps a repeated group's original slot.
            match self.groups.iter_mut().find(|(g, _)| *g == group) {
                Some(slot) => slot.1 = pos,
                None => self.groups.push((group, pos)),
            }
        }
    }

    /// Descriptor names in `metric_init` order.
    pub(crate) fn names(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (group, pos) in &self.groups {
            // A dict keyed by position: duplicate positions cannot occur.
            for (_, metric) in pos {
                out.push(format!("{group}_{metric}"));
            }
        }
        out.extend([PCT_TCPLOSS, PCT_ATTEMPTFAILS, PCT_RETRANS].map(String::from));
        out
    }

    /// The value-line pass of `get_metrics`, applied to one file's text.
    /// Err when a value line names a group not seen at start (Python KeyError).
    pub(crate) fn parse_values(&self, text: &str, into: &mut Data) -> Result<()> {
        for line in py_lines(text) {
            if !is_value_line(line) {
                continue;
            }
            let fields = py_split_ws(line);
            let group = fields[0].replace(':', "").to_lowercase();
            let mut m = HashMap::new();
            let pos = self.get(&group);
            for (count, value) in fields.iter().enumerate() {
                if count > 0 {
                    let pos = pos.with_context(|| format!("netstats: group {group:?} not present at start"))?;
                    if let Some((_, name)) = pos.iter().find(|(c, _)| *c == count) {
                        m.insert(name.clone(), (*value).to_string());
                    }
                }
            }
            into.insert(group, m);
        }
        Ok(())
    }
}

/// Why a Python expression would not produce a number.
#[derive(Debug, PartialEq)]
enum PyErr {
    /// KeyError (caught by every callback).
    Key,
    /// ValueError from `float()` (only `get_tcpattemptfail_percentage` catches it).
    Value,
}

/// `float(snapshot['data'][group][key])`.
fn fetch(s: &Snapshot, group: &str, key: &str) -> Result<f64, PyErr> {
    let v = s.data.get(group).and_then(|g| g.get(key)).ok_or(PyErr::Key)?;
    py_float(v).ok_or(PyErr::Value)
}

/// Python `float(str)` for the integer text /proc prints.
fn py_float(s: &str) -> Option<f64> {
    let t = s.trim().replace('_', "");
    t.parse::<f64>().ok()
}

pub struct Netstats {
    pos: StatsPos,
    names: Vec<String>,
    curr: Snapshot,
    last: Snapshot,
    /// The latest refresh attempt raised in Python, so every callback raises.
    failed: bool,
}

impl Netstats {
    /// `metric_init`: learn the counter layout from the live files.
    pub fn new() -> Result<Self> {
        let mut texts = Vec::new();
        for f in STATS_FILES {
            texts.push(std::fs::read_to_string(f).with_context(|| format!("reading {f}"))?);
        }
        Ok(Self::from_headers(&texts.iter().map(String::as_str).collect::<Vec<_>>()))
    }

    fn from_headers(texts: &[&str]) -> Self {
        let mut pos = StatsPos::default();
        for t in texts {
            pos.learn(t);
        }
        let names = pos.names();
        Netstats { pos, names, curr: Snapshot::default(), last: Snapshot::default(), failed: false }
    }

    /// One `get_metrics` refresh from already-read file contents.
    fn refresh(&mut self, now: f64, texts: &[&str]) -> Result<()> {
        let mut data = Data::new();
        for t in texts {
            self.pos.parse_values(t, &mut data)?;
        }
        self.last = std::mem::replace(&mut self.curr, Snapshot { time: now, data });
        Ok(())
    }

    fn sample_with(&mut self, now: f64, read: impl Fn(&str) -> std::io::Result<String>) {
        if now - self.curr.time > METRICS_CACHE_MAX {
            let mut texts = Vec::new();
            for f in STATS_FILES {
                match read(f) {
                    Ok(t) => texts.push(t),
                    Err(e) => {
                        log::warn!("netstats: {f}: {e}");
                        self.failed = true;
                        return;
                    }
                }
            }
            let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
            match self.refresh(now, &texts) {
                Ok(()) => self.failed = false,
                Err(e) => {
                    log::warn!("{e:#}");
                    self.failed = true;
                }
            }
        }
    }

    /// `get_delta`.
    fn delta(&self, name: &str) -> Option<f64> {
        let mut parts = name.split('_');
        let group = parts.next().unwrap_or("");
        let metric = parts.collect::<Vec<_>>().join("_");
        let r = (|| {
            let c = fetch(&self.curr, group, &metric)?;
            let l = fetch(&self.last, group, &metric)?;
            Ok::<f64, PyErr>((c - l) / (self.curr.time - self.last.time))
        })();
        match r {
            Ok(d) if d < 0.0 => Some(0.0),
            Ok(d) => Some(d),
            Err(PyErr::Key) => Some(0.0),
            Err(PyErr::Value) => None,
        }
    }

    /// The shared formula of the three percentage callbacks.
    fn pct(&self, group: &str, key: &str) -> Result<f64, PyErr> {
        let (c, l) = (&self.curr, &self.last);
        let num = 100.0 * (fetch(c, group, key)? - fetch(l, group, key)?);
        let denom = fetch(c, "tcp", "outsegs")? + fetch(c, "tcp", "insegs")?
            - fetch(l, "tcp", "insegs")?
            - fetch(l, "tcp", "outsegs")?;
        if denom == 0.0 {
            // ZeroDivisionError
            return Ok(0.0);
        }
        let p = num / denom;
        Ok(if p < 0.0 { 0.0 } else { p })
    }
}

impl Source for Netstats {
    fn name(&self) -> &'static str {
        "netstats"
    }

    fn names(&self) -> Vec<String> {
        self.names.clone()
    }

    fn sample(&mut self, now: f64) {
        self.sample_with(now, |f| std::fs::read_to_string(f));
    }

    fn value(&self, name: &str) -> Option<Reading> {
        if self.failed || !self.names.iter().any(|n| n == name) {
            return None;
        }
        let v = match name {
            // get_tcploss_percentage / get_retrans_percentage catch KeyError and
            // ZeroDivisionError only.
            PCT_TCPLOSS => match self.pct("tcpext", "tcploss") {
                Ok(p) => p,
                Err(PyErr::Key) => 0.0,
                Err(PyErr::Value) => return None,
            },
            PCT_RETRANS => match self.pct("tcp", "retranssegs") {
                Ok(p) => p,
                Err(PyErr::Key) => 0.0,
                Err(PyErr::Value) => return None,
            },
            // get_tcpattemptfail_percentage catches everything.
            PCT_ATTEMPTFAILS => self.pct("tcp", "attemptfails").unwrap_or(0.0),
            _ => self.delta(name)?,
        };
        Some(Reading::Num(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Captured from a Linode VM (kernel 7.1.9), 2026-10-17.
    const NETSTAT_A: &str = "TcpExt: SyncookiesSent SyncookiesRecv ListenOverflows ListenDrops TCPLossUndo\n\
TcpExt: 939 1917 4822 5191 3711\n\
IpExt: InNoRoutes InTruncatedPkts InOctets OutOctets\n\
IpExt: 165 0 1180261901429 659234499200\n";
    const SNMP_A: &str = "Ip: Forwarding DefaultTTL InReceives\n\
Ip: 1 64 391897077\n\
IcmpMsg: InType3 InType5\n\
IcmpMsg: 3965 103\n\
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors\n\
Tcp: 1 200 120000 -1 11270868 6112716 149052 991033 191 415154458 878240863 3491327 2193 4650878 0\n\
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors\n\
Udp: 16979551 304515 21135 17304448 21135 0 0 0 0\n";
    // 15 s later (hand-advanced counters).
    const NETSTAT_B: &str = "TcpExt: SyncookiesSent SyncookiesRecv ListenOverflows ListenDrops TCPLossUndo\n\
TcpExt: 939 1917 4822 5221 3712\n\
IpExt: InNoRoutes InTruncatedPkts InOctets OutOctets\n\
IpExt: 165 0 1180262901429 659235499200\n";
    const SNMP_B: &str = "Ip: Forwarding DefaultTTL InReceives\n\
Ip: 1 64 391898077\n\
IcmpMsg: InType3 InType5\n\
IcmpMsg: 3965 103\n\
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors\n\
Tcp: 1 200 120000 -1 11270968 6112716 149067 991033 185 415156458 878243863 3491352 2193 4650878 0\n\
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors\n\
Udp: 16979851 304515 21138 17304748 21135 0 0 0 0\n";

    fn num(s: &Netstats, n: &str) -> f64 {
        match s.value(n) {
            Some(Reading::Num(v)) => v,
            other => panic!("{n}: {other:?}"),
        }
    }

    #[test]
    fn split_matches_python_re_split() {
        assert_eq!(py_split_ws("Ip: 1 64\n"), vec!["Ip:", "1", "64", ""]);
        assert_eq!(py_split_ws("  a\t\tb"), vec!["", "a", "b"]);
        assert_eq!(py_split_ws("x"), vec!["x"]);
        assert!(is_value_line("Tcp: 1 200\n"));
        assert!(!is_value_line("Tcp: RtoAlgorithm RtoMin\n"));
        assert!(!is_value_line("Tcp: -1\n"));
    }

    #[test]
    fn names_follow_metric_init_order() {
        let s = Netstats::from_headers(&[NETSTAT_A, SNMP_A]);
        let names = s.names();
        assert_eq!(&names[..3], ["tcpext_syncookiessent", "tcpext_syncookiesrecv", "tcpext_listenoverflows"]);
        assert!(names.contains(&"icmpmsg_intype5".to_string()));
        assert_eq!(names.len(), 5 + 4 + 3 + 2 + 15 + 9 + 3);
        assert_eq!(&names[names.len() - 3..], [PCT_TCPLOSS, PCT_ATTEMPTFAILS, PCT_RETRANS]);
        for n in ["tcp_attemptfails", "tcp_insegs", "tcp_outsegs", "tcp_retrans_percentage", "tcpext_listendrops",
            "tcpext_tcploss_percentage", "udp_indatagrams", "udp_inerrors", "udp_outdatagrams"] {
            assert!(names.iter().any(|x| x == n), "{n}");
        }
    }

    #[test]
    fn first_sample_is_zero_then_deltas() {
        let mut s = Netstats::from_headers(&[NETSTAT_A, SNMP_A]);
        s.refresh(1000.0, &[NETSTAT_A, SNMP_A]).unwrap();
        for n in s.names() {
            assert_eq!(num(&s, &n), 0.0, "{n}");
        }
        s.refresh(1015.0, &[NETSTAT_B, SNMP_B]).unwrap();
        assert_eq!(num(&s, "tcp_insegs"), 2000.0 / 15.0);
        assert_eq!(num(&s, "tcp_outsegs"), 3000.0 / 15.0);
        assert_eq!(num(&s, "tcp_attemptfails"), 1.0);
        assert_eq!(num(&s, "tcpext_listendrops"), 2.0);
        assert_eq!(num(&s, "udp_indatagrams"), 20.0);
        assert_eq!(num(&s, "udp_inerrors"), 0.2);
        assert_eq!(num(&s, "udp_outdatagrams"), 20.0);
        // CurrEstab fell: negative -> 0
        assert_eq!(num(&s, "tcp_currestab"), 0.0);
        assert_eq!(num(&s, "tcp_maxconn"), 0.0);
        assert_eq!(num(&s, "tcp_retrans_percentage"), 100.0 * 25.0 / 5000.0);
        assert_eq!(num(&s, "tcp_attemptfails_percentage"), 100.0 * 15.0 / 5000.0);
        // No TCPLoss counter on this kernel: KeyError -> 0.0
        assert_eq!(num(&s, "tcpext_tcploss_percentage"), 0.0);
    }

    #[test]
    fn zero_denominator_and_cache_window() {
        let mut s = Netstats::from_headers(&[NETSTAT_A, SNMP_A]);
        let reads = std::cell::Cell::new(0);
        let read = |f: &str| -> std::io::Result<String> {
            reads.set(reads.get() + 1);
            Ok(if f.ends_with("snmp") { SNMP_A } else { NETSTAT_A }.to_string())
        };
        s.sample_with(100.0, read);
        s.sample_with(105.0, read); // 5.0 is not > METRICS_CACHE_MAX: cached
        assert_eq!(reads.get(), 2);
        s.sample_with(105.5, read);
        assert_eq!(reads.get(), 4);
        assert_eq!((s.last.time, s.curr.time), (100.0, 105.5));
        // Same snapshot twice (cache) -> denominator 0 -> 0.0
        s.refresh(106.0, &[NETSTAT_A, SNMP_A]).unwrap();
        s.refresh(121.0, &[NETSTAT_A, SNMP_A]).unwrap();
        assert_eq!(num(&s, "tcp_retrans_percentage"), 0.0);
        assert_eq!(num(&s, "tcp_attemptfails_percentage"), 0.0);
        assert_eq!(num(&s, "tcp_insegs"), 0.0);
    }

    #[test]
    #[ignore]
    fn live_parity_with_python() {
        let mut ours = Netstats::new().unwrap();
        // Rates: 5% or 0.5/s (3 events in the 6 s window); percentages: 10% or 0.05 points.
        let tol = |n: &str| if n.ends_with("_percentage") { (0.10, 0.05) } else { (0.05, 0.5) };
        super::parity::run("netstats", "/etc/ganglia/conf.d/netstats.pyconf", &mut ours, &[], tol);
    }

    #[test]
    fn positions_fixed_at_start_and_new_group_fails() {
        let mut s = Netstats::from_headers(&[NETSTAT_A, SNMP_A]);
        // IcmpMsg grew a column: values are read by start-time position.
        let grown = SNMP_A.replace("IcmpMsg: InType3 InType5\nIcmpMsg: 3965 103", "IcmpMsg: InType0 InType3 InType5\nIcmpMsg: 7 3965 103");
        s.refresh(10.0, &[NETSTAT_A, &grown]).unwrap();
        assert_eq!(s.curr.data["icmpmsg"]["intype3"], "7");
        assert_eq!(s.curr.data["icmpmsg"]["intype5"], "3965");
        // A group absent at start breaks every later refresh.
        let mut s = Netstats::from_headers(&[NETSTAT_A, SNMP_A]);
        let extra = format!("{SNMP_A}UdpLite: InDatagrams\nUdpLite: 0\n");
        assert!(s.refresh(10.0, &[NETSTAT_A, &extra]).is_err());
        s.sample_with(10.0, |f| Ok(if f.ends_with("snmp") { extra.clone() } else { NETSTAT_A.to_string() }));
        assert_eq!(s.value("tcp_insegs"), None);
    }
}

/// Live parity against the Python modules (shared with multi_interface's tests).
/// The Python sources are found via `$RGMOND_PY_MODULES` (default:
/// /usr/lib/ganglia/python_modules), driven by tools/parity/driver_net.py.
#[cfg(test)]
pub(crate) mod parity {
    use super::super::{Reading, Source};
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// RGMOND_PY_MODULES is a gmond python_modules tree: the source layout
    /// (network/, disk/, ...) or ganglia's flat install directory.
    fn module_dir(subdir: &str) -> String {
        let base = std::env::var("RGMOND_PY_MODULES").unwrap_or_else(|_| "/usr/lib/ganglia/python_modules".into());
        let nested = format!("{base}/{subdir}");
        if std::path::Path::new(&nested).is_dir() { nested } else { base }
    }

    type Values = HashMap<String, Option<f64>>;

    /// The `param NAME { value = ... }` pairs of a pyconf, as gmond passes them.
    pub fn pyconf_params(path: &str) -> HashMap<String, String> {
        let text = std::fs::read_to_string(path).unwrap();
        let re = regex::Regex::new(r#"(?m)^\s*param\s+(\S+)\s*\{\s*value\s*=\s*([^\n}]*?)\s*\}"#).unwrap();
        re.captures_iter(&text)
            .map(|c| (c[1].to_string(), c[2].trim_matches(|ch| ch == '"' || ch == '\'').to_string()))
            .collect()
    }

    fn now() -> f64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64()
    }

    fn read_block(r: &mut impl BufRead) -> Vec<String> {
        let mut out = Vec::new();
        loop {
            let mut l = String::new();
            assert!(r.read_line(&mut l).unwrap() > 0, "python driver exited");
            let l = l.trim_end_matches('\n');
            if l == "END" {
                return out;
            }
            out.push(l.to_string());
        }
    }

    fn ours(src: &dyn Source) -> Values {
        src.names()
            .into_iter()
            .map(|n| {
                let v = match src.value(&n) {
                    Some(Reading::Num(v)) => Some(v),
                    Some(Reading::Str(s)) => panic!("{n}: unexpected string {s:?}"),
                    None => None,
                };
                (n, v)
            })
            .collect()
    }

    /// Compare one round. `tol(name) = (relative, absolute)`. Returns
    /// (metrics compared, non-zero ones, worst relative difference).
    fn compare(round: &str, py: &Values, rs: &Values, exact: bool, tol: &dyn Fn(&str) -> (f64, f64)) -> (usize, usize, f64) {
        let (mut nonzero, mut worst) = (0, 0.0f64);
        let mut bad = Vec::new();
        for (n, r) in rs {
            let p = &py[n];
            let ok = match (p, r) {
                (Some(p), Some(r)) if p == r => true,
                (Some(p), Some(r)) if !exact => {
                    let (rel, abs) = tol(n);
                    let d = (p - r).abs();
                    let scale = p.abs().max(r.abs());
                    worst = worst.max(d / scale);
                    d <= abs.max(rel * scale)
                }
                (None, None) => true,
                _ => false,
            };
            if matches!((p, r), (Some(p), Some(r)) if *p != 0.0 || *r != 0.0) {
                nonzero += 1;
            }
            if !ok {
                bad.push(format!("{n}: python {p:?} rust {r:?}"));
            }
        }
        bad.sort();
        assert!(bad.is_empty(), "{round}: {} mismatches:\n{}", bad.len(), bad.join("\n"));
        (rs.len(), nonzero, worst)
    }

    /// Sample the Python module and `src` together over two cache windows and
    /// require the same names (Python may also declare `python_only`) and
    /// values: exact on the first sample and on cache hits, within `tol` on
    /// refreshed rates.
    pub fn run(module: &str, pyconf: &str, src: &mut dyn Source, python_only: &[&str], tol: impl Fn(&str) -> (f64, f64)) {
        let dir = module_dir("network");
        let driver = concat!(env!("CARGO_MANIFEST_DIR"), "/tools/parity/driver_net.py");
        let mut child = Command::new("python3")
            .args([driver, &dir, module, pyconf])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("python3");
        let mut stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());

        let mut py_names = read_block(&mut stdout);
        py_names.sort();
        let mut rs_names = src.names();
        rs_names.sort();
        let mut expect = rs_names.clone();
        expect.extend(python_only.iter().map(|s| s.to_string()));
        expect.sort();
        assert_eq!(py_names, expect, "{module}: metric name sets");
        let mut dedup = rs_names.clone();
        dedup.dedup();
        assert_eq!(dedup.len(), rs_names.len(), "duplicate names");

        let mut round = |src: &mut dyn Source| -> (Values, Values, f64) {
            writeln!(stdin, "sample").unwrap();
            stdin.flush().unwrap();
            let t = now();
            src.sample(t);
            let block = read_block(&mut stdout);
            let pt: f64 = block[0].strip_prefix("T ").unwrap().parse().unwrap();
            let mut py: Values = block[1..]
                .iter()
                .map(|l| {
                    let (n, v) = l.split_once('\t').unwrap();
                    (n.to_string(), if v == "None" { None } else { Some(v.parse().unwrap()) })
                })
                .collect();
            for n in python_only {
                py.remove(*n);
            }
            (py, ours(src), (t - pt).abs())
        };

        let (p1, r1, skew) = round(src);
        let s = compare("first sample", &p1, &r1, true, &tol);
        assert_eq!(s.1, 0, "first sample must be all zero");
        eprintln!("{module}: {} names match; first sample all 0.0 on both (skew {:.1} ms)", s.0, skew * 1e3);

        std::thread::sleep(Duration::from_secs_f64(6.0));
        let (p2, r2, skew) = round(src);
        let s = compare("second sample", &p2, &r2, false, &tol);
        eprintln!("{module}: 6 s window: {} compared, {} non-zero, worst rel diff {:.2e} (skew {:.1} ms)", s.0, s.1, s.2, skew * 1e3);

        std::thread::sleep(Duration::from_secs_f64(1.0));
        let (p3, r3, _) = round(src);
        assert_eq!(p3, p2, "python cache window");
        assert_eq!(r3, r2, "rust cache window");
        eprintln!("{module}: 1 s later both served from cache, unchanged");

        std::thread::sleep(Duration::from_secs_f64(5.5));
        let (p4, r4, skew) = round(src);
        let s = compare("third refresh", &p4, &r4, false, &tol);
        eprintln!("{module}: next window: {} compared, {} non-zero, worst rel diff {:.2e} (skew {:.1} ms)", s.0, s.1, s.2, skew * 1e3);

        writeln!(stdin, "quit").unwrap();
        drop(stdin);
        child.wait().unwrap();
    }
}
