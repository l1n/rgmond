//! `rgmond replay`: feed captured UDP traffic through the store and diff our
//! XML against the dumps C gmond served at the same moments (phase 1 gate).

use crate::proto::Msg;
use crate::store::{Store, USEC};
use crate::xml::{self, Cluster, XmlParams};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, HashMap};

/// One host or metric element: its attributes, plus EXTRA_ELEMENTs for metrics.
#[derive(Debug, Default, PartialEq)]
pub struct Elem {
    pub attrs: BTreeMap<String, String>,
    pub extra: Vec<(String, String)>,
}

/// A dump as (header lines, hosts keyed by NAME|IP, metrics keyed by host key + metric name).
#[derive(Debug, Default)]
pub struct Dump {
    pub cluster: BTreeMap<String, String>,
    pub hosts: BTreeMap<String, Elem>,
    pub metrics: BTreeMap<(String, String), Elem>,
}

fn attrs(line: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let mut rest = line;
    while let Some(eq) = rest.find("=\"") {
        let key = rest[..eq].rsplit([' ', '<']).next().unwrap_or("").to_string();
        let after = &rest[eq + 2..];
        let end = after.find('"').unwrap_or(after.len());
        m.insert(key, after[..end].to_string());
        rest = &after[(end + 1).min(after.len())..];
    }
    m
}

pub fn parse_dump(bytes: &[u8]) -> Dump {
    let text = crate::xdr::latin1_decode(bytes);
    let mut d = Dump::default();
    let mut host = String::new();
    let mut metric: Option<(String, String)> = None;
    for line in text.lines() {
        if line.starts_with("<CLUSTER ") {
            d.cluster = attrs(line);
        } else if line.starts_with("<HOST ") {
            let a = attrs(line);
            host = format!("{}|{}", a["NAME"], a["IP"]);
            d.hosts.insert(host.clone(), Elem { attrs: a, extra: vec![] });
        } else if line.starts_with("<METRIC ") {
            let a = attrs(line);
            let k = (host.clone(), a["NAME"].clone());
            d.metrics.insert(k.clone(), Elem { attrs: a, extra: vec![] });
            metric = Some(k);
        } else if line.starts_with("<EXTRA_ELEMENT ") {
            if let Some(k) = &metric {
                let a = attrs(line);
                d.metrics.get_mut(k).unwrap().extra.push((a["NAME"].clone(), a["VAL"].clone()));
            }
        }
    }
    d
}

/// Attributes that are wall-clock readings and legitimately differ by the
/// sub-second skew between our render time and gmond's.
const CLOCKS: &[&str] = &["TN", "REPORTED", "LOCALTIME"];

fn diff_elem(what: &str, a: &Elem, b: &Elem, out: &mut Vec<String>) {
    for (k, av) in &a.attrs {
        let bv = b.attrs.get(k);
        let same = match bv {
            Some(bv) if CLOCKS.contains(&k.as_str()) => match (av.parse::<i64>(), bv.parse::<i64>()) {
                (Ok(x), Ok(y)) => (x - y).abs() <= 1,
                _ => av == bv,
            },
            Some(bv) => av == bv,
            None => false,
        };
        if !same {
            out.push(format!("{what}: {k} gmond={av:?} ours={bv:?}"));
        }
    }
    for k in b.attrs.keys() {
        if !a.attrs.contains_key(k) {
            out.push(format!("{what}: extra attribute {k}"));
        }
    }
    if a.extra != b.extra {
        out.push(format!("{what}: EXTRA_DATA gmond={:?} ours={:?}", a.extra, b.extra));
    }
}

pub fn diff(gmond: &Dump, ours: &Dump, seen_in_capture: &std::collections::HashSet<(String, String)>) -> Vec<String> {
    let mut out = vec![];
    let cl = Elem { attrs: gmond.cluster.clone(), extra: vec![] };
    diff_elem("CLUSTER", &cl, &Elem { attrs: ours.cluster.clone(), extra: vec![] }, &mut out);
    for (k, h) in &gmond.hosts {
        match ours.hosts.get(k) {
            Some(o) => diff_elem(&format!("HOST {k}"), h, o, &mut out),
            None => out.push(format!("HOST {k}: missing")),
        }
    }
    for k in ours.hosts.keys() {
        if !gmond.hosts.contains_key(k) {
            out.push(format!("HOST {k}: extra"));
        }
    }
    for (k, m) in &gmond.metrics {
        match ours.metrics.get(k) {
            Some(o) => {
                let mut d = vec![];
                diff_elem(&format!("METRIC {}/{}", k.0, k.1), m, o, &mut d);
                // gmond receives its own metrics over UDP and the kernel drops some
                // (Udp6RcvbufErrors). If our copy is strictly fresher, a differing
                // value or TN is a packet gmond lost, not a disagreement.
                let tn = |e: &Elem| e.attrs.get("TN").and_then(|v| v.parse::<i64>().ok());
                let fresher = matches!((tn(o), tn(m)), (Some(a), Some(b)) if a + 1 < b);
                let only_value = d.iter().all(|l| l.contains(": VAL ") || l.contains(": TN "));
                for l in d {
                    out.push(if fresher && only_value { format!("{l} [gmond missed a packet]") } else { l });
                }
            }
            // Nothing in the capture ever carried it: gmond holds it from before we started.
            None if !seen_in_capture.contains(&(k.0.rsplit('|').next().unwrap_or("").to_string(), k.1.clone())) => {
                out.push(format!("METRIC {}/{}: missing {PRE_CAPTURE}", k.0, k.1))
            }
            None => out.push(format!("METRIC {}/{}: missing", k.0, k.1)),
        }
    }
    for k in ours.metrics.keys() {
        if !gmond.metrics.contains_key(k) {
            out.push(format!("METRIC {}/{}: extra [gmond missed a packet]", k.0, k.1));
        }
    }
    out
}

pub const EXPLAINED: &str = "[gmond missed a packet]";
pub const PRE_CAPTURE: &str = "[last sent before the capture began]";

pub struct ReplayArgs {
    pub pcap: String,
    pub xml_dir: String,
    pub port: u16,
    pub params: (Cluster, String, u32, u32),
    /// Skip snapshots taken before this many seconds of traffic: state that
    /// predates the capture (metadata sent once, slow groups) needs time to recur.
    pub warmup_secs: i64,
}

/// Returns (snapshots compared, snapshots with unexplained differences, each
/// distinct difference with the number of snapshots it appeared in).
pub fn run(a: &ReplayArgs) -> Result<(usize, usize, Vec<String>)> {
    let packets: Vec<_> =
        crate::pcap::read(&a.pcap)?.into_iter().filter(|p| p.dst_port == a.port).collect();
    let mut snaps: Vec<(i64, std::path::PathBuf)> = std::fs::read_dir(&a.xml_dir)?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let n = e.file_name().into_string().ok()?;
            let ts = n.strip_prefix(&format!("{}-", a.port))?.strip_suffix(".xml")?.parse().ok()?;
            Some((ts, e.path()))
        })
        .collect();
    snaps.sort();
    let start = packets
        .first()
        .map(|p| p.ts_micros)
        .or(snaps.first().map(|(t, _)| t * USEC))
        .context("no packets and no snapshots")?;

    // (host ip, metric) pairs some captured packet carried.
    let seen_in_capture: std::collections::HashSet<(String, String)> = packets
        .iter()
        .filter_map(|p| Msg::decode(&p.payload).ok().map(|m| {
            let ip = if m.id().spoof {
                m.id().host.split(':').next().unwrap_or("").to_string()
            } else {
                crate::daemon::ip_string(p.src)
            };
            (ip, crate::store::sanitize_metric_name(&m.id().name, m.id().spoof))
        }))
        .collect();

    // Reverse DNS as gmond saw it: take names from the dumps themselves.
    let mut names: HashMap<String, String> = HashMap::new();
    for (_, p) in &snaps {
        for h in parse_dump(&std::fs::read(p)?).hosts.values() {
            names.insert(h.attrs["IP"].clone(), h.attrs["NAME"].clone());
        }
    }

    let (cluster, tags, tmax, dmax) = &a.params;
    let params = XmlParams { cluster, tags, host_tmax: *tmax, host_dmax: *dmax, allow_extra_data: true };
    let mut store = Store::default();
    let mut i = 0;
    let (mut compared, mut bad) = (0, 0);
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    // A capture spanning a gmond restart: gmond's state starts empty at that moment.
    let mut reset_at: Option<i64> =
        std::env::var("REPLAY_RESET_AT").ok().and_then(|v| v.parse::<i64>().ok()).map(|t| t * USEC);
    for (ts, path) in &snaps {
        // The snapshot file name is when the connection was opened (whole seconds).
        let at = ts * USEC;
        while i < packets.len() && packets[i].ts_micros <= at {
            let p = &packets[i];
            if let Some(r) = reset_at {
                if p.ts_micros >= r {
                    store = Store::default();
                    reset_at = None;
                }
            }
            if let Ok(m) = Msg::decode(&p.payload) {
                store.handle(m, &crate::daemon::ip_string(p.src), p.ts_micros, &mut |ip| names.get(ip).cloned());
            }
            i += 1;
        }
        if at - start < a.warmup_secs * USEC {
            continue;
        }
        store.cleanup(at, *dmax);
        let gm = parse_dump(&std::fs::read(path)?);
        let d_early = diff(&gm, &parse_dump(&xml::render(&store, &params, at)), &seen_in_capture);
        // The file name has whole-second resolution: gmond answered somewhere in
        // [at, at+1s). A difference only counts if it shows at both ends.
        let d = if d_early.is_empty() {
            d_early
        } else {
            let mut late = store.clone();
            let mut j = i;
            while j < packets.len() && packets[j].ts_micros <= at + USEC {
                let p = &packets[j];
                if let Ok(m) = Msg::decode(&p.payload) {
                    late.handle(m, &crate::daemon::ip_string(p.src), p.ts_micros, &mut |ip| names.get(ip).cloned());
                }
                j += 1;
            }
            let d_late = diff(&gm, &parse_dump(&xml::render(&late, &params, at + USEC - 1)), &seen_in_capture);
            let key = |l: &String| match l.find(" gmond=") { Some(i) => l[..i].to_string(), None => l.clone() };
            let late_keys: std::collections::HashSet<String> = d_late.iter().map(key).collect();
            d_early.into_iter().filter(|l| late_keys.contains(&key(l))).collect()
        };
        compared += 1;
        if d.iter().any(|l| !l.ends_with(EXPLAINED) && !l.ends_with(PRE_CAPTURE)) {
            bad += 1;
        }
        if !d.is_empty() {
            for l in d {
                // Values differ per snapshot; key on the element and attribute only.
                if std::env::var_os("REPLAY_VERBOSE").is_some() {
                    println!("{}: {l}", path.display());
                }
                let tag = if l.ends_with(EXPLAINED) { EXPLAINED } else if l.ends_with(PRE_CAPTURE) { PRE_CAPTURE } else { "" };
                let key = match l.find(" gmond=") { Some(i) => format!("{} {tag}", &l[..i]), None => l };
                *seen.entry(key).or_default() += 1;
            }
        }
    }
    Ok((compared, bad, seen.into_iter().map(|(k, n)| format!("{n:4}x {k}")).collect()))
}
