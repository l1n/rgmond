//! BPF-derived metrics (new in rgmond; none of these existed in gmond).
//!
//! Programs come from bpf/rgmond.bpf.c, compiled by build.rs. Each feature is
//! loaded only if every tracepoint field it reads sits at the offset compiled
//! into the program, per /sys/kernel/tracing/events/*/format. A feature that
//! fails to verify, load or attach is skipped with one log line: no existing
//! metric depends on BPF.

use super::{Reading, Source};
use anyhow::{Context, Result, bail};
use aya::maps::{Array, HashMap as BpfHash, MapData, PerCpuArray};
use aya::programs::TracePoint;
use aya::{Ebpf, EbpfLoader, Pod};
use log::{info, warn};
use std::collections::{BTreeMap, HashMap};

static OBJ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rgmond.bpf.o"));

const SLOTS: usize = 32;

/// Mirrors `struct hist` in rgmond.bpf.c.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Hist {
    slots: [u64; SLOTS],
    count: u64,
    sum_ns: u64,
}
unsafe impl Pod for Hist {}

impl Hist {
    fn minus(&self, prev: &Hist) -> Hist {
        let mut d = *self;
        for i in 0..SLOTS {
            d.slots[i] = self.slots[i].saturating_sub(prev.slots[i]);
        }
        d.count = self.count.saturating_sub(prev.count);
        d.sum_ns = self.sum_ns.saturating_sub(prev.sum_ns);
        d
    }

    /// Upper edge (in microseconds) of the log2 bucket holding quantile q.
    fn quantile_us(&self, q: f64) -> f64 {
        if self.count == 0 {
            return 0.0;
        }
        let want = (self.count as f64 * q).ceil() as u64;
        let mut seen = 0;
        for (i, n) in self.slots.iter().enumerate() {
            seen += n;
            if seen >= want {
                return (1u64 << (i + 1)) as f64;
            }
        }
        (1u64 << SLOTS) as f64
    }

    fn mean_us(&self) -> f64 {
        if self.count == 0 { 0.0 } else { self.sum_ns as f64 / self.count as f64 / 1000.0 }
    }
}

struct Feature {
    name: &'static str,
    doc: &'static str,
    /// (program, tracepoint category, tracepoint name)
    programs: &'static [(&'static str, &'static str, &'static str)],
    /// (category/name, field, offset, size) the programs depend on.
    fields: &'static [(&'static str, &'static str, usize, usize)],
}

const FEATURES: &[Feature] = &[
    Feature {
        name: "biolatency",
        doc: "Block I/O latency per disk, issue to completion: mean and 99th percentile.",
        programs: &[("block_issue", "block", "block_rq_issue"), ("block_complete", "block", "block_rq_complete")],
        fields: &[
            ("block/block_rq_issue", "dev", 8, 4),
            ("block/block_rq_issue", "sector", 16, 8),
            ("block/block_rq_complete", "dev", 8, 4),
            ("block/block_rq_complete", "sector", 16, 8),
        ],
    },
    Feature {
        name: "tcp",
        doc: "TCP retransmitted segments and received resets per local port, for the ports in `tcp_ports`.",
        programs: &[("tcp_retransmit", "tcp", "tcp_retransmit_skb"), ("tcp_reset", "tcp", "tcp_receive_reset")],
        fields: &[("tcp/tcp_retransmit_skb", "sport", 28, 2), ("tcp/tcp_receive_reset", "sport", 16, 2)],
    },
    Feature {
        name: "runqlat",
        doc: "Run-queue latency, from wakeup to running on a CPU: mean and 99th percentile.",
        programs: &[
            ("sched_wakeup", "sched", "sched_wakeup"),
            ("sched_wakeup_new", "sched", "sched_wakeup_new"),
            ("sched_switch", "sched", "sched_switch"),
        ],
        fields: &[
            ("sched/sched_wakeup", "pid", 24, 4),
            ("sched/sched_wakeup_new", "pid", 24, 4),
            ("sched/sched_switch", "prev_pid", 24, 4),
            ("sched/sched_switch", "prev_state", 32, 8),
            ("sched/sched_switch", "next_pid", 56, 4),
        ],
    },
    Feature {
        name: "softirq",
        doc: "Share of CPU time spent in each softirq vector.",
        programs: &[("softirq_entry", "irq", "softirq_entry"), ("softirq_exit", "irq", "softirq_exit")],
        fields: &[("irq/softirq_entry", "vec", 8, 4), ("irq/softirq_exit", "vec", 8, 4)],
    },
    Feature {
        name: "reclaim",
        doc: "Time tasks spent stalled in direct memory reclaim.",
        programs: &[
            ("reclaim_begin", "vmscan", "mm_vmscan_direct_reclaim_begin"),
            ("reclaim_end", "vmscan", "mm_vmscan_direct_reclaim_end"),
        ],
        fields: &[],
    },
];

/// (feature, tracepoints, description) for `rgmond docs`.
pub fn feature_docs() -> Vec<(&'static str, Vec<String>, &'static str)> {
    FEATURES.iter().map(|f| (f.name, f.programs.iter().map(|(_, c, t)| format!("`{c}/{t}`")).collect(), f.doc)).collect()
}

/// The kernel's softirq vector names, in vector order (include/linux/interrupt.h).
const SOFTIRQS: [&str; 10] = ["hi", "timer", "nettx", "netrx", "block", "irqpoll", "tasklet", "sched", "hrtimer", "rcu"];

/// (offset, size) of a field in a tracepoint format file.
fn field_layout(event: &str, field: &str) -> Result<(usize, usize)> {
    let path = format!("/sys/kernel/tracing/events/{event}/format");
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    for line in text.lines() {
        let Some(decl) = line.trim().strip_prefix("field:") else { continue };
        let mut parts = decl.split(';').map(str::trim);
        let name = parts.next().unwrap_or("");
        let ident = name.rsplit([' ', '*']).next().unwrap_or("").split('[').next().unwrap_or("");
        if ident != field {
            continue;
        }
        let get = |k: &str| {
            decl.split(';').map(str::trim).find_map(|p| p.strip_prefix(k)).and_then(|v| v.parse::<usize>().ok())
        };
        return Ok((get("offset:").unwrap_or(usize::MAX), get("size:").unwrap_or(usize::MAX)));
    }
    bail!("{event} has no field {field}")
}

fn verify(f: &Feature) -> Result<()> {
    for (event, field, off, size) in f.fields {
        let (o, s) = field_layout(event, field)?;
        if (o, s) != (*off, *size) {
            bail!("{event}.{field} is at {o}+{s}, program expects {off}+{size}");
        }
    }
    Ok(())
}

/// Block device name for a kernel dev_t (MAJOR << 20 | MINOR inside the kernel).
fn dev_name(dev: u32) -> String {
    let (maj, min) = (dev >> 20, dev & ((1 << 20) - 1));
    std::fs::read_to_string(format!("/sys/dev/block/{maj}:{min}/uevent"))
        .ok()
        .and_then(|u| u.lines().find_map(|l| l.strip_prefix("DEVNAME=").map(str::to_string)))
        .unwrap_or_else(|| format!("{maj}_{min}"))
        .replace(['/', '-'], "_")
}

pub struct Bpf {
    ebpf: Ebpf,
    enabled: Vec<&'static str>,
    ports: Vec<u16>,
    last_t: f64,
    prev_hist: HashMap<String, Hist>,
    prev_count: HashMap<String, u64>,
    prev_sirq: [u64; 16],
    values: BTreeMap<String, Reading>,
}

impl Bpf {
    /// params: features = "biolatency tcp runqlat softirq reclaim" (default all),
    /// tcp_ports = "22 25 443" (ports to report retransmits/resets for).
    pub fn new(params: &toml::Table) -> Result<Bpf> {
        let want: Vec<String> = params
            .get("features")
            .and_then(|v| v.as_str())
            .map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or_else(|| FEATURES.iter().map(|f| f.name.to_string()).collect());
        let ports: Vec<u16> = params
            .get("tcp_ports")
            .and_then(|v| v.as_str())
            .map(|s| s.split_whitespace().filter_map(|p| p.parse().ok()).collect())
            .unwrap_or_default();
        let mut ebpf = EbpfLoader::new().btf(None).load(OBJ).context("loading BPF object")?;
        let mut enabled = vec![];
        for f in FEATURES.iter().filter(|f| want.iter().any(|w| w == f.name)) {
            let res: Result<()> = (|| {
                verify(f)?;
                for (prog, cat, tp) in f.programs {
                    let p: &mut TracePoint = ebpf.program_mut(prog).context("program missing")?.try_into()?;
                    p.load().with_context(|| format!("loading {prog}"))?;
                    p.attach(cat, tp).with_context(|| format!("attaching {prog} to {cat}/{tp}"))?;
                }
                Ok(())
            })();
            match res {
                Ok(()) => {
                    info!("bpf: {} enabled", f.name);
                    enabled.push(f.name);
                }
                Err(e) => warn!("bpf: {} disabled: {e:#}", f.name),
            }
        }
        if enabled.is_empty() {
            bail!("no BPF feature could be enabled");
        }
        let mut b = Bpf {
            ebpf,
            enabled,
            ports,
            last_t: 0.0,
            prev_hist: HashMap::new(),
            prev_count: HashMap::new(),
            prev_sirq: [0; 16],
            values: BTreeMap::new(),
        };
        b.sample(crate::store::now_micros() as f64 / 1e6);
        Ok(b)
    }

    fn on(&self, f: &str) -> bool {
        self.enabled.contains(&f)
    }

    fn hist_delta(&mut self, key: String, cur: Hist) -> Hist {
        let d = match self.prev_hist.get(&key) {
            Some(p) => cur.minus(p),
            None => cur.minus(&cur),
        };
        self.prev_hist.insert(key, cur);
        d
    }

    fn count_rate(&mut self, key: String, cur: u64, dt: f64) -> f64 {
        let prev = self.prev_count.insert(key, cur);
        match prev {
            Some(p) if dt > 0.0 => cur.saturating_sub(p) as f64 / dt,
            _ => 0.0,
        }
    }

    fn map(&self, name: &str) -> &aya::maps::Map {
        self.ebpf.map(name).expect("map compiled into rgmond.bpf.o")
    }
}

impl Source for Bpf {
    fn name(&self) -> &'static str {
        "bpf"
    }

    fn names(&self) -> Vec<String> {
        let mut v = vec![];
        if self.on("biolatency") {
            for d in block_devices() {
                v.push(format!("biolat_{d}_avg_ms"));
                v.push(format!("biolat_{d}_p99_ms"));
            }
        }
        if self.on("tcp") {
            for p in &self.ports {
                v.push(format!("tcp_retrans_port_{p}"));
                v.push(format!("tcp_rst_port_{p}"));
            }
        }
        if self.on("runqlat") {
            v.push("runq_lat_avg_us".into());
            v.push("runq_lat_p99_us".into());
        }
        if self.on("softirq") {
            v.extend(SOFTIRQS.iter().map(|n| format!("softirq_time_{n}_pct")));
        }
        if self.on("reclaim") {
            v.push("reclaim_stall_ms".into());
        }
        v
    }

    fn sample(&mut self, now: f64) {
        let dt = if self.last_t > 0.0 { now - self.last_t } else { 0.0 };
        self.last_t = now;
        let mut out: BTreeMap<String, Reading> = BTreeMap::new();

        if self.on("biolatency") {
            let devs: Vec<(u32, Hist)> = BpfHash::<&MapData, u32, Hist>::try_from(self.map("bio_hist"))
                .map(|m| m.iter().filter_map(|r| r.ok()).collect())
                .unwrap_or_default();
            for (dev, h) in devs {
                let name = dev_name(dev);
                let d = self.hist_delta(format!("bio/{dev}"), h);
                out.insert(format!("biolat_{name}_avg_ms"), Reading::Num(d.mean_us() / 1000.0));
                out.insert(format!("biolat_{name}_p99_ms"), Reading::Num(d.quantile_us(0.99) / 1000.0));
            }
        }
        if self.on("tcp") {
            for (map, prefix) in [("tcp_retx", "tcp_retrans_port"), ("tcp_rst", "tcp_rst_port")] {
                let counts: HashMap<u16, u64> = BpfHash::<&MapData, u16, u64>::try_from(self.map(map))
                    .map(|m| m.iter().filter_map(|r| r.ok()).collect())
                    .unwrap_or_default();
                for p in self.ports.clone() {
                    let c = counts.get(&p).copied().unwrap_or(0);
                    let r = self.count_rate(format!("{map}/{p}"), c, dt);
                    out.insert(format!("{prefix}_{p}"), Reading::Num(r));
                }
            }
        }
        if self.on("runqlat") {
            if let Ok(Some(h)) = Array::<&MapData, Hist>::try_from(self.map("runq_hist")).map(|a| a.get(&0, 0).ok()) {
                let d = self.hist_delta("runq".into(), h);
                out.insert("runq_lat_avg_us".into(), Reading::Num(d.mean_us()));
                out.insert("runq_lat_p99_us".into(), Reading::Num(d.quantile_us(0.99)));
            }
        }
        if self.on("softirq") {
            let totals: Option<Vec<u64>> = PerCpuArray::<&MapData, u64>::try_from(self.map("sirq_time")).ok().map(|a| {
                (0..SOFTIRQS.len()).map(|i| a.get(&(i as u32), 0).map(|v| v.iter().sum()).unwrap_or(0)).collect()
            });
            if let Some(totals) = totals {
                let ncpu = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }.max(1) as f64;
                for (i, n) in SOFTIRQS.iter().enumerate() {
                    let total = totals[i];
                    let d = total.saturating_sub(self.prev_sirq[i]);
                    self.prev_sirq[i] = total;
                    // Percent of all CPUs' time spent in this softirq.
                    let pct = if dt > 0.0 { d as f64 / (dt * 1e9 * ncpu) * 100.0 } else { 0.0 };
                    out.insert(format!("softirq_time_{n}_pct"), Reading::Num(pct));
                }
            }
        }
        if self.on("reclaim") {
            if let Ok(Some(h)) = Array::<&MapData, Hist>::try_from(self.map("reclaim_total")).map(|a| a.get(&0, 0).ok()) {
                let d = self.hist_delta("reclaim".into(), h);
                let ms_per_s = if dt > 0.0 { d.sum_ns as f64 / 1e6 / dt } else { 0.0 };
                out.insert("reclaim_stall_ms".into(), Reading::Num(ms_per_s));
            }
        }
        self.values = out;
    }

    fn value(&self, name: &str) -> Option<Reading> {
        self.values.get(name).cloned().or_else(|| {
            // A device with no I/O yet this run has no histogram entry: report 0.
            name.starts_with("biolat_").then_some(Reading::Num(0.0))
        })
    }
}

/// Whole disks (not partitions) with a queue, the devices block tracepoints report.
fn block_devices() -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir("/sys/block")
        .map(|d| d.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    v.retain(|d| {
        let size = std::fs::read_to_string(format!("/sys/block/{d}/size")).ok().and_then(|s| s.trim().parse::<u64>().ok());
        !d.starts_with("loop") && !d.starts_with("ram") && size.unwrap_or(0) > 0
    });
    v.sort();
    v.into_iter().map(|d| d.replace(['/', '-'], "_")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hist_quantiles() {
        let mut h = Hist { slots: [0; SLOTS], count: 0, sum_ns: 0 };
        h.slots[3] = 98; // 8..16 us
        h.slots[10] = 2; // 1..2 ms
        h.count = 100;
        h.sum_ns = 100_000;
        assert_eq!(h.quantile_us(0.5), 16.0);
        assert_eq!(h.quantile_us(0.99), 2048.0);
        assert_eq!(h.mean_us(), 1.0);
    }

    #[test]
    #[ignore] // needs root (CAP_BPF, CAP_PERFMON, tracefs)
    fn live_load() {
        let mut t = toml::Table::new();
        t.insert("tcp_ports".into(), "22 443".into());
        let mut b = Bpf::new(&t).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(3));
        b.sample(crate::store::now_micros() as f64 / 1e6);
        for n in b.names() {
            println!("{n} = {:?}", b.value(&n));
        }
        assert!(!b.enabled.is_empty());
    }
}
