//! Port of gmond's python_modules/cpu/cpu_stats.py: context switches,
//! process creation and soft IRQ rates from /proc/stat, plus procs_blocked.
//!
//! Semantics kept from the Python module:
//! - /proc/stat is re-read only when the cached copy is more than
//!   `METRICS_CACHE_MAX` (5) seconds old; otherwise the previous pair of
//!   snapshots is reused.
//! - Rates are (current - previous) / (time between the two reads). The first
//!   read has an empty "previous" snapshot, so every rate is 0 then.
//! - A negative delta (counter reset or wrap) is reported as 0.
//! - procs_blocked is the current absolute value, 0 if the line is missing.
//! - Anything that would raise in Python (unreadable file, short or
//!   non-numeric line) makes gmond's mod_python send 0, so it reads as 0 here.
//!
//! `cpu_intr` and the `softirq` total, which the Python module also defines,
//! are not produced: rgmond takes cpu_intr from the libmetrics port.

use super::{Reading, Source};
use std::collections::HashMap;

const STAT_FILE: &str = "/proc/stat";
const METRICS_CACHE_MAX: f64 = 5.0;

/// Position of each soft IRQ in the `softirq` line's values (index 0 is the total).
const SOFTIRQ_POS: [(&str, usize); 10] = [
    ("hi", 1),
    ("timer", 2),
    ("nettx", 3),
    ("netrx", 4),
    ("block", 5),
    ("blockiopoll", 6),
    ("tasklet", 7),
    ("sched", 8),
    ("hrtimer", 9),
    ("rcu", 10),
];

#[derive(Default)]
struct Snapshot {
    time: f64,
    /// First word of each line -> the remaining words.
    data: HashMap<String, Vec<String>>,
}

impl Snapshot {
    fn parse(time: f64, text: &str) -> Snapshot {
        let mut data = HashMap::new();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            if let Some(key) = parts.next() {
                data.insert(key.to_string(), parts.map(str::to_string).collect());
            }
        }
        Snapshot { time, data }
    }

    fn field(&self, key: &str, idx: usize) -> Option<f64> {
        self.data.get(key)?.get(idx)?.parse().ok()
    }
}

pub struct CpuStats {
    cur: Snapshot,
    last: Snapshot,
    /// The last refresh attempt could not read /proc/stat (Python's
    /// get_metrics returned 0 and every callback raised).
    failed: bool,
}

impl CpuStats {
    #[allow(dead_code)]
    pub fn new(_params: &toml::Table) -> anyhow::Result<Self> {
        Ok(CpuStats { cur: Snapshot::default(), last: Snapshot::default(), failed: false })
    }

    fn update(&mut self, now: f64, read: impl FnOnce() -> std::io::Result<String>) {
        self.failed = false;
        if now - self.cur.time > METRICS_CACHE_MAX {
            match read() {
                Ok(text) => {
                    self.last = std::mem::replace(&mut self.cur, Snapshot::parse(now, &text));
                }
                Err(e) => {
                    log::debug!("cpu_stats: {STAT_FILE}: {e}");
                    self.failed = true;
                }
            }
        }
    }

    /// get_delta / get_softirq_delta: rate of one counter between snapshots.
    fn delta(&self, key: &str, idx: usize) -> f64 {
        let (Some(c), Some(l)) = (self.cur.field(key, idx), self.last.field(key, idx)) else {
            return 0.0;
        };
        let d = (c - l) / (self.cur.time - self.last.time);
        if d < 0.0 { 0.0 } else { d }
    }
}

impl Source for CpuStats {
    fn name(&self) -> &'static str {
        "cpu_stats"
    }

    fn names(&self) -> Vec<String> {
        let mut v: Vec<String> =
            ["cpu_ctxt", "procs_created", "procs_blocked"].iter().map(|s| s.to_string()).collect();
        v.extend(SOFTIRQ_POS.iter().map(|(n, _)| format!("softirq_{n}")));
        v
    }

    fn sample(&mut self, now: f64) {
        self.update(now, || std::fs::read_to_string(STAT_FILE));
    }

    fn value(&self, name: &str) -> Option<Reading> {
        let v = match name {
            "cpu_ctxt" => self.delta("ctxt", 0),
            "procs_created" => self.delta("processes", 0),
            // get_value: the raw string, which gmond converts with strtod.
            "procs_blocked" => self.cur.field("procs_blocked", 0).unwrap_or(0.0),
            _ => {
                let irq = name.strip_prefix("softirq_")?;
                let &(_, idx) = SOFTIRQ_POS.iter().find(|(n, _)| *n == irq)?;
                self.delta("softirq", idx)
            }
        };
        Some(Reading::Num(if self.failed { 0.0 } else { v }))
    }
}

#[cfg(test)]
#[path = "../../tools/parity/harness.rs"]
mod parity_harness;

#[cfg(test)]
mod tests {
    use super::*;

    const STAT_A: &str = "\
cpu  57585000 262724 17774006 1542301779 7129580 1752404 1595470 312821 0 0
cpu0 3622642 16094 1095056 96175436 552025 113126 200912 22942 0 0
intr 1234567890 9 0 0 0 0
ctxt 3184164318
btime 1791224066
processes 11738515
procs_running 3
procs_blocked 0
softirq 1940637043 0 272338356 642198 562122688 0 0 27795402 321218244 36547 756483608
";
    const STAT_B: &str = "\
cpu  57585100 262724 17774016 1542302779 7129580 1752404 1595470 312821 0 0
cpu0 3622652 16094 1095056 96175536 552025 113126 200912 22942 0 0
intr 1234577890 9 0 0 0 0
ctxt 3184264318
btime 1791224066
processes 11738615
procs_running 2
procs_blocked 2
softirq 1940737043 10 272348356 642298 562132688 0 0 27795502 321228244 36557 756493608
";

    fn num(s: &CpuStats, n: &str) -> f64 {
        match s.value(n) {
            Some(Reading::Num(v)) => v,
            other => panic!("{n}: {other:?}"),
        }
    }

    fn fed(text: &'static str) -> impl FnOnce() -> std::io::Result<String> {
        move || Ok(text.to_string())
    }

    #[test]
    fn rates_across_two_samples() {
        let mut s = CpuStats::new(&toml::Table::new()).unwrap();
        s.update(1000.0, fed(STAT_A));
        // First read: no previous snapshot, every rate is 0.
        for n in s.names() {
            assert_eq!(num(&s, &n), 0.0, "{n}");
        }
        s.update(1010.0, fed(STAT_B));
        assert_eq!(num(&s, "cpu_ctxt"), 10000.0);
        assert_eq!(num(&s, "procs_created"), 10.0);
        assert_eq!(num(&s, "procs_blocked"), 2.0);
        assert_eq!(num(&s, "softirq_hi"), 1.0);
        assert_eq!(num(&s, "softirq_timer"), 1000.0);
        assert_eq!(num(&s, "softirq_nettx"), 10.0);
        assert_eq!(num(&s, "softirq_netrx"), 1000.0);
        assert_eq!(num(&s, "softirq_block"), 0.0);
        assert_eq!(num(&s, "softirq_blockiopoll"), 0.0);
        assert_eq!(num(&s, "softirq_tasklet"), 10.0);
        assert_eq!(num(&s, "softirq_sched"), 1000.0);
        assert_eq!(num(&s, "softirq_hrtimer"), 1.0);
        assert_eq!(num(&s, "softirq_rcu"), 1000.0);
        assert_eq!(s.value("cpu_intr"), None);
        assert_eq!(s.value("softirq"), None);
    }

    #[test]
    fn cache_window_and_negative_delta() {
        let mut s = CpuStats::new(&toml::Table::new()).unwrap();
        s.update(1000.0, fed(STAT_A));
        s.update(1010.0, fed(STAT_B));
        // Within 5 s of the last read: no re-read, same values.
        s.update(1015.0, || panic!("must not re-read inside the cache window"));
        assert_eq!(num(&s, "cpu_ctxt"), 10000.0);
        // Counters going backwards read as 0.
        s.update(1015.5, fed(STAT_A));
        assert_eq!(num(&s, "cpu_ctxt"), 0.0);
        assert_eq!(num(&s, "procs_blocked"), 0.0);
    }

    #[test]
    fn unreadable_file_reads_zero_then_recovers() {
        let mut s = CpuStats::new(&toml::Table::new()).unwrap();
        s.update(1000.0, fed(STAT_A));
        s.update(1010.0, fed(STAT_B));
        assert_eq!(num(&s, "procs_blocked"), 2.0);
        // A failed read: every metric is 0 this round.
        s.update(1020.0, || Err(std::io::Error::other("gone")));
        assert_eq!(num(&s, "procs_blocked"), 0.0);
        assert_eq!(num(&s, "cpu_ctxt"), 0.0);
        // The cache time did not move, so the very next round re-reads, and
        // the previous snapshot is still the one from 1010.
        s.update(1021.0, fed(STAT_A));
        assert_eq!(num(&s, "procs_blocked"), 0.0);
        assert_eq!(num(&s, "cpu_ctxt"), 0.0); // B -> A goes backwards
        s.update(1032.0, fed(STAT_B));
        assert!((num(&s, "cpu_ctxt") - 100000.0 / 11.0).abs() < 1e-9);
    }

    #[test]
    #[ignore]
    fn live_parity_with_python() {
        use super::parity_harness as harness;
        let mut py = harness::PyModule::spawn("cpu", "cpu_stats");
        let mut rs = CpuStats::new(&toml::Table::new()).unwrap();
        for round in 0..4 {
            rs.sample(harness::now());
            let p = py.sample();
            let r = harness::rust_values(&rs);
            for (n, rv) in &r {
                let pv = p[n];
                eprintln!("round {round} {n:22} rust {rv:14.4} python {pv:14.4}");
                if round == 0 {
                    assert!(*rv == 0.0 && pv == 0.0, "{n}: first sample must be 0");
                } else if n == "procs_blocked" {
                    // An instantaneous count of D-state tasks, read microseconds
                    // apart on each side: small flips are expected.
                    assert!((*rv - pv).abs() <= 2.0, "{n}: {rv} vs {pv}");
                } else {
                    assert!(harness::close(*rv, pv, 2.0, 0.03), "{n}: {rv} vs {pv}");
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(6));
        }
    }
}
