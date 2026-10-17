//! Port of gmond's python_modules/vm_stats/vm_stats.py, limited to the four
//! metrics gmond's stock pyconf configures: vm_pgmajfault, vm_pgpgin, vm_pgpgout (rates
//! from /proc/vmstat) and vm_vmeff.
//!
//! Semantics kept from the Python module:
//! - /proc/vmstat is re-read only when the cached copy is more than
//!   `METRICS_CACHE_MAX` (5) seconds old.
//! - Rates are (current - previous) / (time between the two reads); the first
//!   read has an empty previous snapshot, so rates are 0 then. Negative
//!   deltas (counter reset) read as 0.
//! - vm_vmeff = 100 * d(pgsteal_normal) / d(pgscan_kswapd_normal), 0 when
//!   the scan delta is 0. Kernels since 4.8 have neither counter, so the
//!   Python module (and this port) always reports 0 there.
//! - Anything that would raise in Python (unreadable file, non-numeric value)
//!   makes gmond's mod_python send 0, so it reads as 0 here.

use super::{Reading, Source};
use std::collections::HashMap;

const VMSTAT_FILE: &str = "/proc/vmstat";
const METRICS_CACHE_MAX: f64 = 5.0;
const NAMES: [&str; 4] = ["vm_pgmajfault", "vm_pgpgin", "vm_pgpgout", "vm_vmeff"];

#[derive(Default)]
struct Snapshot {
    time: f64,
    /// Counter name -> its value text (the second word of the line).
    data: HashMap<String, String>,
}

impl Snapshot {
    fn parse(time: f64, text: &str) -> Snapshot {
        let mut data = HashMap::new();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            if let Some(key) = parts.next() {
                data.insert(key.to_string(), parts.next().unwrap_or("").to_string());
            }
        }
        Snapshot { time, data }
    }

    fn get(&self, key: &str) -> Option<f64> {
        self.data.get(key)?.parse().ok()
    }
}

pub struct VmStats {
    cur: Snapshot,
    last: Snapshot,
    failed: bool,
}

impl VmStats {
    #[allow(dead_code)]
    pub fn new(_params: &toml::Table) -> anyhow::Result<Self> {
        Ok(VmStats { cur: Snapshot::default(), last: Snapshot::default(), failed: false })
    }

    fn update(&mut self, now: f64, read: impl FnOnce() -> std::io::Result<String>) {
        self.failed = false;
        if now - self.cur.time > METRICS_CACHE_MAX {
            match read() {
                Ok(text) => {
                    self.last = std::mem::replace(&mut self.cur, Snapshot::parse(now, &text));
                }
                Err(e) => {
                    log::debug!("vm_stats: {VMSTAT_FILE}: {e}");
                    self.failed = true;
                }
            }
        }
    }

    /// Difference of one counter between the snapshots.
    fn diff(&self, key: &str) -> Option<f64> {
        Some(self.cur.get(key)? - self.last.get(key)?)
    }

    /// get_delta
    fn delta(&self, key: &str) -> f64 {
        let Some(d) = self.diff(key) else { return 0.0 };
        let d = d / (self.cur.time - self.last.time);
        if d < 0.0 { 0.0 } else { d }
    }

    /// get_vmeff
    fn vmeff(&self) -> f64 {
        let Some(scan) = self.diff("pgscan_kswapd_normal") else { return 0.0 };
        if scan == 0.0 {
            return 0.0;
        }
        let Some(steal) = self.diff("pgsteal_normal") else { return 0.0 };
        let d = 100.0 * steal / scan;
        if d < 0.0 { 0.0 } else { d }
    }
}

impl Source for VmStats {
    fn name(&self) -> &'static str {
        "vm_stats"
    }

    fn names(&self) -> Vec<String> {
        NAMES.iter().map(|s| s.to_string()).collect()
    }

    fn sample(&mut self, now: f64) {
        self.update(now, || std::fs::read_to_string(VMSTAT_FILE));
    }

    fn value(&self, name: &str) -> Option<Reading> {
        let v = match name {
            "vm_vmeff" => self.vmeff(),
            "vm_pgmajfault" | "vm_pgpgin" | "vm_pgpgout" => self.delta(&name[3..]),
            _ => return None,
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

    const VMSTAT_A: &str = "\
nr_free_pages 104066
nr_zone_inactive_anon 1009737
pgpgin 3118886232
pgpgout 3375267896
pswpin 0
pswpout 0
pgsteal_kswapd 850706135
pgscan_kswapd 852354544
pgmajfault 1628239
";
    const VMSTAT_B: &str = "\
nr_free_pages 104000
nr_zone_inactive_anon 1009700
pgpgin 3118896232
pgpgout 3375277896
pswpin 0
pswpout 0
pgsteal_kswapd 850706235
pgscan_kswapd 852354644
pgmajfault 1628269
";

    fn num(s: &VmStats, n: &str) -> f64 {
        match s.value(n) {
            Some(Reading::Num(v)) => v,
            other => panic!("{n}: {other:?}"),
        }
    }

    fn fed(text: String) -> impl FnOnce() -> std::io::Result<String> {
        move || Ok(text)
    }

    #[test]
    fn rates_across_two_samples() {
        let mut s = VmStats::new(&toml::Table::new()).unwrap();
        s.update(100.0, fed(VMSTAT_A.into()));
        for n in s.names() {
            assert_eq!(num(&s, &n), 0.0, "{n}");
        }
        s.update(130.0, fed(VMSTAT_B.into()));
        assert_eq!(num(&s, "vm_pgmajfault"), 1.0);
        assert!((num(&s, "vm_pgpgin") - 10000.0 / 30.0).abs() < 1e-9);
        assert!((num(&s, "vm_pgpgout") - 10000.0 / 30.0).abs() < 1e-9);
        // No *_normal counters on modern kernels: always 0.
        assert_eq!(num(&s, "vm_vmeff"), 0.0);
        assert_eq!(s.value("vm_nr_free_pages"), None);
        // Inside the cache window nothing is re-read.
        s.update(135.0, || panic!("re-read inside cache window"));
        assert_eq!(num(&s, "vm_pgmajfault"), 1.0);
        // Counters going backwards read as 0.
        s.update(135.1, fed(VMSTAT_A.into()));
        assert_eq!(num(&s, "vm_pgpgin"), 0.0);
    }

    #[test]
    fn vmeff_on_old_kernels() {
        let a = format!("{VMSTAT_A}pgsteal_normal 1000\npgscan_kswapd_normal 2000\n");
        let b = format!("{VMSTAT_A}pgsteal_normal 1300\npgscan_kswapd_normal 2400\n");
        let c = format!("{VMSTAT_A}pgsteal_normal 1300\npgscan_kswapd_normal 2400\n");
        let mut s = VmStats::new(&toml::Table::new()).unwrap();
        s.update(100.0, fed(a));
        s.update(110.0, fed(b));
        assert_eq!(num(&s, "vm_vmeff"), 75.0);
        s.update(120.0, fed(c));
        assert_eq!(num(&s, "vm_vmeff"), 0.0); // no pages scanned
    }

    #[test]
    #[ignore]
    fn live_parity_with_python() {
        use super::parity_harness as harness;
        let mut py = harness::PyModule::spawn("vm_stats", "vm_stats");
        let mut rs = VmStats::new(&toml::Table::new()).unwrap();
        for round in 0..4 {
            rs.sample(harness::now());
            let p = py.sample();
            let r = harness::rust_values(&rs);
            for (n, rv) in &r {
                let pv = p[n];
                eprintln!("round {round} {n:22} rust {rv:14.4} python {pv:14.4}");
                if round == 0 {
                    assert!(*rv == 0.0 && pv == 0.0, "{n}: first sample must be 0");
                } else {
                    assert!(harness::close(*rv, pv, 2.0, 0.03), "{n}: {rv} vs {pv}");
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(6));
        }
    }
}
