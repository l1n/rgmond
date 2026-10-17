//! Port of gmond's python_modules/memory/mem_stats.py, limited to the
//! /proc/meminfo fields gmond's stock pyconf configures from it: mem_anonpages,
//! mem_dirty, mem_hardware_corrupted, mem_mapped and mem_writeback.
//! (mem_total, mem_free, swap_* and friends come from the libmetrics port.)
//!
//! Semantics kept from the Python module:
//! - Absolute values, no cache: /proc/meminfo is read on every collection.
//! - The fields are in kB and these metrics have units "Bytes", so the value
//!   is kB * 1024.
//! - If a field appears more than once the last occurrence wins; a missing
//!   field reads as 0, as does an unreadable file (IOError returns 0).
//! - A matching line with a non-numeric value makes the Python callback
//!   raise, which gmond's mod_python sends as 0.

use super::{Reading, Source};

const MEMINFO_FILE: &str = "/proc/meminfo";

/// Metric name -> /proc/meminfo field (orig_name in the Python module).
const FIELDS: [(&str, &str); 5] = [
    ("mem_dirty", "Dirty"),
    ("mem_writeback", "Writeback"),
    ("mem_anonpages", "AnonPages"),
    ("mem_mapped", "Mapped"),
    ("mem_hardware_corrupted", "HardwareCorrupted"),
];

pub struct MemStats {
    values: [f64; FIELDS.len()],
}

impl MemStats {
    #[allow(dead_code)]
    pub fn new(_params: &toml::Table) -> anyhow::Result<Self> {
        Ok(MemStats { values: [0.0; FIELDS.len()] })
    }

    fn update(&mut self, read: std::io::Result<String>) {
        self.values = match read {
            Ok(text) => Self::parse(&text),
            Err(e) => {
                log::debug!("mem_stats: {MEMINFO_FILE}: {e}");
                [0.0; FIELDS.len()]
            }
        };
    }

    fn parse(text: &str) -> [f64; FIELDS.len()] {
        // Per field: None = not seen, Some(None) = seen but would raise.
        let mut found: [Option<Option<f64>>; FIELDS.len()] = [None; FIELDS.len()];
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let Some(key) = parts.next().and_then(|k| k.strip_suffix(':')) else { continue };
            if let Some(i) = FIELDS.iter().position(|(_, f)| *f == key) {
                // Python stops at the first line that raises.
                if found[i] != Some(None) {
                    found[i] = Some(parts.next().and_then(|v| v.parse::<f64>().ok()).map(|kb| kb * 1024.0));
                }
            }
        }
        found.map(|f| f.flatten().unwrap_or(0.0))
    }
}

impl Source for MemStats {
    fn name(&self) -> &'static str {
        "mem_stats"
    }

    fn names(&self) -> Vec<String> {
        FIELDS.iter().map(|(n, _)| n.to_string()).collect()
    }

    fn sample(&mut self, _now: f64) {
        self.update(std::fs::read_to_string(MEMINFO_FILE));
    }

    fn value(&self, name: &str) -> Option<Reading> {
        let i = FIELDS.iter().position(|(n, _)| *n == name)?;
        Some(Reading::Num(self.values[i]))
    }
}

#[cfg(test)]
#[path = "../../tools/parity/harness.rs"]
mod parity_harness;

#[cfg(test)]
mod tests {
    use super::*;

    const MEMINFO_A: &str = "\
MemTotal:       32842056 kB
MemFree:          416264 kB
Buffers:         2876992 kB
Cached:         19783808 kB
SwapTotal:        262140 kB
SwapFree:           1068 kB
Dirty:            124484 kB
Writeback:             0 kB
AnonPages:       7935616 kB
Mapped:          1493800 kB
Shmem:           1395016 kB
WritebackTmp:          0 kB
HardwareCorrupted:     0 kB
HugePages_Total:       0
";
    const MEMINFO_B: &str = "\
MemTotal:       32842056 kB
MemFree:          400000 kB
Dirty:              2048 kB
Writeback:           512 kB
AnonPages:       7935000 kB
Mapped:          1493000 kB
WritebackTmp:          4 kB
HardwareCorrupted:     8 kB
";

    fn num(s: &MemStats, n: &str) -> f64 {
        match s.value(n) {
            Some(Reading::Num(v)) => v,
            other => panic!("{n}: {other:?}"),
        }
    }

    #[test]
    fn two_samples() {
        let mut s = MemStats::new(&toml::Table::new()).unwrap();
        s.update(Ok(MEMINFO_A.into()));
        assert_eq!(num(&s, "mem_dirty"), 124484.0 * 1024.0);
        assert_eq!(num(&s, "mem_writeback"), 0.0);
        assert_eq!(num(&s, "mem_anonpages"), 7935616.0 * 1024.0);
        assert_eq!(num(&s, "mem_mapped"), 1493800.0 * 1024.0);
        assert_eq!(num(&s, "mem_hardware_corrupted"), 0.0);
        s.update(Ok(MEMINFO_B.into()));
        assert_eq!(num(&s, "mem_dirty"), 2048.0 * 1024.0);
        assert_eq!(num(&s, "mem_writeback"), 512.0 * 1024.0); // not WritebackTmp
        assert_eq!(num(&s, "mem_anonpages"), 7935000.0 * 1024.0);
        assert_eq!(num(&s, "mem_mapped"), 1493000.0 * 1024.0);
        assert_eq!(num(&s, "mem_hardware_corrupted"), 8.0 * 1024.0);
        assert_eq!(s.value("mem_total"), None);
        assert_eq!(s.value("mem_free"), None);
    }

    #[test]
    fn missing_bad_and_repeated_fields() {
        let v = MemStats::parse("Dirty: 1 kB\nDirty: 2 kB\nMapped: x kB\nMapped: 5 kB\nAnonPages:\n");
        assert_eq!(v, [2048.0, 0.0, 0.0, 0.0, 0.0]);
        let mut s = MemStats::new(&toml::Table::new()).unwrap();
        s.update(Ok(MEMINFO_A.into()));
        s.update(Err(std::io::Error::other("gone")));
        assert_eq!(num(&s, "mem_dirty"), 0.0);
    }

    #[test]
    #[ignore]
    fn live_parity_with_python() {
        use super::parity_harness as harness;
        let mut py = harness::PyModule::spawn("memory", "mem_stats");
        let mut rs = MemStats::new(&toml::Table::new()).unwrap();
        // Absolute values that the kernel changes constantly (AnonPages,
        // Dirty...): each must match exactly in at least one of several
        // back-to-back reads, and be close in all of them.
        let names = rs.names();
        let mut exact = vec![false; names.len()];
        for round in 0..10 {
            rs.sample(harness::now());
            let p = py.sample();
            let r = harness::rust_values(&rs);
            for (i, n) in names.iter().enumerate() {
                let (rv, pv) = (r[n], p[n]);
                eprintln!("round {round} {n:22} rust {rv:16.0} python {pv:16.0}");
                assert!(harness::close(rv, pv, 4.0 * 1024.0 * 1024.0, 0.01), "{n}: {rv} vs {pv}");
                exact[i] |= rv == pv;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        for (n, ok) in names.iter().zip(exact) {
            assert!(ok, "{n} never matched exactly");
        }
    }
}
