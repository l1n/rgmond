//! Pressure stall information (/proc/pressure). New in rgmond.
//!
//! Each metric is the percentage of wall time over the last collection
//! interval in which some (or all, "full") runnable tasks were stalled on the
//! resource, computed from the kernel's cumulative `total=` microseconds. That
//! is exact over the interval, unlike the kernel's smoothed avg10.

use super::{Reading, Source};
use std::collections::HashMap;

const SERIES: &[(&str, &str)] =
    &[("cpu", "some"), ("memory", "some"), ("memory", "full"), ("io", "some"), ("io", "full"), ("irq", "full")];

pub struct Pressure {
    last: HashMap<String, (f64, u64)>,
    values: HashMap<String, Reading>,
}

/// `total=` of the given line kind in a /proc/pressure file.
pub fn total(text: &str, kind: &str) -> Option<u64> {
    let line = text.lines().find(|l| l.starts_with(kind))?;
    line.split_whitespace().find_map(|f| f.strip_prefix("total=")).and_then(|v| v.parse().ok())
}

impl Pressure {
    pub fn new(_params: &toml::Table) -> anyhow::Result<Pressure> {
        anyhow::ensure!(std::path::Path::new("/proc/pressure/cpu").exists(), "kernel has no PSI (/proc/pressure)");
        Ok(Pressure { last: HashMap::new(), values: HashMap::new() })
    }
}

impl Source for Pressure {
    fn name(&self) -> &'static str {
        "pressure"
    }

    fn names(&self) -> Vec<String> {
        SERIES.iter().map(|(r, k)| format!("psi_{r}_{k}")).collect()
    }

    fn sample(&mut self, now: f64) {
        for (res, kind) in SERIES {
            let name = format!("psi_{res}_{kind}");
            let Some(t) = std::fs::read_to_string(format!("/proc/pressure/{res}")).ok().and_then(|x| total(&x, kind))
            else {
                continue;
            };
            let pct = match self.last.get(&name) {
                Some(&(t0, v0)) if now > t0 => (t.saturating_sub(v0) as f64 / 1e6) / (now - t0) * 100.0,
                _ => 0.0,
            };
            self.last.insert(name.clone(), (now, t));
            self.values.insert(name, Reading::Num(pct.clamp(0.0, 100.0)));
        }
    }

    fn value(&self, name: &str) -> Option<Reading> {
        self.values.get(name).cloned()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_totals() {
        let t = "some avg10=0.00 avg60=0.00 avg300=0.00 total=109840864\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=108961062\n";
        assert_eq!(super::total(t, "some"), Some(109840864));
        assert_eq!(super::total(t, "full"), Some(108961062));
    }
}
