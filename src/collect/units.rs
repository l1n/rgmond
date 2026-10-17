//! Per-systemd-unit resource use from cgroup v2. New in rgmond; replaces the
//! idea behind procstat (one process found by regex) with whole services.
//!
//! params: units = "nginx postfix dovecot" (".service" is implied when no
//! suffix is given). Metrics per unit (name with '-' and '.' as '_'):
//!   unit_<u>_cpu    percent of one CPU over the interval (cpu.stat usage_usec)
//!   unit_<u>_mem    bytes charged to the unit (memory.current)
//!   unit_<u>_tasks  number of tasks (pids.current)

use super::{Reading, Source};
use std::collections::HashMap;

pub struct Units {
    units: Vec<(String, String)>, // (metric stem, cgroup dir)
    last_cpu: HashMap<String, (f64, u64)>,
    values: HashMap<String, Reading>,
}

fn read_num(path: &str) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn usage_usec(dir: &str) -> Option<u64> {
    let t = std::fs::read_to_string(format!("{dir}/cpu.stat")).ok()?;
    t.lines().find_map(|l| l.strip_prefix("usage_usec ")).and_then(|v| v.trim().parse().ok())
}

impl Units {
    pub fn new(params: &toml::Table) -> anyhow::Result<Units> {
        let list = params.get("units").and_then(|v| v.as_str()).unwrap_or("");
        let units = list
            .split_whitespace()
            .map(|u| {
                let unit = if u.contains('.') { u.to_string() } else { format!("{u}.service") };
                // Template instances (foo@bar.service) live in system-foo.slice.
                let slice = if unit.ends_with(".slice") {
                    String::new()
                } else if let Some((prefix, _)) = unit.split_once('@') {
                    format!("system.slice/system-{prefix}.slice/")
                } else {
                    "system.slice/".into()
                };
                let stem = unit.trim_end_matches(".service").replace(['-', '.', '@'], "_");
                (stem, format!("/sys/fs/cgroup/{slice}{unit}"))
            })
            .collect();
        Ok(Units { units, last_cpu: HashMap::new(), values: HashMap::new() })
    }
}

impl Source for Units {
    fn name(&self) -> &'static str {
        "units"
    }

    fn names(&self) -> Vec<String> {
        self.units
            .iter()
            .flat_map(|(s, _)| [format!("unit_{s}_cpu"), format!("unit_{s}_mem"), format!("unit_{s}_tasks")])
            .collect()
    }

    fn sample(&mut self, now: f64) {
        for (stem, dir) in &self.units {
            // A stopped unit has no cgroup: report zeros rather than going silent.
            let cpu = usage_usec(dir);
            let pct = match (cpu, self.last_cpu.get(stem)) {
                (Some(u), Some(&(t0, u0))) if now > t0 && u >= u0 => (u - u0) as f64 / 1e6 / (now - t0) * 100.0,
                _ => 0.0,
            };
            match cpu {
                Some(u) => {
                    self.last_cpu.insert(stem.clone(), (now, u));
                }
                None => {
                    self.last_cpu.remove(stem);
                }
            }
            self.values.insert(format!("unit_{stem}_cpu"), Reading::Num(pct));
            let mem = read_num(&format!("{dir}/memory.current")).unwrap_or(0);
            self.values.insert(format!("unit_{stem}_mem"), Reading::Num(mem as f64));
            let tasks = read_num(&format!("{dir}/pids.current")).unwrap_or(0);
            self.values.insert(format!("unit_{stem}_tasks"), Reading::Num(tasks as f64));
        }
    }

    fn value(&self, name: &str) -> Option<Reading> {
        self.values.get(name).cloned()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn cgroup_paths() {
        let mut p = toml::Table::new();
        p.insert("units".into(), "nginx gmond@agg user.slice".into());
        let u = super::Units::new(&p).unwrap();
        let dirs: Vec<&str> = u.units.iter().map(|(_, d)| d.as_str()).collect();
        assert_eq!(
            dirs,
            [
                "/sys/fs/cgroup/system.slice/nginx.service",
                "/sys/fs/cgroup/system.slice/system-gmond.slice/gmond@agg.service",
                "/sys/fs/cgroup/user.slice",
            ]
        );
        assert_eq!(u.units[1].0, "gmond_agg");
    }
}
