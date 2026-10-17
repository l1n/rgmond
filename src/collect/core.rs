//! gmond's built-in metrics (core_metrics + libmetrics/linux/metrics.c:
//! cpu, load, mem, net, proc, sys, disk modules), with the same arithmetic.

use super::{Reading, Source};
use std::collections::HashMap;

const NAMES: &[&str] = &[
    "heartbeat", "gexec", "location",
    "cpu_num", "cpu_speed", "cpu_user", "cpu_nice", "cpu_system", "cpu_idle", "cpu_aidle",
    "cpu_wio", "cpu_intr", "cpu_sintr", "cpu_steal",
    "load_one", "load_five", "load_fifteen", "proc_run", "proc_total",
    "mem_total", "mem_free", "mem_shared", "mem_buffers", "mem_cached", "swap_total", "swap_free",
    "boottime", "machine_type", "os_name", "os_release",
    "bytes_in", "bytes_out", "pkts_in", "pkts_out",
    "disk_free", "disk_total", "part_max_used",
];

/// The "cpu" line of /proc/stat: user nice system idle iowait irq softirq steal.
#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub struct Jiffies([f64; 8]);

impl Jiffies {
    pub fn parse(stat: &str) -> Option<Jiffies> {
        let line = stat.lines().find(|l| l.starts_with("cpu "))?;
        let mut j = [0.0; 8];
        for (i, v) in line.split_whitespace().skip(1).take(8).enumerate() {
            j[i] = v.parse().ok()?;
        }
        Some(Jiffies(j))
    }

    /// total_jiffies_func on a 2.6.11+ kernel: all eight states.
    fn total(&self) -> f64 {
        self.0.iter().sum()
    }
}

/// sanityCheck(): clamp to [0, 100].
fn clamp_pct(v: f64) -> f64 {
    v.clamp(0.0, 100.0)
}

/// Per-state CPU percentages between two snapshots, as cpu_*_func compute them.
/// `system` includes irq and softirq, exactly as libmetrics does.
pub fn cpu_pcts(last: &Jiffies, now: &Jiffies) -> HashMap<&'static str, f64> {
    let dt = now.total() - last.total();
    let pct = |d: f64| if d != 0.0 { clamp_pct(d / dt * 100.0) } else { 0.0 };
    let d = |i: usize| now.0[i] - last.0[i];
    let mut m = HashMap::new();
    m.insert("cpu_user", pct(d(0)));
    m.insert("cpu_nice", pct(d(1)));
    m.insert("cpu_system", pct(d(2) + d(5) + d(6)));
    m.insert("cpu_idle", pct(d(3)));
    m.insert("cpu_wio", pct(d(4)));
    m.insert("cpu_intr", pct(d(5)));
    m.insert("cpu_sintr", pct(d(6)));
    // cpu_steal_func skips sanityCheck.
    m.insert("cpu_steal", if d(7) != 0.0 { d(7) / dt * 100.0 } else { 0.0 });
    m
}

/// strstr(meminfo, key) then atof of the next token: first occurrence of the
/// key anywhere in the text (so "Cached:" matches the Cached line, which
/// comes before SwapCached).
fn meminfo(text: &str, key: &str) -> f64 {
    text.find(key)
        .and_then(|i| text[i + key.len()..].split_whitespace().next())
        .and_then(|t| t.parse().ok())
        .unwrap_or(0.0)
}

/// /proc/net/dev totals over interfaces gmond counts: everything except names
/// starting with "lo" or "bond", and VLAN interfaces.
pub fn netdev_totals(text: &str, is_vlan: &dyn Fn(&str) -> bool) -> HashMap<String, [u64; 4]> {
    let mut m = HashMap::new();
    for line in text.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else { continue };
        let name = name.trim();
        if name.starts_with("lo") || name.starts_with("bond") || is_vlan(name) {
            continue;
        }
        let f: Vec<u64> = rest.split_whitespace().filter_map(|t| t.parse().ok()).collect();
        if f.len() >= 10 {
            // rbytes rpkts ... tbytes(8) tpkts(9)
            m.insert(name.to_string(), [f[0], f[1], f[8], f[9]]);
        }
    }
    m
}

fn is_vlan(name: &str) -> bool {
    // libmetrics asks SIOCGIFVLAN; the kernel lists VLAN devices here.
    std::fs::read_to_string("/proc/net/vlan/config")
        .map(|t| t.lines().skip(2).any(|l| l.split('|').next().map(str::trim) == Some(name)))
        .unwrap_or(false)
}

/// find_disk_space(): (total GB, free GB, max % used) over local writable
/// /dev/ mounts, each device counted once. Units are 1e9 bytes.
fn disk_space(mounts: &str) -> (f64, f64, f32) {
    let mut seen = std::collections::HashSet::new();
    let (mut total, mut free, mut max) = (0.0f64, 0.0f64, 0.0f32);
    for line in mounts.lines() {
        let f: Vec<&str> = line.splitn(5, ' ').collect();
        if f.len() < 4 {
            continue;
        }
        let (device, mount, fstype, mode) = (f[0], f[1], f[2], f[3]);
        if mode.starts_with("ro") {
            continue;
        }
        let remote = device.contains(':')
            || (fstype == "smbfs" && device.starts_with("//"))
            || fstype.starts_with("nfs")
            || matches!(fstype, "autofs" | "gfs" | "none");
        if remote || !(device.starts_with("/dev/") || device.starts_with("/dev2/")) {
            continue;
        }
        if !seen.insert(device.to_string()) {
            continue;
        }
        // C passes the path still octal-escaped, so such mounts fail statvfs and are skipped.
        let Some(sv) = statvfs(mount) else { continue };
        let (size, avail, bsize) = (sv.0 as f64, sv.1 as f64, sv.2 as f64);
        total += size * bsize;
        free += avail * bsize;
        let pct = if size != 0.0 { ((size - avail) / size * 100.0) as f32 } else { 0.0 };
        if max == 0.0 || max < pct {
            max = pct;
        }
    }
    (total / 1e9, free / 1e9, max)
}

/// (f_blocks, f_bavail, f_bsize)
fn statvfs(path: &str) -> Option<(u64, u64, u64)> {
    let c = std::ffi::CString::new(path).ok()?;
    let mut sv: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut sv) } != 0 {
        return None;
    }
    Some((sv.f_blocks as u64, sv.f_bavail as u64, sv.f_bsize as u64))
}

pub struct Core {
    started: u32,
    location: Option<String>,
    cpu_speed: u32,
    os_release: String,
    /// Each cpu_* metric keeps its own previous snapshot (a static in each C function).
    last_jiffies: HashMap<&'static str, Jiffies>,
    last_net: Option<(f64, HashMap<String, [u64; 4]>)>,
    values: HashMap<&'static str, Reading>,
}

impl Core {
    pub fn new(started: u32, location: Option<String>) -> Core {
        // cpu_speed_func: scaling_max_freq (kHz) if present, else "cpu MHz" from cpuinfo.
        let cpu_speed = std::fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|k| (k / 1000) as u32)
            .filter(|&v| v != 0)
            .or_else(|| {
                let ci = std::fs::read_to_string("/proc/cpuinfo").ok()?;
                let i = ci.find("cpu MHz")?;
                let after = ci[i..].split_once(':')?.1.trim_start();
                let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
                digits.parse().ok()
            })
            .unwrap_or(0);
        let os_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim_end_matches('\n').to_string())
            .unwrap_or_default();
        let mut c = Core {
            started,
            location,
            cpu_speed,
            os_release,
            last_jiffies: HashMap::new(),
            last_net: None,
            values: HashMap::new(),
        };
        // metric_init primes the interface counters. The first cpu deltas are
        // against zero jiffies, exactly like the zero-initialised C statics.
        c.sample_net(crate::store::now_micros() as f64 / 1e6);
        c
    }

    fn sample_net(&mut self, now: f64) {
        let Ok(text) = std::fs::read_to_string("/proc/net/dev") else { return };
        let cur = netdev_totals(&text, &is_vlan);
        if let Some((t0, prev)) = &self.last_net {
            let dt = now - t0;
            // proc_net_dev.thresh: a delta-t under 1 s is "dubious" and skipped.
            if dt < 1.0 {
                return;
            }
            let mut d = [0f64; 4];
            for (name, c) in &cur {
                let p = prev.get(name).copied().unwrap_or([0; 4]);
                for k in 0..4 {
                    d[k] += if c[k] >= p[k] { (c[k] - p[k]) as f64 } else { (u64::MAX - p[k] + c[k]) as f64 };
                }
            }
            let r = d.map(|x| x / dt);
            if !(r[0] > 1e13 || r[2] > 1e13 || r[1] > 1e8 || r[3] > 1e8) {
                self.values.insert("bytes_in", Reading::Num(r[0]));
                self.values.insert("pkts_in", Reading::Num(r[1]));
                self.values.insert("bytes_out", Reading::Num(r[2]));
                self.values.insert("pkts_out", Reading::Num(r[3]));
            }
        } else {
            for k in ["bytes_in", "pkts_in", "bytes_out", "pkts_out"] {
                self.values.insert(k, Reading::Num(0.0));
            }
        }
        self.last_net = Some((now, cur));
    }
}

impl Source for Core {
    fn name(&self) -> &'static str {
        "core"
    }

    fn names(&self) -> Vec<String> {
        NAMES.iter().map(|s| s.to_string()).collect()
    }

    fn sample(&mut self, now: f64) {
        let all: Vec<&str> = NAMES.to_vec();
        self.sample_for(now, &all);
    }

    fn sample_for(&mut self, now: f64, names: &[&str]) {
        let wants = |n: &str| names.contains(&n);
        let v = &mut self.values;
        v.insert("heartbeat", Reading::Num(self.started as f64));
        v.insert("gexec", Reading::Str("OFF".into()));
        if let Some(l) = &self.location {
            v.insert("location", Reading::Str(l.clone()));
        }
        v.insert("cpu_num", Reading::Num(unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) } as f64));
        v.insert("cpu_speed", Reading::Num(self.cpu_speed as f64));
        v.insert("machine_type", Reading::Str(std::env::consts::ARCH.into()));
        v.insert("os_name", Reading::Str("Linux".into()));
        v.insert("os_release", Reading::Str(self.os_release.clone()));

        if let Ok(stat) = std::fs::read_to_string("/proc/stat") {
            if let Some(j) = Jiffies::parse(&stat) {
                for (k, _) in cpu_pcts(&j, &j) {
                    if !wants(k) {
                        continue;
                    }
                    let last = self.last_jiffies.get(k).copied().unwrap_or_default();
                    v.insert(k, Reading::Num(cpu_pcts(&last, &j)[k]));
                    self.last_jiffies.insert(k, j);
                }
                let total = j.total();
                v.insert("cpu_aidle", Reading::Num(if total > 0.0 { clamp_pct(j.0[3] / total * 100.0) } else { 0.0 }));
            }
            if let Some(b) = stat.lines().find_map(|l| l.strip_prefix("btime ")) {
                v.insert("boottime", Reading::Num(b.trim().parse().unwrap_or(0.0)));
            }
        }
        if let Ok(la) = std::fs::read_to_string("/proc/loadavg") {
            let f: Vec<&str> = la.split_whitespace().collect();
            let num = |i: usize| f.get(i).and_then(|t| t.parse::<f64>().ok()).unwrap_or(0.0);
            v.insert("load_one", Reading::Num(num(0)));
            v.insert("load_five", Reading::Num(num(1)));
            v.insert("load_fifteen", Reading::Num(num(2)));
            if let Some((run, total)) = f.get(3).and_then(|t| t.split_once('/')) {
                let run: i64 = run.parse().unwrap_or(0);
                v.insert("proc_run", Reading::Num((run - 1).max(0) as f64));
                v.insert("proc_total", Reading::Num(total.parse().unwrap_or(0.0)));
            }
        }
        if let Ok(mi) = std::fs::read_to_string("/proc/meminfo") {
            for (k, key) in [
                ("mem_total", "MemTotal:"),
                ("mem_free", "MemFree:"),
                ("mem_shared", "MemShared:"),
                ("mem_buffers", "Buffers:"),
                ("mem_cached", "Cached:"),
                ("swap_total", "SwapTotal:"),
                ("swap_free", "SwapFree:"),
            ] {
                v.insert(k, Reading::Num(meminfo(&mi, key)));
            }
        }
        if let Ok(m) = std::fs::read_to_string("/proc/mounts") {
            let (total, free, max) = disk_space(&m);
            v.insert("disk_total", Reading::Num(total));
            v.insert("disk_free", Reading::Num(free));
            v.insert("part_max_used", Reading::Num(max as f64));
        }
        if ["bytes_in", "bytes_out", "pkts_in", "pkts_out"].iter().any(|n| wants(n)) {
            self.sample_net(now);
        }
    }

    fn value(&self, name: &str) -> Option<Reading> {
        self.values.get(name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_includes_irq_and_softirq() {
        let a = Jiffies([100.0, 0.0, 50.0, 800.0, 10.0, 5.0, 5.0, 30.0]);
        let b = Jiffies([200.0, 0.0, 100.0, 1600.0, 20.0, 10.0, 10.0, 60.0]);
        let p = cpu_pcts(&a, &b);
        // dt = 1000
        assert_eq!(p["cpu_user"], 10.0);
        assert_eq!(p["cpu_system"], 6.0);
        assert_eq!(p["cpu_idle"], 80.0);
        assert_eq!(p["cpu_steal"], 3.0);
    }

    #[test]
    fn meminfo_uses_first_match() {
        let t = "MemTotal:       32842056 kB\nCached:         23584000 kB\nSwapCached:            0 kB\n";
        assert_eq!(meminfo(t, "Cached:"), 23584000.0);
        assert_eq!(meminfo(t, "MemShared:"), 0.0);
    }

    #[test]
    fn netdev_skips_lo_and_bond() {
        let t = "Inter-|   Receive\n face |bytes\n    lo: 10 1 0 0 0 0 0 0 10 1 0 0 0 0 0 0\n  eth0: 100 2 0 0 0 0 0 0 300 4 0 0 0 0 0 0\nbond0: 5 5 0 0 0 0 0 0 5 5 0 0 0 0 0 0\n";
        let m = netdev_totals(t, &|_| false);
        assert_eq!(m.len(), 1);
        assert_eq!(m["eth0"], [100, 2, 300, 4]);
    }
}
