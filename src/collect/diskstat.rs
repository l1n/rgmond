//! Port of Ganglia's `disk/diskstat.py`: per-device I/O statistics from
//! /proc/diskstats, named `diskstat_<dev>_<label>`.
//!
//! The Python module's semantics are kept on purpose, including the odd ones:
//! * `reads`, `writes`, `reads_merged`, `writes_merged` are plain differences
//!   between two updates (not rates); a negative difference becomes 0.
//! * `io_time` is a difference too, converted from ms to seconds, and
//!   `percent_io_time` is `io_time / interval * 100`.
//! * `read_bytes_per_sec`, `write_bytes_per_sec`, `read_time`, `write_time`
//!   and `weighted_io_time` are deltas divided by the interval; a counter that
//!   went backwards is assumed to have wrapped at 32 bits, and the stored
//!   previous value then keeps the added 2^32 (as the Python does).
//! * Every value is 0 on the first update, which happens at construction
//!   (the Python calls `update_stats()` from `metric_init`).
//! * Updates are cached for MAX_UPDATE_TIME (15 s) after the last one.
//! * Device discovery: base devices from /proc/partitions (names not ending
//!   in a digit, or containing "md"), larger than MIN_DISK_SIZE KiB per
//!   /sys/block/<dev>/size. IGNORE_DEV is defined in the Python but never
//!   used, so it is not applied here either. A `devices` param, even an empty
//!   one, disables the size check; a non-empty one replaces discovery.
#![allow(dead_code)] // until the scheduler wires sources in

use super::{Reading, Source};
use anyhow::{Context, Result, bail};
use regex::Regex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const MAX_UPDATE_TIME: f64 = 15.0;
const BYTES_PER_SECTOR: f64 = 512.0;
/// 5 GB, in KiB.
const MIN_DISK_SIZE: f64 = 5242880.0;

/// Labels in the order the Python's `descriptions` dict yields them.
const LABELS: [&str; 11] = [
    "reads",
    "reads_merged",
    "read_bytes_per_sec",
    "read_time",
    "writes",
    "writes_merged",
    "write_bytes_per_sec",
    "write_time",
    "io_time",
    "percent_io_time",
    "weighted_io_time",
];

pub struct Diskstat {
    root: PathBuf,
    partitions: Vec<String>,
    last_update: f64,
    cur_time: f64,
    /// Keyed by device name with '/' replaced by '-', as in the Python.
    stats: HashMap<String, HashMap<&'static str, f64>>,
    last_val: HashMap<String, HashMap<&'static str, f64>>,
}

/// A .pyconf param as the string gmond would hand the Python module.
pub(crate) fn param_str(params: &toml::Table, key: &str) -> Option<String> {
    params.get(key).map(|v| match v {
        toml::Value::String(s) => s.clone(),
        other => other.to_string(),
    })
}

impl Diskstat {
    pub fn new(params: &toml::Table) -> Result<Self> {
        Self::new_at(params, Path::new("/"), wall_now())
    }

    /// `root` prefixes /proc and /sys (for tests); `now` is the init time.
    pub(crate) fn new_at(params: &toml::Table, root: &Path, now: f64) -> Result<Self> {
        if param_str(params, "device-mapper").as_deref() == Some("true") {
            // The Python builds its dev table from every /proc/partitions line,
            // and the blank line after the header makes `(maj, min, name) =
            // line.split()[:3]` raise, so metric_init fails in this mode.
            bail!("diskstat: device-mapper mode fails in the Python module (blank /proc/partitions line); not supported");
        }
        let devices = param_str(params, "devices");
        let partitions = get_partitions(root, devices.as_deref())?;
        let mut me = Diskstat {
            root: root.to_path_buf(),
            partitions,
            last_update: 0.0,
            cur_time: 0.0,
            stats: HashMap::new(),
            last_val: HashMap::new(),
        };
        me.update_stats(now)?;
        // metric_init indexes stats[dev] with the unreplaced name.
        for dev in &me.partitions {
            if !me.stats.contains_key(dev) {
                bail!("diskstat: KeyError {dev:?} in metric_init (device name contains '/')");
            }
        }
        Ok(me)
    }

    fn update_stats(&mut self, now: f64) -> Result<()> {
        self.cur_time = now;
        if self.cur_time - self.last_update < MAX_UPDATE_TIME {
            return Ok(());
        }
        self.stats.clear();
        let text = std::fs::read_to_string(self.root.join("proc/diskstats"))
            .context("reading /proc/diskstats")?;
        // `vals` deliberately outlives one device: the Python reuses the
        // previous device's line when a device is missing from diskstats.
        let mut vals: Option<Vec<&str>> = None;
        for raw in self.partitions.clone() {
            let dev = raw.replace('/', "-");
            self.stats.entry(dev.clone()).or_default();
            self.last_val.entry(dev.clone()).or_default();
            for line in text.lines() {
                let f: Vec<&str> = line.split_whitespace().collect();
                if f.contains(&dev.as_str()) {
                    vals = Some(f);
                }
            }
            let Some(v) = vals.as_ref() else {
                bail!("diskstat: {dev} not in /proc/diskstats (NameError in the Python)");
            };
            let int = |i: usize| -> Result<f64> {
                let s = v.get(i).context("short diskstats line")?;
                Ok(s.parse::<i64>().with_context(|| format!("bad diskstats field {s:?}"))? as f64)
            };
            let (r, w, rm, wm) = (int(3)?, int(7)?, int(4)?, int(8)?);
            let (rs, ws, rt, wt) = (int(5)?, int(9)?, int(6)?, int(10)?);
            let (io, wio) = (int(12)?, int(13)?);
            self.get_diff(&dev, "reads", r, 1.0);
            self.get_diff(&dev, "writes", w, 1.0);
            self.get_diff(&dev, "reads_merged", rm, 1.0);
            self.get_diff(&dev, "writes_merged", wm, 1.0);
            self.get_delta(&dev, "read_bytes_per_sec", rs, BYTES_PER_SECTOR);
            self.get_delta(&dev, "write_bytes_per_sec", ws, BYTES_PER_SECTOR);
            self.get_delta(&dev, "read_time", rt, 0.001);
            self.get_delta(&dev, "write_time", wt, 0.001);
            self.get_diff(&dev, "io_time", io, 0.001);
            let io_time = self.stats[&dev]["io_time"];
            self.get_percent_time(&dev, "percent_io_time", io_time);
            self.get_delta(&dev, "weighted_io_time", wio, 0.001);
        }
        self.last_update = self.cur_time;
        Ok(())
    }

    fn get_delta(&mut self, dev: &str, key: &'static str, mut val: f64, convert: f64) {
        let interval = self.cur_time - self.last_update;
        let last = self.last_val.get_mut(dev).unwrap();
        let out = match last.get(key) {
            Some(&prev) if interval > 0.0 => {
                if val < prev {
                    val += 4294967296.0;
                }
                (val - prev) * convert / interval
            }
            _ => 0.0,
        };
        last.insert(key, val.trunc());
        self.stats.get_mut(dev).unwrap().insert(key, out);
    }

    fn get_percent_time(&mut self, dev: &str, key: &'static str, val: f64) {
        let interval = self.cur_time - self.last_update;
        let out = if interval > 0.0 { val / interval * 100.0 } else { 0.0 };
        self.stats.get_mut(dev).unwrap().insert(key, out);
    }

    fn get_diff(&mut self, dev: &str, key: &'static str, val: f64, convert: f64) {
        let last = self.last_val.get_mut(dev).unwrap();
        let mut out = match last.get(key) {
            Some(&prev) => (val - prev) * convert,
            None => 0.0,
        };
        if out < 0.0 {
            out = 0.0;
        }
        last.insert(key, val);
        self.stats.get_mut(dev).unwrap().insert(key, out);
    }
}

fn get_partitions(root: &Path, devices: Option<&str>) -> Result<Vec<String>> {
    let out: Vec<String> = match devices {
        Some(d) if !d.is_empty() => d.split_whitespace().map(String::from).collect(),
        _ => {
            let text = std::fs::read_to_string(root.join("proc/partitions"))
                .context("reading /proc/partitions")?;
            let has_num = Regex::new(r"(\w+)?\d+").unwrap();
            let mut v = Vec::new();
            for line in text.lines() {
                if !has_num.is_match(line) {
                    continue;
                }
                let name = line
                    .split_whitespace()
                    .nth(3)
                    .with_context(|| format!("short /proc/partitions line {line:?}"))?;
                let ends_digit = name.chars().last().is_some_and(|c| c.is_ascii_digit());
                if name.contains("md") || !ends_digit {
                    v.push(name.to_string());
                }
            }
            v
        }
    };
    let mut parts = Vec::new();
    for dev in out {
        if devices.is_some() {
            parts.push(dev);
        } else {
            let p = root.join("sys/block").join(&dev).join("size");
            let s = std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
            let sectors: i64 = s.trim().parse().with_context(|| format!("bad {}", p.display()))?;
            if sectors as f64 * BYTES_PER_SECTOR / 1024.0 > MIN_DISK_SIZE {
                parts.push(dev);
            }
        }
    }
    Ok(parts)
}

pub(crate) fn wall_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

impl Source for Diskstat {
    fn name(&self) -> &'static str {
        "diskstat"
    }

    fn names(&self) -> Vec<String> {
        LABELS
            .iter()
            .flat_map(|l| self.partitions.iter().map(move |d| format!("diskstat_{d}_{l}")))
            .collect()
    }

    fn sample(&mut self, now: f64) {
        if let Err(e) = self.update_stats(now) {
            log::warn!("diskstat: {e:#}");
        }
    }

    fn value(&self, name: &str) -> Option<Reading> {
        // get_stat: the device is between the first and second underscore;
        // any lookup failure is reported as 0.
        let rest = name.strip_prefix("diskstat_")?;
        let (dev, label) = rest.split_once('_').unwrap_or((rest, ""));
        let v = self.stats.get(dev).and_then(|m| m.get(label)).copied().unwrap_or(0.0);
        Some(Reading::Num(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARTITIONS: &str = "major minor  #blocks  name

   1        0      16384 ram0
   1       15      16384 ram15
   8        0  670826496 sda
   8       16     266240 sdb
   8       32  125829120 sdc
   9        0   20971520 md0
 254        0   20971520 dm-0
";

    fn diskstats(sda: [u64; 11]) -> String {
        format!(
            "   1       0 ram0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
   8       0 sda {} {} {} {} {} {} {} {} 0 {} {} 0 0 0 0 4979050 432594
   8      16 sdb 41540 13097 438560 8715 24684 99338 1106640 582190 0 30098 590906 0 0 0 0 0 0
   8      32 sdc 183963 11272 17065218 365095 37301 53472 9660040 82267 0 142974 488552 0 0 0 0 3109 41189
   9       0 md0 1 2 3 4 5 6 7 8 0 9 10 0 0 0 0 0 0
",
            sda[0], sda[1], sda[2], sda[3], sda[4], sda[5], sda[6], sda[7], sda[8], sda[9]
        )
    }

    fn fixture(sda: [u64; 11]) -> tempdir::Dir {
        let d = tempdir::Dir::new("diskstat");
        d.write("proc/partitions", PARTITIONS);
        d.write("proc/diskstats", &diskstats(sda));
        for (dev, size) in [("sda", 1341652992u64), ("sdb", 532480), ("sdc", 251658240), ("md0", 41943040)] {
            d.write(&format!("sys/block/{dev}/size"), &format!("{size}\n"));
        }
        d
    }

    const BASE: [u64; 11] = [98901205, 8391638, 6220270206, 25532641, 156312919, 180964146, 6739982827, 275108576, 28302339, 301073812, 0];

    #[test]
    fn discovery_follows_partitions_and_size() {
        let d = fixture(BASE);
        let s = Diskstat::new_at(&toml::Table::new(), d.path(), 1000.0).unwrap();
        // ram* end in a digit, sdb is too small, dm-0 ends in a digit; md0 kept.
        assert_eq!(s.partitions, ["sda", "sdc", "md0"]);
        assert_eq!(s.names().len(), 33);
        assert_eq!(s.names()[0], "diskstat_sda_reads");
        assert_eq!(s.names()[32], "diskstat_md0_weighted_io_time");
    }

    #[test]
    fn devices_param() {
        let d = fixture(BASE);
        let mut p = toml::Table::new();
        p.insert("devices".into(), "sdb sda".into());
        let s = Diskstat::new_at(&p, d.path(), 1000.0).unwrap();
        assert_eq!(s.partitions, ["sdb", "sda"]);
        // An empty devices param still discovers, but skips the size check.
        p.insert("devices".into(), "".into());
        let s = Diskstat::new_at(&p, d.path(), 1000.0).unwrap();
        assert_eq!(s.partitions, ["sda", "sdb", "sdc", "md0"]);
        p.insert("device-mapper".into(), "true".into());
        assert!(Diskstat::new_at(&p, d.path(), 1000.0).is_err());
    }

    #[test]
    fn diffs_deltas_cache_and_wrap() {
        let d = fixture(BASE);
        let mut s = Diskstat::new_at(&toml::Table::new(), d.path(), 1000.0).unwrap();
        let v = |s: &Diskstat, n: &str| match s.value(n) {
            Some(Reading::Num(x)) => x,
            o => panic!("{o:?}"),
        };
        for l in LABELS {
            assert_eq!(v(&s, &format!("diskstat_sda_{l}")), 0.0);
        }
        let mut next = BASE;
        next[0] += 14; // reads
        next[1] += 3; // reads merged
        next[2] += 630; // sectors read
        next[3] += 40; // ms reading
        next[4] += 1505; // writes
        next[5] += 323;
        next[6] += 27000; // sectors written
        next[7] = 100; // ms writing went backwards: 32-bit wrap
        next[8] += 59; // ms doing I/O
        next[9] += 300; // weighted ms
        d.write("proc/diskstats", &diskstats(next));
        s.sample(1010.0); // within 15 s: cached
        assert_eq!(v(&s, "diskstat_sda_reads"), 0.0);
        s.sample(1020.0);
        assert_eq!(v(&s, "diskstat_sda_reads"), 14.0);
        assert_eq!(v(&s, "diskstat_sda_reads_merged"), 3.0);
        assert_eq!(v(&s, "diskstat_sda_writes"), 1505.0);
        assert_eq!(v(&s, "diskstat_sda_writes_merged"), 323.0);
        assert_eq!(v(&s, "diskstat_sda_read_bytes_per_sec"), 630.0 * 512.0 / 20.0);
        assert_eq!(v(&s, "diskstat_sda_write_bytes_per_sec"), 27000.0 * 512.0 / 20.0);
        assert_eq!(v(&s, "diskstat_sda_read_time"), 40.0 * 0.001 / 20.0);
        let wrapped = (100.0 + 4294967296.0 - 275108576.0) * 0.001 / 20.0;
        assert_eq!(v(&s, "diskstat_sda_write_time"), wrapped);
        assert!((v(&s, "diskstat_sda_io_time") - 0.059).abs() < 1e-12);
        assert!((v(&s, "diskstat_sda_percent_io_time") - 0.059 / 20.0 * 100.0).abs() < 1e-12);
        assert_eq!(v(&s, "diskstat_sda_weighted_io_time"), 300.0 * 0.001 / 20.0);
        // The wrapped value is stored with 2^32 added, so later readings are
        // all "wrapped" again and the deltas stay consistent (Python quirk).
        s.sample(1040.0);
        assert_eq!(v(&s, "diskstat_sda_reads"), 0.0);
        assert_eq!(v(&s, "diskstat_sda_write_time"), 0.0);
        // Diffs that go negative are clamped to 0.
        d.write("proc/diskstats", &diskstats(BASE));
        s.sample(1060.0);
        assert_eq!(v(&s, "diskstat_sda_reads"), 0.0);
        // Unknown names read as 0 like get_stat's except branch.
        assert_eq!(v(&s, "diskstat_sdz_reads"), 0.0);
    }
}

#[cfg(test)]
mod live {
    use super::parity::{Py, close, num, sorted};
    use super::*;

    /// cargo test -- --ignored diskstat: the port and disk/diskstat.py with
    /// the live diskstat.pyconf (no params), sampled over the same interval.
    #[test]
    #[ignore]
    fn parity_with_python() {
        let mut py = Py::start("disk", "diskstat", &[]);
        let mut ours = Diskstat::new(&toml::Table::new()).unwrap();
        assert_eq!(sorted(ours.names()), sorted(py.names.clone()));
        for n in ours.names() {
            assert!(crate::collect::spec::lookup(&n).is_some(), "{n}: no metadata");
        }
        std::thread::sleep(std::time::Duration::from_secs(16));
        let theirs = py.sample();
        ours.sample(wall_now());
        let mut ok = true;
        for n in ours.names() {
            let label = &n[n.find('_').unwrap() + 1..];
            let label = &label[label.find('_').unwrap() + 1..];
            // Both sides read /proc/diskstats a few ms apart under live I/O.
            let abs = match label {
                "reads" | "writes" | "reads_merged" | "writes_merged" => 5.0,
                "read_bytes_per_sec" | "write_bytes_per_sec" => 5.0 * 4096.0 / 16.0,
                "percent_io_time" => 0.1,
                _ => 0.01,
            };
            ok &= close(&n, num(ours.value(&n)), &theirs[&n], 0.05, abs);
        }
        assert!(ok);
    }
}

#[cfg(test)]
pub(crate) mod tempdir {
    //! Tiny scratch directory for fixture /proc and /sys trees.
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    pub struct Dir(PathBuf);

    impl Dir {
        pub fn new(tag: &str) -> Dir {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/fixtures").join(format!(
                "rgmond-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&p).unwrap();
            Dir(p)
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
        pub fn write(&self, rel: &str, body: &str) {
            let p = self.0.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
pub(crate) mod parity {
    //! Runs a gmond Python module through tools/parity/pymodule.py so the
    //! #[ignore] live tests can sample it at the same moments as the port.
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

    fn module_dir(subdir: &str) -> String {
        // RGMOND_PY_MODULES is a gmond python_modules tree: either the source layout
        // (network/, disk/, ...) or ganglia's flat install directory.
        let base = std::env::var("RGMOND_PY_MODULES").unwrap_or_else(|_| "/usr/lib/ganglia/python_modules".into());
        let nested = format!("{base}/{subdir}");
        if std::path::Path::new(&nested).is_dir() { nested } else { base }
    }

    pub struct Py {
        child: Child,
        stdin: ChildStdin,
        stdout: BufReader<ChildStdout>,
        pub names: Vec<String>,
    }

    impl Py {
        /// Start `<subdir>/<module>.py` and run its metric_init(params).
        pub fn start(subdir: &str, module: &str, params: &[(&str, &str)]) -> Py {
            let dir = module_dir(subdir);
            let json = format!(
                "{{{}}}",
                params.iter().map(|(k, v)| format!("{k:?}: {v:?}")).collect::<Vec<_>>().join(", ")
            );
            let driver = concat!(env!("CARGO_MANIFEST_DIR"), "/tools/parity/pymodule.py");
            let mut child = Command::new("python3")
                .args([driver, &dir, module, &json])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .expect("python3");
            let stdin = child.stdin.take().unwrap();
            let stdout = BufReader::new(child.stdout.take().unwrap());
            let mut py = Py { child, stdin, stdout, names: Vec::new() };
            assert_eq!(py.line(), "READY");
            loop {
                let l = py.line();
                if l == "END" {
                    break;
                }
                py.names.push(l);
            }
            py
        }

        fn line(&mut self) -> String {
            let mut s = String::new();
            assert!(self.stdout.read_line(&mut s).unwrap() > 0, "python driver exited");
            s.trim_end_matches('\n').to_string()
        }

        /// One collection pass: name -> repr(value).
        pub fn sample(&mut self) -> BTreeMap<String, String> {
            writeln!(self.stdin, "sample").unwrap();
            self.stdin.flush().unwrap();
            let mut out = BTreeMap::new();
            loop {
                let l = self.line();
                if l == "END" {
                    return out;
                }
                let (n, v) = l.split_once('\t').unwrap();
                out.insert(n.to_string(), v.to_string());
            }
        }
    }

    impl Drop for Py {
        fn drop(&mut self) {
            let _ = writeln!(self.stdin, "quit");
            let _ = self.child.wait();
        }
    }

    pub fn sorted(mut v: Vec<String>) -> Vec<String> {
        v.sort();
        v
    }

    /// Compare one value; `rel` is a fraction of the larger magnitude, `abs`
    /// an absolute floor. Prints the pair for the test log.
    pub fn close(name: &str, ours: f64, theirs: &str, rel: f64, abs: f64) -> bool {
        let t: f64 = theirs.parse().unwrap_or_else(|_| panic!("{name}: python gave {theirs}"));
        let tol = (rel * ours.abs().max(t.abs())).max(abs);
        let ok = (ours - t).abs() <= tol;
        println!("{} {name}: rust={ours} python={t}", if ok { "ok  " } else { "FAIL" });
        ok
    }

    pub fn num(r: Option<super::Reading>) -> f64 {
        match r {
            Some(super::Reading::Num(x)) => x,
            o => panic!("{o:?}"),
        }
    }
}
