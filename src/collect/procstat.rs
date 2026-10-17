//! Port of Ganglia's `process/procstat.py`: CPU and memory use of a process
//! group, as `procstat_<proc>_cpu` (percent) and `procstat_<proc>_mem` (bytes).
//!
//! Each param `<proc> = <value>` names a process. A value ending in ".pid" is
//! a pidfile; otherwise it is an awk pattern that the Python runs as
//! `ps -Ao pid,ppid,pgid,args | awk '<value> && $2 == 1 && !/awk/ &&
//! !/procstat\.py/'`. Here /proc is scanned directly: each process is turned
//! into the line ps would print and matched the same way. Only a single awk
//! regex literal (`/ERE/`) is supported as the pattern.
//!
//! Semantics kept from the Python:
//! * Metrics exist for every configured process; while the lookup fails (no
//!   match, more than one match, missing pidfile, ...) cpu reads 0.0 and mem 0.
//! * The (ppid, pgid) found is cached while /proc/<ppid> exists.
//! * All processes whose /proc/<pid>/stat field 5 (pgrp) equals the pgid are
//!   summed: cpu jiffies are utime+stime+cutime+cstime, mem is statm rss *
//!   page size. /proc/<pid>/stat is split on whitespace naively, as the
//!   Python does (a comm with spaces shifts the fields).
//! * cpu = 100 * Δjiffies / (Δt * CLK_TCK); 0.0 on the first update.
//! * Updates are cached for MAX_UPDATE_TIME (15 s); the first runs at init.
#![allow(dead_code)] // until the scheduler wires sources in

use super::diskstat::{param_str, wall_now};
use super::{Reading, Source};
use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use std::path::{Path, PathBuf};

const MAX_UPDATE_TIME: f64 = 15.0;

enum Matcher {
    PidFile(String),
    Regex(Regex),
}

struct Proc {
    name: String,
    matcher: Matcher,
    cached: Option<(String, String)>,
    last: Option<(f64, i64)>,
    cpu: f64,
    mem: i64,
}

pub struct Procstat {
    proc_root: PathBuf,
    procs: Vec<Proc>,
    last_update: f64,
    jiffies_per_sec: f64,
    page_size: i64,
}

/// Turn an awk regex literal `/.../` into a Rust regex.
fn awk_regex(val: &str) -> Result<Regex> {
    let inner = val
        .strip_prefix('/')
        .and_then(|s| s.strip_suffix('/'))
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("only a single awk regex literal /.../ or a .pid file is supported, got {val:?}"))?;
    // Inside an awk regex literal, "\/" is a literal slash; any other
    // unescaped '/' would end the literal.
    let mut out = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('/') => out.push('/'),
                Some(n) => {
                    out.push('\\');
                    out.push(n);
                }
                None => bail!("trailing backslash in {val:?}"),
            },
            '/' => bail!("only a single awk regex literal /.../ is supported, got {val:?}"),
            c => out.push(c),
        }
    }
    Regex::new(&out).with_context(|| format!("bad regex {val:?}"))
}

impl Procstat {
    pub fn new(params: &toml::Table) -> Result<Self> {
        // SAFETY: sysconf has no preconditions.
        let (hz, page) = unsafe { (libc::sysconf(libc::_SC_CLK_TCK), libc::sysconf(libc::_SC_PAGESIZE)) };
        Self::new_at(params, Path::new("/proc"), wall_now(), hz as f64, page as i64)
    }

    pub(crate) fn new_at(params: &toml::Table, proc_root: &Path, now: f64, hz: f64, page: i64) -> Result<Self> {
        let mut procs = Vec::new();
        for key in params.keys() {
            let val = param_str(params, key).unwrap_or_default();
            let matcher = if val.ends_with(".pid") {
                Matcher::PidFile(val)
            } else {
                Matcher::Regex(awk_regex(&val).with_context(|| format!("procstat param {key}"))?)
            };
            procs.push(Proc { name: key.clone(), matcher, cached: None, last: None, cpu: 0.0, mem: 0 });
        }
        let mut me = Procstat { proc_root: proc_root.to_path_buf(), procs, last_update: 0.0, jiffies_per_sec: hz, page_size: page };
        me.update_stats(now);
        Ok(me)
    }

    fn update_stats(&mut self, now: f64) {
        if now - self.last_update < MAX_UPDATE_TIME {
            return;
        }
        self.last_update = now;
        let root = self.proc_root.clone();
        for i in 0..self.procs.len() {
            let found = get_pgid(&root, &self.procs[i]);
            let p = &mut self.procs[i];
            let (ppid, pgid) = match found {
                Ok(v) => v,
                Err(e) => {
                    log::debug!("procstat {}: failed getting pgid: {e:#}", p.name);
                    p.cpu = 0.0;
                    p.mem = 0;
                    continue;
                }
            };
            p.cached = Some((ppid.clone(), pgid.clone()));
            let pids = get_pgroup(&root, &ppid, &pgid);
            let cpu_time = now;
            let proc_time: i64 = pids.iter().map(|pid| read_cpu(&root, pid)).sum();
            p.cpu = match p.last {
                Some((t0, j0)) => 100.0 * (proc_time - j0) as f64 / ((cpu_time - t0) * self.jiffies_per_sec),
                None => 0.0,
            };
            p.last = Some((cpu_time, proc_time));
            p.mem = get_rss(&root, &pids) * self.page_size;
        }
    }
}

fn read_first_line(path: &Path) -> std::io::Result<String> {
    let s = std::fs::read_to_string(path)?;
    Ok(s.split_inclusive('\n').next().unwrap_or("").to_string())
}

fn get_pgid(root: &Path, p: &Proc) -> Result<(String, String)> {
    if let Some((ppid, pgid)) = &p.cached {
        if root.join(ppid).exists() {
            return Ok((ppid.clone(), pgid.clone()));
        }
    }
    let (ppid, pgid) = match &p.matcher {
        Matcher::PidFile(f) => {
            if !Path::new(f).exists() {
                bail!("pidfile ({f}) does not exist");
            }
            let ppid = read_first_line(Path::new(f))?.trim().to_string();
            let stat = read_first_line(&root.join(&ppid).join("stat"))?;
            let pgid = stat.split_whitespace().nth(4).context("short stat")?.to_string();
            (ppid, pgid)
        }
        Matcher::Regex(re) => {
            let mut hits = Vec::new();
            for line in ps_lines(root) {
                let ppid_is_1 = line.split_whitespace().nth(1) == Some("1");
                if re.is_match(&line) && ppid_is_1 && !line.contains("awk") && !line.contains("procstat.py") {
                    hits.push(line);
                }
            }
            match hits.len() {
                0 => bail!("no process returned"),
                1 => {}
                _ => bail!("more than 1 result returned\n{}", hits.join("\n")),
            }
            let f: Vec<&str> = hits[0].split_whitespace().collect();
            (f[0].to_string(), f[2].to_string())
        }
    };
    if root.join(&ppid).exists() {
        Ok((ppid, pgid))
    } else {
        bail!("/proc/{ppid} does not exist")
    }
}

/// The lines `ps -Ao pid,ppid,pgid,args` prints (without the header) for
/// every process: right-aligned id columns, then the args column, which is
/// the cmdline with NULs as spaces and control characters as '?', or
/// "[comm]" when the cmdline is empty.
fn ps_lines(root: &Path) -> Vec<String> {
    let width = std::fs::read_to_string(root.join("sys/kernel/pid_max"))
        .map(|s| s.trim().len().max(5))
        .unwrap_or(7);
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(root) else { return out };
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(pid) = name.to_str().filter(|s| s.bytes().all(|b| b.is_ascii_digit())) else { continue };
        let Ok(stat) = std::fs::read_to_string(e.path().join("stat")) else { continue };
        let (Some(lp), Some(rp)) = (stat.find('('), stat.rfind(')')) else { continue };
        let comm = &stat[lp + 1..rp];
        let rest: Vec<&str> = stat[rp + 1..].split_whitespace().collect();
        let (Some(ppid), Some(pgid)) = (rest.get(1), rest.get(2)) else { continue };
        let cmdline = std::fs::read(e.path().join("cmdline")).unwrap_or_default();
        let args = ps_args(&cmdline).unwrap_or_else(|| format!("[{comm}]"));
        out.push(format!("{pid:>width$} {ppid:>width$} {pgid:>width$} {args}"));
    }
    out
}

fn ps_args(cmdline: &[u8]) -> Option<String> {
    let trimmed = cmdline.strip_suffix(b"\0").unwrap_or(cmdline);
    if trimmed.is_empty() {
        return None;
    }
    let s = String::from_utf8_lossy(trimmed);
    Some(s.chars().map(|c| if c == '\0' { ' ' } else if c.is_control() { '?' } else { c }).collect())
}

/// pids in /proc/[1-9]* whose (naively split) stat field 5 equals pgid,
/// with ppid first.
fn get_pgroup(root: &Path, ppid: &str, pgid: &str) -> Vec<String> {
    let mut list = Vec::new();
    if let Ok(rd) = std::fs::read_dir(root) {
        for e in rd.flatten() {
            let name = e.file_name();
            let Some(n) = name.to_str() else { continue };
            if !n.starts_with(|c: char| ('1'..='9').contains(&c)) {
                continue;
            }
            let Ok(line) = read_first_line(&e.path().join("stat")) else { continue };
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() > 4 && f[4] == pgid {
                list.push(f[0].to_string());
            }
        }
    }
    if let Some(i) = list.iter().position(|p| p == ppid) {
        let p = list.remove(i);
        list.insert(0, p);
    }
    list
}

/// utime+stime+cutime+cstime from a naively split stat; 0 on any failure.
fn read_cpu(root: &Path, pid: &str) -> i64 {
    let Ok(line) = read_first_line(&root.join(pid).join("stat")) else { return 0 };
    let f: Vec<&str> = line.split_whitespace().collect();
    let get = |i: usize| f.get(i).and_then(|s| s.parse::<i64>().ok());
    match (get(13), get(14), get(15), get(16)) {
        (Some(a), Some(b), Some(c), Some(d)) => a + b + c + d,
        _ => 0,
    }
}

fn get_rss(root: &Path, pids: &[String]) -> i64 {
    pids.iter()
        .filter_map(|p| read_first_line(&root.join(p).join("statm")).ok())
        .filter_map(|l| l.split_whitespace().nth(1).and_then(|s| s.parse::<i64>().ok()))
        .sum()
}

impl Source for Procstat {
    fn name(&self) -> &'static str {
        "procstat"
    }

    fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.procs.iter().map(|p| format!("procstat_{}_cpu", p.name)).collect();
        v.extend(self.procs.iter().map(|p| format!("procstat_{}_mem", p.name)));
        v
    }

    fn sample(&mut self, now: f64) {
        self.update_stats(now);
    }

    fn value(&self, name: &str) -> Option<Reading> {
        let rest = name.strip_prefix("procstat_")?;
        let (proc, label) = rest.rsplit_once('_')?;
        let p = self.procs.iter().find(|p| p.name == proc)?;
        match label {
            "cpu" => Some(Reading::Num(p.cpu)),
            "mem" => Some(Reading::Num(p.mem as f64)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::diskstat::tempdir::Dir;

    fn stat(pid: u32, comm: &str, ppid: u32, pgrp: u32, utime: u64, stime: u64) -> String {
        format!("{pid} ({comm}) S {ppid} {pgrp} {pgrp} 0 -1 4194624 2398 0 0 0 {utime} {stime} 3 4 20 0 1 0 197474 61382656 1849 18446744073709551615 1 1 0 0 0 0 0 4096 16903 0 0 0 17 1 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
    }

    fn proc_entry(d: &Dir, pid: u32, comm: &str, ppid: u32, pgrp: u32, cmd: &str, jiffies: (u64, u64), rss: u64) {
        d.write(&format!("{pid}/stat"), &stat(pid, comm, ppid, pgrp, jiffies.0, jiffies.1));
        d.write(&format!("{pid}/cmdline"), &cmd.replace(' ', "\0"));
        d.write(&format!("{pid}/statm"), &format!("14986 {rss} 1234 25 0 1200 0\n"));
    }

    fn fixture(gmond_jiffies: (u64, u64)) -> Dir {
        let d = Dir::new("procstat");
        d.write("sys/kernel/pid_max", "4194304\n");
        proc_entry(&d, 1, "systemd", 0, 1, "/sbin/init\0", (500, 600), 3000);
        proc_entry(&d, 2, "kthreadd", 0, 0, "", (0, 0), 0);
        proc_entry(&d, 3333109, "gmond", 1, 3333109, "/usr/bin/gmond --pid-file=/run/gmond.pid\0", gmond_jiffies, 1849);
        proc_entry(&d, 3333120, "gmond worker", 3333109, 3333109, "/usr/bin/gmond --pid-file=/run/gmond.pid\0", (10, 10), 100);
        proc_entry(&d, 3340468, "gmond", 1, 3340468, "/usr/bin/gmond --pid-file=/run/gmond_b.pid -c /etc/ganglia/gmond_b.conf\0", (1, 1), 500);
        proc_entry(&d, 4000000, "sh", 1, 4000000, "sh -c ps | awk /gmond/\0", (1, 1), 1);
        d
    }

    fn val(s: &Procstat, n: &str) -> f64 {
        match s.value(n) {
            Some(Reading::Num(x)) => x,
            o => panic!("{n}: {o:?}"),
        }
    }

    #[test]
    fn regex_conversion() {
        assert!(awk_regex(r"/\/usr\/libexec\/mysqld/").unwrap().is_match("1 1 1 /usr/libexec/mysqld --x"));
        assert!(awk_regex("/splunkd.*start/").unwrap().is_match("splunkd -p 8089 start"));
        assert!(awk_regex("java.*Dopennms").is_err());
        assert!(awk_regex("/a/ || /b/").is_err());
    }

    #[test]
    fn ps_line_format() {
        let d = fixture((100, 50));
        let mut lines = ps_lines(d.path());
        lines.sort();
        assert!(lines.contains(&"      2       0       0 [kthreadd]".to_string()));
        assert!(lines.contains(&"3333109       1 3333109 /usr/bin/gmond --pid-file=/run/gmond.pid".to_string()));
    }

    #[test]
    fn two_gmonds_is_an_error_and_reads_zero() {
        let d = fixture((100, 50));
        let mut p = toml::Table::new();
        p.insert("gmond".into(), "/gmond/".into());
        p.insert("missing".into(), "/nonexistent/var/run/x.pid".into());
        let s = Procstat::new_at(&p, d.path(), 1000.0, 100.0, 4096).unwrap();
        let mut names = s.names();
        names.sort();
        assert_eq!(names, ["procstat_gmond_cpu", "procstat_gmond_mem", "procstat_missing_cpu", "procstat_missing_mem"]);
        for n in names {
            assert_eq!(val(&s, &n), 0.0);
        }
    }

    #[test]
    fn group_cpu_and_mem() {
        let d = fixture((100, 50));
        let mut p = toml::Table::new();
        p.insert("gmond".into(), r"/gmond --pid-file=\/run\/gmond\.pid/".into());
        let mut s = Procstat::new_at(&p, d.path(), 1000.0, 100.0, 4096).unwrap();
        assert_eq!(val(&s, "procstat_gmond_cpu"), 0.0);
        // Group 3333109 = gmond + its worker (whose comm has a space, so its
        // naively split utime/stime fields are shifted by one).
        assert_eq!(val(&s, "procstat_gmond_mem"), ((1849 + 100) * 4096) as f64);
        proc_entry(&d, 3333109, "gmond", 1, 3333109, "/usr/bin/gmond --pid-file=/run/gmond.pid\0", (130, 65), 1900);
        s.sample(1010.0); // cached
        assert_eq!(val(&s, "procstat_gmond_cpu"), 0.0);
        s.sample(1030.0);
        // 45 more jiffies over 30 s at 100 Hz.
        assert!((val(&s, "procstat_gmond_cpu") - 100.0 * 45.0 / (30.0 * 100.0)).abs() < 1e-12);
        assert_eq!(val(&s, "procstat_gmond_mem"), ((1900 + 100) * 4096) as f64);
    }

    #[test]
    fn naive_split_shifts_fields() {
        let d = fixture((0, 0));
        // "gmond worker" splits into two fields, so stat[13..17] are
        // cmajflt(0), utime(10), stime(10), cutime(3).
        assert_eq!(read_cpu(d.path(), "3333120"), 10 + 10 + 3);
        assert_eq!(read_cpu(d.path(), "3333109"), 3 + 4);
    }
}

#[cfg(test)]
mod live {
    use super::*;
    use crate::collect::diskstat::parity::{Py, close, num, sorted};

    fn run(regex: &str, expect_zero: bool) {
        let mut py = Py::start("process", "procstat", &[("gmond", regex)]);
        let mut t = toml::Table::new();
        t.insert("gmond".into(), regex.into());
        let mut ours = Procstat::new(&t).unwrap();
        assert_eq!(sorted(ours.names()), sorted(py.names.clone()));
        for n in ours.names() {
            assert!(crate::collect::spec::lookup(&n).is_some(), "{n}: no metadata");
        }
        std::thread::sleep(std::time::Duration::from_secs(16));
        let theirs = py.sample();
        ours.sample(wall_now());
        let cpu = num(ours.value("procstat_gmond_cpu"));
        let mem = num(ours.value("procstat_gmond_mem"));
        // One jiffy over 16 s is 0.0625%; rss may move a few pages.
        let ok = close("procstat_gmond_cpu", cpu, &theirs["procstat_gmond_cpu"], 0.05, 0.07)
            & close("procstat_gmond_mem", mem, &theirs["procstat_gmond_mem"], 0.01, 0.0);
        assert!(ok);
        if expect_zero {
            assert_eq!((cpu, mem), (0.0, 0.0));
        } else {
            assert!(mem > 0.0);
        }
    }

    /// cargo test -- --ignored procstat: the live procstat.pyconf value.
    /// Two gmonds have ppid 1 here (gmond.pid and gmond_b.pid), so the
    /// Python's lookup fails with "more than 1 result" and reports 0.
    #[test]
    #[ignore]
    fn parity_with_python_live_config() {
        run("/gmond/", true);
    }

    /// The same, narrowed to the main C gmond so real values are compared.
    #[test]
    #[ignore]
    fn parity_with_python_main_gmond() {
        run(r"/gmond --pid-file=\/run\/gmond\.pid/", false);
    }
}
