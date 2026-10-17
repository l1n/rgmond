//! Port of Ganglia's `disk/diskfree.py`: free space per mounted filesystem,
//! as `disk_free_absolute_<key>` (GB) and `disk_free_percent_<key>` (%).
//!
//! Mount selection and naming follow the Python exactly:
//! * only mounts whose source (first /proc/mounts field) starts with '/' or
//!   "tmpfs" are considered; the mount point is used exactly as /proc/mounts
//!   spells it, i.e. with ' ', '\t', '\n' and '\\' octal-escaped;
//! * the key is the mount point without its leading '/', with '/' -> '_',
//!   except that "/" is "rootfs";
//! * a mount is kept if its size (f_blocks * f_frsize) in GiB exceeds
//!   `min_disk_size` and it is not "/dev", or if its key is listed in
//!   `explicit_mounts_to_check`; duplicated mount points give duplicated names.
//! * a failing statvfs() during discovery makes the Python's metric_init
//!   raise, so `new` fails too; at sample time errors read as 0.
//!
//! When `mounts` is the kernel's own table (/proc/mounts, /proc/self/mounts)
//! the list comes from listmount(2)/statmount(2) instead of parsing text; it
//! yields the same (source, mount point) pairs in the same order (both are
//! the mount namespace in mount-id order). If either syscall is unavailable
//! the file is parsed, as is any other `mounts` path.
#![allow(dead_code)] // until the scheduler wires sources in

use super::diskstat::param_str;
use super::{Reading, Source};
use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::ffi::CString;

const NAME_PREFIX: &str = "disk_free_";

pub struct Diskfree {
    names: Vec<String>,
    /// path_key -> mount point (the Python's PATHS).
    paths: HashMap<String, String>,
    values: HashMap<String, f64>,
}

#[derive(Clone, Copy)]
struct Vfs {
    blocks: u64,
    bavail: u64,
    frsize: u64,
}

fn statvfs(path: &str) -> std::io::Result<Vfs> {
    let c = CString::new(path).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: c is a valid NUL-terminated string and st a valid out-pointer.
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Vfs { blocks: st.f_blocks as u64, bavail: st.f_bavail as u64, frsize: st.f_frsize as u64 })
}

/// (source, mount point) pairs, both escaped the way /proc/mounts prints them.
fn mount_table(mounts: &str) -> Vec<(String, String)> {
    if mounts == "/proc/mounts" || mounts == "/proc/self/mounts" {
        match kernel::list() {
            Ok(v) => return v,
            Err(e) => log::debug!("diskfree: listmount/statmount unavailable ({e}); parsing {mounts}"),
        }
    }
    // An unreadable mounts file gives no metrics (the Python uses f = []).
    let Ok(text) = std::fs::read_to_string(mounts) else { return Vec::new() };
    parse_mounts(&text)
}

/// The lines the Python looks at, as (first field, second field).
fn parse_mounts(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(|l| {
            let mut f = l.split_whitespace();
            (f.next().unwrap_or("").to_string(), f.next().unwrap_or("").to_string())
        })
        .collect()
}

/// /proc/mounts' mangle(): octal-escape space, tab, newline and backslash.
fn mangle(s: &[u8]) -> String {
    let mut out = Vec::with_capacity(s.len());
    for &b in s {
        if matches!(b, b' ' | b'\t' | b'\n' | b'\\') {
            out.extend_from_slice(format!("\\{b:03o}").as_bytes());
        } else {
            out.push(b);
        }
    }
    // Other bytes pass through unchanged, as in /proc/mounts.
    String::from_utf8_lossy(&out).into_owned()
}

mod kernel {
    //! listmount(2) / statmount(2), Linux 6.8+ (sb_source needs 6.15+).
    use super::mangle;
    use std::io::{Error, ErrorKind, Result};

    const NR_STATMOUNT: libc::c_long = 457;
    const NR_LISTMOUNT: libc::c_long = 458;
    const LSMT_ROOT: u64 = u64::MAX;
    const STATMOUNT_MNT_POINT: u64 = 0x10;
    const STATMOUNT_SB_SOURCE: u64 = 0x200;
    const MNT_ID_REQ_SIZE_VER0: u32 = 24;

    #[repr(C)]
    struct MntIdReq {
        size: u32,
        spare: u32,
        mnt_id: u64,
        param: u64,
    }

    // Offsets into struct statmount (linux/mount.h).
    const OFF_MASK: usize = 8;
    const OFF_MNT_POINT: usize = 108;
    const OFF_SB_SOURCE: usize = 124;
    const OFF_STR: usize = 512;

    fn ids() -> Result<Vec<u64>> {
        let mut out = Vec::new();
        let mut last = 0u64;
        let mut buf = vec![0u64; 512];
        loop {
            let req = MntIdReq { size: MNT_ID_REQ_SIZE_VER0, spare: 0, mnt_id: LSMT_ROOT, param: last };
            // SAFETY: req and buf are valid for the sizes passed.
            let n = unsafe { libc::syscall(NR_LISTMOUNT, &req as *const MntIdReq, buf.as_mut_ptr(), buf.len(), 0u32) };
            if n < 0 {
                return Err(Error::last_os_error());
            }
            let n = n as usize;
            out.extend_from_slice(&buf[..n]);
            if n < buf.len() {
                return Ok(out);
            }
            last = buf[n - 1];
        }
    }

    fn cstr_at(buf: &[u8], off_field: usize) -> Result<Vec<u8>> {
        let off = u32::from_ne_bytes(buf[off_field..off_field + 4].try_into().unwrap()) as usize;
        let s = buf.get(OFF_STR + off..).ok_or_else(|| Error::from(ErrorKind::InvalidData))?;
        let end = s.iter().position(|&b| b == 0).ok_or_else(|| Error::from(ErrorKind::InvalidData))?;
        Ok(s[..end].to_vec())
    }

    /// Returns None for a mount that vanished between listmount and statmount.
    fn stat(id: u64) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let want = STATMOUNT_MNT_POINT | STATMOUNT_SB_SOURCE;
        let mut len = 4096usize;
        loop {
            let mut buf = vec![0u8; len];
            let req = MntIdReq { size: MNT_ID_REQ_SIZE_VER0, spare: 0, mnt_id: id, param: want };
            // SAFETY: req and buf are valid for the sizes passed.
            let r = unsafe { libc::syscall(NR_STATMOUNT, &req as *const MntIdReq, buf.as_mut_ptr(), len, 0u32) };
            if r < 0 {
                let e = Error::last_os_error();
                match e.raw_os_error() {
                    Some(libc::EOVERFLOW) if len < 1 << 24 => {
                        len *= 4;
                        continue;
                    }
                    Some(libc::ENOENT) => return Ok(None),
                    _ => return Err(e),
                }
            }
            let mask = u64::from_ne_bytes(buf[OFF_MASK..OFF_MASK + 8].try_into().unwrap());
            if mask & want != want {
                // Older kernel without sb_source: can't reproduce /proc/mounts.
                return Err(Error::from(ErrorKind::Unsupported));
            }
            return Ok(Some((cstr_at(&buf, OFF_SB_SOURCE)?, cstr_at(&buf, OFF_MNT_POINT)?)));
        }
    }

    pub fn list() -> Result<Vec<(String, String)>> {
        let mut out = Vec::new();
        for id in ids()? {
            if let Some((src, point)) = stat(id)? {
                out.push((mangle(&src), mangle(&point)));
            }
        }
        Ok(out)
    }
}

impl Diskfree {
    pub fn new(params: &toml::Table) -> Result<Self> {
        let mounts = param_str(params, "mounts").unwrap_or_else(|| "/proc/mounts".into());
        Self::from_table(params, mount_table(&mounts), statvfs)
    }

    fn from_table(
        params: &toml::Table,
        table: Vec<(String, String)>,
        stat: impl Fn(&str) -> std::io::Result<Vfs>,
    ) -> Result<Self> {
        let min_size: f64 = match param_str(params, "min_disk_size") {
            Some(s) => s.trim().parse().with_context(|| format!("diskfree: min_disk_size {s:?}"))?,
            None => 1.0,
        };
        let explicit: Vec<String> = match param_str(params, "explicit_mounts_to_check") {
            Some(s) if !s.is_empty() => s.split(' ').map(|m| m.get(1..).unwrap_or("").replace('/', "_")).collect(),
            _ => Vec::new(),
        };
        let mut names = Vec::new();
        let mut paths = HashMap::new();
        for (source, point) in table {
            if !(source.starts_with('/') || source.starts_with("tmpfs")) {
                continue;
            }
            if point.is_empty() {
                bail!("diskfree: IndexError on mounts line starting {source:?}");
            }
            let key = if point == "/" { "rootfs".to_string() } else { point[1..].replace('/', "_") };
            let d = stat(&point).with_context(|| format!("diskfree: statvfs({point}) in metric_init"))?;
            let size = (d.blocks as u128 * d.frsize as u128) as f64 / (1u64 << 30) as f64;
            if (size > min_size && point != "/dev") || explicit.contains(&key) {
                for unit in ["absolute", "percent"] {
                    names.push(format!("{NAME_PREFIX}{unit}_{key}"));
                }
                paths.insert(key, point);
            }
        }
        Ok(Diskfree { names, paths, values: HashMap::new() })
    }

    /// get_value(): which path the Python statvfs()es for a metric name.
    fn path_for(&self, key: &str) -> String {
        if key == "rootfs" {
            "/".into()
        } else if let Some(p) = self.paths.get(key) {
            format!("/{p}")
        } else {
            format!("/{}", key.replace('_', "/"))
        }
    }

    fn compute(&self, name: &str, stat: &impl Fn(&str) -> std::io::Result<Vfs>) -> f64 {
        let rest = name.strip_prefix(NAME_PREFIX).unwrap_or(name);
        let (unit, key) = if let Some(k) = rest.strip_prefix("absolute_") {
            ("absolute", k)
        } else if let Some(k) = rest.strip_prefix("percent_") {
            ("percent", k)
        } else {
            return 0.0;
        };
        match stat(&self.path_for(key)) {
            Err(_) => 0.0,
            Ok(d) if unit == "percent" => {
                if d.blocks == 0 {
                    0.0 // ZeroDivisionError
                } else {
                    d.bavail as f64 / d.blocks as f64 * 100.0
                }
            }
            Ok(d) => (d.bavail as u128 * d.frsize as u128) as f64 / (1u64 << 30) as f64,
        }
    }

    fn sample_with(&mut self, stat: impl Fn(&str) -> std::io::Result<Vfs>) {
        let vals: Vec<(String, f64)> = self.names.iter().map(|n| (n.clone(), self.compute(n, &stat))).collect();
        self.values = vals.into_iter().collect();
    }
}

impl Source for Diskfree {
    fn name(&self) -> &'static str {
        "diskfree"
    }

    fn names(&self) -> Vec<String> {
        self.names.clone()
    }

    fn sample(&mut self, _now: f64) {
        // No caching in the Python: every callback calls statvfs().
        self.sample_with(statvfs);
    }

    fn value(&self, name: &str) -> Option<Reading> {
        self.values.get(name).map(|&v| Reading::Num(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTS: &str = r"/dev/root / ext4 rw,relatime 0 0
devtmpfs /dev devtmpfs rw,nosuid,noexec,relatime,size=16415436k 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev,inode64,huge=advise,usrquota 0 0
tmpfs /run tmpfs rw,nosuid,nodev,size=6568412k,nr_inodes=819200,mode=755 0 0
none /run/credentials/systemd-journald.service tmpfs ro,nosuid,nodev 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev,relatime,inode64,huge=advise 0 0
/dev/sdc /srv/data/media ext4 rw,noatime 0 0
/dev/sdd /mnt/my\040disk ext4 rw 0 0
remote: /srv/rclone/drive fuse.rclone rw,nosuid,nodev,relatime 0 0
tmpfs /run/user/1001 tmpfs rw,nosuid,nodev,relatime,size=3284204k 0 0
tmpfs /tiny tmpfs rw 0 0
/dev/sde /boot ext4 rw 0 0
";

    fn fake(path: &str) -> std::io::Result<Vfs> {
        let gb = 1u64 << 30;
        let p = path.trim_start_matches('/');
        Ok(match p {
            "" => Vfs { blocks: 160 * gb / 4096, bavail: 64 * gb / 4096, frsize: 4096 },
            "tiny" => Vfs { blocks: 1, bavail: 1, frsize: 4096 },
            "boot" => Vfs { blocks: 0, bavail: 0, frsize: 4096 },
            "mnt/my\\040disk" => return Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
            _ => Vfs { blocks: 4 * gb / 4096, bavail: gb / 4096, frsize: 4096 },
        })
    }

    #[test]
    fn selection_and_names() {
        let mut p = toml::Table::new();
        p.insert("min_disk_size".into(), "1".into());
        p.insert("explicit_mounts_to_check".into(), "/tiny /boot".into());
        // statvfs of the escaped mount point fails: the Python's metric_init raises.
        assert!(Diskfree::from_table(&p, parse_mounts(MOUNTS), fake).is_err());
        let table: Vec<_> = parse_mounts(MOUNTS).into_iter().filter(|(_, m)| !m.contains("040")).collect();
        let mut s = Diskfree::from_table(&p, table, fake).unwrap();
        let keys: Vec<&str> = s.names.iter().filter_map(|n| n.strip_prefix("disk_free_absolute_")).collect();
        assert_eq!(keys, ["rootfs", "dev_shm", "run", "tmp", "srv_data_media", "run_user_1001", "tiny", "boot"]);
        assert_eq!(s.names.len(), 16);
        s.sample_with(fake);
        assert_eq!(s.value("disk_free_absolute_rootfs"), Some(Reading::Num(64.0)));
        assert_eq!(s.value("disk_free_percent_rootfs"), Some(Reading::Num(40.0)));
        assert_eq!(s.value("disk_free_percent_run"), Some(Reading::Num(25.0)));
        assert_eq!(s.value("disk_free_percent_boot"), Some(Reading::Num(0.0)));
        assert_eq!(s.path_for("srv_data_media"), "//srv/data/media");
        assert_eq!(s.path_for("not_known"), "/not/known");
    }

    #[test]
    fn mangle_matches_proc_mounts() {
        assert_eq!(mangle(b"/mnt/my disk\\x\ty"), r"/mnt/my\040disk\134x\011y");
        assert_eq!(mangle("/mnt/é".as_bytes()), "/mnt/é");
    }
}

#[cfg(test)]
pub(crate) mod parity_support {
    /// What the kernel-API path yields, for the live parity test.
    pub fn kernel_table() -> std::io::Result<Vec<(String, String)>> {
        super::kernel::list()
    }
    pub fn file_table() -> Vec<(String, String)> {
        super::parse_mounts(&std::fs::read_to_string("/proc/mounts").unwrap())
    }
}

#[cfg(test)]
mod live {
    use super::*;
    use crate::collect::diskstat::parity::{Py, close, num};

    /// cargo test -- --ignored diskfree: the port and disk/diskfree.py with
    /// the live diskfree.pyconf params, sampled at the same moment.
    #[test]
    #[ignore]
    fn parity_with_python() {
        // The kernel-API mount list must be exactly what /proc/mounts lists,
        // in the same order, for the fields the Python looks at.
        let k = parity_support::kernel_table().expect("listmount/statmount");
        assert_eq!(k, parity_support::file_table());
        let params = [("mounts", "/proc/mounts"), ("min_disk_size", "1")];
        let mut py = Py::start("disk", "diskfree", &params);
        let mut t = toml::Table::new();
        for (k, v) in params {
            t.insert(k.into(), v.into());
        }
        let mut ours = Diskfree::new(&t).unwrap();
        assert_eq!(ours.names(), py.names, "same names in the same order");
        for n in ours.names() {
            assert!(crate::collect::spec::lookup(&n).is_some(), "{n}: no metadata");
        }
        let theirs = py.sample();
        ours.sample(0.0);
        let mut ok = true;
        for n in ours.names() {
            // Live filesystems: allow 10 MB (or 0.01 percentage points) of
            // churn between the two reads.
            ok &= close(&n, num(ours.value(&n)), &theirs[&n], 0.0, 1e-2);
        }
        assert!(ok);
    }
}
