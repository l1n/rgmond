//! Test-only helper for the `#[ignore]` live parity tests: runs a gmond Python
//! module under tools/parity/driver.py and samples it on demand, so a Rust
//! source and its Python original can be read at (nearly) the same moment.
//!
//! The Python modules are looked up in `$RGMOND_PY_MODULES` (a
//! `gmond/python_modules` directory with cpu/, memory/, ssl/, vm_stats/ ...).
//! Included with `#[path]` by each source's test module.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// RGMOND_PY_MODULES is a gmond python_modules tree: the source layout
/// (network/, disk/, ...) or ganglia's flat install directory.
fn module_dir(subdir: &str) -> String {
    let base = std::env::var("RGMOND_PY_MODULES").unwrap_or_else(|_| "/usr/lib/ganglia/python_modules".into());
    let nested = format!("{base}/{subdir}");
    if std::path::Path::new(&nested).is_dir() { nested } else { base }
}

pub fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

pub struct PyModule {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl PyModule {
    /// Start `<modules>/<subdir>/<module>.py` under the driver.
    pub fn spawn(subdir: &str, module: &str) -> PyModule {
        let driver = concat!(env!("CARGO_MANIFEST_DIR"), "/tools/parity/driver.py");
        let mut child = Command::new("python3")
            .arg(driver)
            .arg(module_dir(subdir))
            .arg(module)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn python3 driver");
        let stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "READY", "driver for {module} did not start");
        PyModule { child, stdin, stdout }
    }

    /// One collection pass over every descriptor. A callback that raised is
    /// reported as 0, which is what gmond's mod_python sends in that case.
    pub fn sample(&mut self) -> HashMap<String, f64> {
        writeln!(self.stdin, "sample").unwrap();
        self.stdin.flush().unwrap();
        let mut out = HashMap::new();
        loop {
            let mut line = String::new();
            assert!(self.stdout.read_line(&mut line).unwrap() > 0, "driver exited");
            let line = line.trim_end_matches('\n');
            if line == "END" {
                return out;
            }
            let (name, val) = line.split_once('\t').expect("name<TAB>value");
            let v = if val == "ERR" { 0.0 } else { val.trim().parse().unwrap_or(0.0) };
            out.insert(name.to_string(), v);
        }
    }
}

impl Drop for PyModule {
    fn drop(&mut self) {
        let _ = writeln!(self.stdin, "quit");
        let _ = self.child.wait();
    }
}

/// Values of a Rust source's metrics as plain numbers.
pub fn rust_values(src: &dyn crate::collect::Source) -> HashMap<String, f64> {
    src.names()
        .into_iter()
        .map(|n| {
            let v = match src.value(&n) {
                Some(crate::collect::Reading::Num(v)) => v,
                other => panic!("{n}: unexpected reading {other:?}"),
            };
            (n, v)
        })
        .collect()
}

/// `|a - b| <= max(abs, rel * max(|a|, |b|))`.
pub fn close(a: f64, b: f64, abs: f64, rel: f64) -> bool {
    (a - b).abs() <= abs.max(rel * a.abs().max(b.abs()))
}
