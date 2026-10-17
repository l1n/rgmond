//! Port of gmond's python_modules/ssl/entropy.py: `entropy_avail`, the
//! kernel's entropy estimate in bits.
//!
//! Like the Python module it re-reads the file on every collection (no cache)
//! and uses the integer on its last line. An unreadable file reads as 0 (the
//! module returns 0 on IOError); an empty or non-numeric file makes the
//! Python callback raise, which gmond's mod_python sends as 0 too. The value
//! is a uint32, converted as mod_python does (PyLong_AsUnsignedLongMask
//! truncated to unsigned int).

use super::{Reading, Source};

const ENTROPY_FILE: &str = "/proc/sys/kernel/random/entropy_avail";

pub struct Entropy {
    value: f64,
}

impl Entropy {
    #[allow(dead_code)]
    pub fn new(_params: &toml::Table) -> anyhow::Result<Self> {
        Ok(Entropy { value: 0.0 })
    }

    fn update(&mut self, read: std::io::Result<String>) {
        self.value = match read {
            Ok(text) => Self::parse(&text),
            Err(e) => {
                log::debug!("entropy: {ENTROPY_FILE}: {e}");
                0.0
            }
        };
    }

    fn parse(text: &str) -> f64 {
        match text.lines().last().map(|l| l.trim().parse::<i64>()) {
            Some(Ok(v)) => v as u32 as f64,
            _ => 0.0,
        }
    }
}

impl Source for Entropy {
    fn name(&self) -> &'static str {
        "entropy"
    }

    fn names(&self) -> Vec<String> {
        vec!["entropy_avail".to_string()]
    }

    fn sample(&mut self, _now: f64) {
        self.update(std::fs::read_to_string(ENTROPY_FILE));
    }

    fn value(&self, name: &str) -> Option<Reading> {
        (name == "entropy_avail").then_some(Reading::Num(self.value))
    }
}

#[cfg(test)]
#[path = "../../tools/parity/harness.rs"]
mod parity_harness;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_last_line() {
        assert_eq!(Entropy::parse("256\n"), 256.0);
        assert_eq!(Entropy::parse("3017\n"), 3017.0);
        assert_eq!(Entropy::parse("1\n 42 \n"), 42.0);
        assert_eq!(Entropy::parse(""), 0.0);
        assert_eq!(Entropy::parse("x\n"), 0.0);
    }

    #[test]
    fn two_samples() {
        let mut e = Entropy::new(&toml::Table::new()).unwrap();
        assert_eq!(e.value("entropy_avail"), Some(Reading::Num(0.0)));
        e.update(Ok("256\n".into()));
        assert_eq!(e.value("entropy_avail"), Some(Reading::Num(256.0)));
        e.update(Ok("3017\n".into()));
        assert_eq!(e.value("entropy_avail"), Some(Reading::Num(3017.0)));
        e.update(Err(std::io::Error::other("gone")));
        assert_eq!(e.value("entropy_avail"), Some(Reading::Num(0.0)));
        assert_eq!(e.value("entropy"), None);
    }

    #[test]
    #[ignore]
    fn live_parity_with_python() {
        use super::parity_harness as harness;
        let mut py = harness::PyModule::spawn("ssl", "entropy");
        let mut rs = Entropy::new(&toml::Table::new()).unwrap();
        for round in 0..3 {
            rs.sample(harness::now());
            let p = py.sample();
            for (n, rv) in harness::rust_values(&rs) {
                let pv = p[&n];
                eprintln!("round {round} {n:22} rust {rv:14.4} python {pv:14.4}");
                assert!(harness::close(rv, pv, 0.0, 0.0), "{n}: {rv} vs {pv}");
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}
