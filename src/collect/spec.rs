//! Metadata for every metric rgmond sends. spec.toml is what C gmond 3.7.2
//! sends for its own metrics (extracted from captured traffic), so gmetad and
//! ganglia-web see no change; spec_new.toml covers rgmond's new metrics.

use crate::proto::{Metadata, Value};
use crate::collect::Reading;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct MetricSpec {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub units: String,
    pub slope: u32,
    pub tmax: u32,
    pub dmax: u32,
    pub fmt: String,
    /// XDR value message variant gmond used: Float, Double, UInt, UShort, Str.
    pub wire: String,
    pub extra: Vec<(String, String)>,
}

#[derive(Deserialize)]
struct File {
    metric: Vec<MetricSpec>,
}

fn load(text: &str) -> Vec<MetricSpec> {
    toml::from_str::<File>(text).expect("built-in metric spec").metric
}

/// Family entries ("{}" in the name) from both files, as (regex, literal
/// length, spec). When several match, the one with the most literal text wins,
/// so diskstat_{}_weighted_io_time beats diskstat_{}_io_time.
fn patterns() -> &'static Vec<(regex::Regex, usize, MetricSpec)> {
    static P: OnceLock<Vec<(regex::Regex, usize, MetricSpec)>> = OnceLock::new();
    P.get_or_init(|| {
        load(include_str!("spec.toml"))
            .into_iter()
            .chain(load(include_str!("spec_new.toml")))
            .filter(|m| m.name.contains("{}"))
            .map(|m| {
                let re = format!("^{}$", regex::escape(&m.name).replace(r"\{\}", "(.+)"));
                (regex::Regex::new(&re).expect("spec pattern"), m.name.len() - 2, m)
            })
            .collect()
    })
}

/// diskfree's mount point for a metric suffix: "rootfs" is /, otherwise the
/// underscores of the mangled name become slashes.
fn mount_of(part: &str) -> String {
    if part == "rootfs" { "/".to_string() } else { format!("/{}", part.replace('_', "/")) }
}

/// Metadata for a metric name: an exact entry, else the best-matching family.
pub fn lookup(name: &str) -> Option<MetricSpec> {
    if let Some(s) = all().get(name) {
        return Some(s.clone());
    }
    let (re, _, m) = patterns().iter().filter(|(re, _, _)| re.is_match(name)).max_by_key(|(_, lit, _)| *lit)?;
    let part = re.captures(name)?.get(1).map(|g| g.as_str()).unwrap_or("");
    let mut s = m.clone();
    s.name = name.to_string();
    for (_, v) in &mut s.extra {
        *v = v.replace("{name}", name).replace("{mount}", &mount_of(part)).replace("{}", part);
    }
    Some(s)
}

/// Every entry of both files, with whether it is new in rgmond (spec_new.toml).
pub fn documented() -> Vec<(MetricSpec, bool)> {
    load(include_str!("spec.toml"))
        .into_iter()
        .map(|m| (m, false))
        .chain(load(include_str!("spec_new.toml")).into_iter().map(|m| (m, true)))
        .collect()
}

/// Exact-name entries of spec.toml.
pub fn all() -> &'static HashMap<String, MetricSpec> {
    static SPECS: OnceLock<HashMap<String, MetricSpec>> = OnceLock::new();
    SPECS.get_or_init(|| {
        load(include_str!("spec.toml")).into_iter().filter(|m| !m.name.contains("{}")).map(|m| (m.name.clone(), m)).collect()
    })
}

impl MetricSpec {
    pub fn metadata(&self) -> Metadata {
        Metadata {
            type_: self.type_.clone(),
            name: self.name.clone(),
            units: self.units.clone(),
            slope: self.slope,
            tmax: self.tmax,
            dmax: self.dmax,
            extra: self.extra.clone(),
        }
    }

    /// Encode a reading as this metric's wire type, the way gmond's g_val_t
    /// assignment would (C float/integer conversion).
    pub fn encode(&self, r: &Reading) -> Value {
        let num = match r {
            Reading::Num(v) => *v,
            Reading::Str(s) => s.trim().parse().unwrap_or(0.0),
        };
        match self.wire.as_str() {
            "Str" => Value::Str(match r {
                Reading::Str(s) => s.clone(),
                Reading::Num(v) => v.to_string(),
            }),
            "Double" => Value::Double(num),
            "UInt" => Value::UInt(num as u32),
            "UShort" => Value::UShort(num as u16),
            "Int" => Value::Int(num as i32),
            "Short" => Value::Short(num as i16),
            _ => Value::Float(num as f32),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_and_new_metrics() {
        let t = lookup("rx_bytes_wg0").expect("interface family");
        assert_eq!(t.units, "bytes/sec");
        assert!(t.extra.contains(&("TITLE".into(), "rx_bytes_wg0".into())));
        let w = lookup("diskstat_nvme0n1_weighted_io_time").unwrap();
        assert!(w.extra.iter().any(|(_, v)| v.contains("weighted")));
        let d = lookup("disk_free_percent_srv_data").unwrap();
        assert!(d.extra.contains(&("DESC".into(), "Disk space available (%) on /srv/data".into())));
        assert!(lookup("totally_unknown").is_none());
        let p = lookup("biolat_sda_p99_ms").expect("pattern");
        assert_eq!(p.units, "ms");
        assert!(p.extra.iter().any(|(k, v)| k == "TITLE" && v == "sda I/O latency (p99)"));
        assert_eq!(lookup("unit_nginx_tasks").unwrap().wire, "UInt");
    }

    /// The generic spec must reproduce, for every metric gmond sent on the
    /// capture host, exactly the metadata gmond sent (local fixture only).
    #[test]
    fn reproduces_captured_spec() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/spec-captured.toml");
        let Ok(text) = std::fs::read_to_string(path) else { return };
        let captured = load(&text);
        assert!(captured.len() >= 200);
        for c in captured {
            let got = lookup(&c.name).unwrap_or_else(|| panic!("{}: no spec", c.name));
            assert_eq!(format!("{got:?}"), format!("{c:?}"), "{}", c.name);
        }
    }
}
