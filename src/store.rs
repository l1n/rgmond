//! Host/metric state, mirroring gmond.c's `hosts` hash and its update rules
//! (Ganglia_host_get, Ganglia_metadata_save, Ganglia_value_save,
//! Ganglia_update_vidals, Ganglia_metadata_check, cleanup_data).

use crate::proto::{Metadata, MetricId, Msg, Value};
use std::collections::HashMap;

/// Microseconds since the Unix epoch, like apr_time_t.
pub type Micros = i64;
pub const USEC: i64 = 1_000_000;

pub fn now_micros() -> Micros {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

#[derive(Clone, Debug)]
pub struct MetaEntry {
    pub id: MetricId,
    pub meta: Metadata,
    pub last_heard: Micros,
}

#[derive(Clone, Debug)]
pub struct ValEntry {
    pub fmt: String,
    pub value: Value,
    pub last_heard: Micros,
}

#[derive(Clone, Debug)]
pub struct Host {
    pub name: String,
    pub ip: String,
    pub location: Option<String>,
    pub gmond_started: u32,
    pub last_heard: Micros,
    pub metrics: HashMap<String, MetaEntry>,
    pub values: HashMap<String, ValEntry>,
}

#[derive(Default, Clone)]
pub struct Store {
    /// Keyed by IP (or the spoofed IP), as gmond keys its hosts hash.
    pub hosts: HashMap<String, Host>,
}

/// What `Store::handle` asks the caller to do afterwards.
#[derive(Debug, PartialEq)]
pub enum Followup {
    None,
    /// A value arrived for a metric we have no metadata for: ask the sender.
    RequestMetadata(Msg),
    /// A peer asked us to resend metadata for this local metric name.
    ResendMetadata(String),
}

/// gmond's sanitize_metric_name. Its condition ANDs `*p == ':' && !spoof`
/// with the "not a legal char" tests, so the only character it ever rewrites
/// is ':' in a non-spoofed name. Reproduced as-is for compatibility.
pub fn sanitize_metric_name(name: &str, spoof: bool) -> String {
    if spoof { name.to_string() } else { name.replace(':', "_") }
}

/// Split "a:b" at the first ':' after the first character (gmond's strchr(buf+1, ':')).
fn split_spoof(s: &str) -> Option<(&str, &str)> {
    let i = s.char_indices().skip(1).find(|&(_, c)| c == ':')?.0;
    Some((&s[..i], &s[i + 1..]))
}

/// gmond's get_metric_names: the visible name, without a spoof ":realname" suffix.
pub fn display_name(id: &MetricId) -> &str {
    if id.spoof {
        if let Some((first, _)) = split_spoof(&id.name) {
            return first;
        }
    }
    &id.name
}

impl Store {
    /// Look up or create the host a message belongs to (Ganglia_host_get).
    /// `resolve` maps the sender IP to a hostname (reverse DNS); it is only
    /// called for new, non-spoofed hosts.
    fn host_get(
        &mut self,
        remote_ip: &str,
        id: &MetricId,
        now: Micros,
        resolve: &mut dyn FnMut(&str) -> Option<String>,
    ) -> Option<&mut Host> {
        let (key, spoof_name) = if id.spoof {
            let (ip, name) = split_spoof(&id.host)?;
            if name.is_empty() {
                return None;
            }
            (ip.to_string(), Some(name.to_string()))
        } else {
            (remote_ip.to_string(), None)
        };
        if let Some(h) = self.hosts.get_mut(&key) {
            h.last_heard = now;
        } else {
            let name = spoof_name.or_else(|| resolve(&key)).unwrap_or_else(|| key.clone());
            self.hosts.insert(
                key.clone(),
                Host {
                    name,
                    ip: key.clone(),
                    location: None,
                    gmond_started: 0,
                    last_heard: now,
                    metrics: HashMap::new(),
                    values: HashMap::new(),
                },
            );
        }
        self.hosts.get_mut(&key)
    }

    /// Apply one received message (process_udp_recv_channel).
    pub fn handle(
        &mut self,
        msg: Msg,
        remote_ip: &str,
        now: Micros,
        resolve: &mut dyn FnMut(&str) -> Option<String>,
    ) -> Followup {
        let Some(host) = self.host_get(remote_ip, msg.id(), now, resolve) else {
            return Followup::None;
        };
        match msg {
            Msg::MetadataRequest { id } => {
                Followup::ResendMetadata(sanitize_metric_name(&id.name, id.spoof))
            }
            Msg::MetadataFull { mut id, meta } => {
                id.name = sanitize_metric_name(&id.name, id.spoof);
                host.metrics.insert(id.name.clone(), MetaEntry { id, meta, last_heard: now });
                Followup::None
            }
            Msg::Value { mut id, fmt, value } => {
                id.name = sanitize_metric_name(&id.name, id.spoof);
                // Ganglia_update_vidals
                let shown = display_name(&id);
                if shown.eq_ignore_ascii_case("location") {
                    if let Value::Str(s) = &value {
                        host.location = Some(s.clone());
                    }
                } else if shown.eq_ignore_ascii_case("heartbeat") {
                    // gmond reads the union's uint member whatever the type was. gmetric
                    // (including `gmetric -H`) sends values as strings, so for those C
                    // gmond stores the low bits of a heap pointer; parse the string.
                    host.gmond_started = match &value {
                        Value::UInt(v) => *v,
                        Value::Int(v) => *v as u32,
                        Value::UShort(v) => *v as u32,
                        Value::Short(v) => *v as u16 as u32,
                        Value::Str(s) => s.trim().parse().unwrap_or(0),
                        _ => host.gmond_started,
                    };
                }
                let missing = !host.metrics.contains_key(&id.name);
                host.values.insert(id.name.clone(), ValEntry { fmt, value, last_heard: now });
                // Ganglia_metadata_check
                if missing {
                    let req_host = if id.spoof { format!("{}:{}", host.ip, host.name) } else { host.name.clone() };
                    Followup::RequestMetadata(Msg::MetadataRequest {
                        id: MetricId { host: req_host, name: id.name, spoof: id.spoof },
                    })
                } else {
                    Followup::None
                }
            }
        }
    }

    /// Drop expired hosts and metrics (cleanup_data).
    pub fn cleanup(&mut self, now: Micros, host_dmax: u32) {
        self.hosts.retain(|_, h| !(host_dmax != 0 && now - h.last_heard > host_dmax as i64 * USEC));
        for h in self.hosts.values_mut() {
            let expired: Vec<String> = h
                .metrics
                .iter()
                .filter(|(_, m)| m.meta.dmax != 0 && now - m.last_heard > m.meta.dmax as i64 * USEC)
                .map(|(k, _)| k.clone())
                .collect();
            for k in expired {
                h.metrics.remove(&k);
                h.values.remove(&k);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(host: &str, name: &str, spoof: bool) -> MetricId {
        MetricId { host: host.into(), name: name.into(), spoof }
    }

    fn meta(name: &str) -> Metadata {
        Metadata {
            type_: "uint32".into(),
            name: name.into(),
            units: "".into(),
            slope: 3,
            tmax: 60,
            dmax: 0,
            extra: vec![],
        }
    }

    #[test]
    fn spoofed_host_is_keyed_by_its_ip() {
        let mut s = Store::default();
        let m = Msg::MetadataFull { id: id("127.0.0.2:box.example", "x", true), meta: meta("x") };
        s.handle(m, "10.0.0.1", 5, &mut |_| panic!("no lookup for spoofed hosts"));
        let h = &s.hosts["127.0.0.2"];
        assert_eq!(h.name, "box.example");
        assert!(h.metrics.contains_key("x"));
    }

    #[test]
    fn value_without_metadata_asks_for_it() {
        let mut s = Store::default();
        let v = Msg::Value { id: id("h", "a:b", false), fmt: "%u".into(), value: Value::UInt(1) };
        let f = s.handle(v, "10.0.0.1", 5, &mut |_| Some("node1".into()));
        assert_eq!(
            f,
            Followup::RequestMetadata(Msg::MetadataRequest { id: id("node1", "a_b", false) })
        );
        assert_eq!(s.hosts["10.0.0.1"].name, "node1");
    }

    #[test]
    fn heartbeat_sets_gmond_started() {
        let mut s = Store::default();
        let v = Msg::Value { id: id("h", "heartbeat", false), fmt: "%u".into(), value: Value::UInt(1792239543) };
        s.handle(v, "::1", 5, &mut |_| None);
        assert_eq!(s.hosts["::1"].gmond_started, 1792239543);
    }

    #[test]
    fn string_heartbeat_from_gmetric() {
        let mut s = Store::default();
        let v = Msg::Value { id: id("10.9.8.7:box", "heartbeat", true), fmt: "%s".into(), value: Value::Str("1234".into()) };
        s.handle(v, "127.0.0.1", 5, &mut |_| None);
        assert_eq!(s.hosts["10.9.8.7"].gmond_started, 1234);
    }

    #[test]
    fn metrics_expire_by_metadata_age() {
        let mut s = Store::default();
        let mut m = meta("x");
        m.dmax = 10;
        s.handle(Msg::MetadataFull { id: id("h", "x", false), meta: m }, "ip", 0, &mut |_| None);
        s.cleanup(10 * USEC, 0);
        assert!(s.hosts["ip"].metrics.contains_key("x"));
        s.cleanup(11 * USEC, 0);
        assert!(!s.hosts["ip"].metrics.contains_key("x"));
    }
}
