//! Collection groups: gmond's process_collection_groups /
//! Ganglia_collection_group_collect / Ganglia_collection_group_send.

use super::spec::{self, MetricSpec};
use super::{GroupCfg, Reading, Source};
use crate::config::HostCfg;
use crate::proto::{MetricId, Msg};
use crate::store::{Micros, Store, USEC};
use log::warn;

struct Metric {
    source: usize,
    spec: MetricSpec,
    value_threshold: Option<f64>,
    last: Option<Reading>,
    now: Option<Reading>,
    /// 0 = never sent / resend requested.
    metadata_last_sent: Micros,
}

struct Group {
    collect_once: bool,
    collect_every: i64,
    time_threshold: i64,
    metrics: Vec<Metric>,
    next_collect: Micros,
    next_send: Micros,
    collected_once: bool,
}

pub struct Scheduler {
    pub sources: Vec<Box<dyn Source>>,
    groups: Vec<Group>,
    host: HostCfg,
    send_metadata_interval: i64,
}

fn num(r: &Reading) -> f64 {
    match r {
        Reading::Num(v) => *v,
        Reading::Str(_) => 0.0,
    }
}

impl Scheduler {
    /// Resolve each group's metric selectors against the sources, the way
    /// setup_collection_groups matches `name` and `name_match`.
    pub fn new(
        sources: Vec<Box<dyn Source>>,
        groups: &[GroupCfg],
        host: HostCfg,
        send_metadata_interval: u32,
    ) -> anyhow::Result<Scheduler> {
        let catalog: Vec<(usize, String)> =
            sources.iter().enumerate().flat_map(|(i, s)| s.names().into_iter().map(move |n| (i, n))).collect();
        let mut out = vec![];
        let mut taken = std::collections::HashSet::new();
        for g in groups {
            let mut metrics = vec![];
            for sel in &g.metric {
                let matched: Vec<&(usize, String)> = match (&sel.name, &sel.name_match) {
                    (Some(n), _) => catalog.iter().filter(|(_, c)| c == n).collect(),
                    (None, Some(re)) => {
                        let re = regex::Regex::new(&format!("^(?:{re})$"))?;
                        catalog.iter().filter(|(_, c)| re.is_match(c)).collect()
                    }
                    (None, None) => anyhow::bail!("collection group metric needs name or name_match"),
                };
                if matched.is_empty() {
                    warn!("no source provides {:?}", sel.name.as_ref().or(sel.name_match.as_ref()));
                }
                for (src, name) in matched {
                    // gmond collects a metric in the first group that names it.
                    if !taken.insert(name.clone()) {
                        continue;
                    }
                    let Some(spec) = spec::lookup(name) else {
                        warn!("{name}: no metadata spec, not sending it");
                        continue;
                    };
                    metrics.push(Metric {
                        source: *src,
                        spec,
                        value_threshold: sel.value_threshold,
                        last: None,
                        now: None,
                        metadata_last_sent: 0,
                    });
                }
            }
            out.push(Group {
                collect_once: g.collect_once,
                collect_every: g.collect_every as i64 * USEC,
                time_threshold: g.time_threshold as i64 * USEC,
                metrics,
                next_collect: 0,
                next_send: 0,
                collected_once: false,
            });
        }
        Ok(Scheduler { sources, groups: out, host, send_metadata_interval: send_metadata_interval as i64 * USEC })
    }

    /// Every metric name this scheduler sends.
    pub fn names(&self) -> std::collections::HashSet<String> {
        self.groups.iter().flat_map(|g| g.metrics.iter().map(|m| m.spec.name.clone())).collect()
    }

    pub fn request_metadata(&mut self, name: &str) {
        for g in &mut self.groups {
            for m in &mut g.metrics {
                if m.spec.name == name {
                    m.metadata_last_sent = 0;
                }
            }
        }
    }

    fn collect(&mut self, gi: usize, now: Micros) {
        let g = &mut self.groups[gi];
        let mut by_source: std::collections::BTreeMap<usize, Vec<&str>> = Default::default();
        for m in &g.metrics {
            by_source.entry(m.source).or_default().push(&m.spec.name);
        }
        for (src, names) in by_source {
            self.sources[src].sample_for(now as f64 / USEC as f64, &names);
        }
        for m in &mut g.metrics {
            m.last = m.now.take();
            m.now = self.sources[m.source].value(&m.spec.name);
            if let (Some(t), Some(a), Some(b)) = (m.value_threshold, &m.last, &m.now) {
                if t >= 0.0 && !matches!(a, Reading::Str(_)) && (num(a) - num(b)).abs() >= t {
                    g.next_send = 0;
                }
            }
            if m.metadata_last_sent == 0 {
                g.next_send = 0;
            }
        }
        g.collected_once = true;
        g.next_collect = if g.collect_once { i64::MAX } else { now + g.collect_every };
    }

    /// Queue a group's current values (and metadata when due).
    fn send(&mut self, gi: usize, now: Micros, out: &mut Vec<Msg>) {
        let host = self.host.clone();
        let interval = self.send_metadata_interval;
        let g = &mut self.groups[gi];
        for m in &mut g.metrics {
            let Some(r) = &m.now else { continue };
            let id = MetricId { host: host.name.clone(), name: m.spec.name.clone(), spoof: false };
            if m.metadata_last_sent == 0 || (interval != 0 && m.metadata_last_sent < now - interval) {
                out.push(Msg::MetadataFull { id: id.clone(), meta: m.spec.metadata() });
                m.metadata_last_sent = now;
            }
            let value = m.spec.encode(r);
            out.push(Msg::Value { id, fmt: m.spec.fmt.clone(), value });
        }
        g.next_send = now + g.time_threshold;
    }

    /// One pass of process_collection_groups: collect what is due, queue what
    /// must be sent into `out`, and return when to run next.
    pub fn tick(&mut self, now: Micros, out: &mut Vec<Msg>) -> Micros {
        for gi in 0..self.groups.len() {
            if self.groups[gi].next_collect <= now {
                self.collect(gi, now);
            }
        }
        for gi in 0..self.groups.len() {
            let g = &self.groups[gi];
            if g.collected_once && g.next_send <= now {
                self.send(gi, now, out);
            }
        }
        let next = self.groups.iter().map(|g| g.next_send.min(g.next_collect)).min().unwrap_or(now + USEC);
        if next < now { now + USEC } else { next }
    }
}

impl Scheduler {
    /// Apply queued messages as if they had arrived from our own address.
    pub fn deliver(&self, msgs: Vec<Msg>, now: Micros, store: &mut Store) {
        let name = self.host.name.clone();
        for m in msgs {
            store.handle(m, &self.host.ip, now, &mut |_| Some(name.clone()));
        }
    }
}
