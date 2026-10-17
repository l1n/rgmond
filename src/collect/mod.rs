//! Local metric collectors and the collection-group scheduler that sends
//! their values into the store, following gmond's collect/send rules.

use serde::Deserialize;

pub mod bpf;
pub mod core;
pub mod cpu_stats;
pub mod entropy;
pub mod mem_stats;
pub mod multi_interface;
pub mod netstats;
pub mod pressure;
pub mod sched;
pub mod spec;
pub mod units;
pub mod diskfree;
pub mod diskstat;
pub mod procstat;
pub mod vm_stats;

/// A value read from the system, before it is encoded as the metric's wire type.
#[derive(Clone, Debug, PartialEq)]
pub enum Reading {
    Num(f64),
    Str(String),
}

/// One family of metrics (a port of one gmond module or Python module).
///
/// The scheduler calls `sample` once per collection of a group that contains
/// any of this source's metrics, then `value` for each of them. Sources that
/// compute rates keep their previous sample and divide by the elapsed time,
/// with the same caching rules as the module they replace.
pub trait Source: Send {
    /// Short name for logs, e.g. "netstats".
    fn name(&self) -> &'static str;
    /// Metric names this source produces (fixed after construction).
    fn names(&self) -> Vec<String>;
    /// Refresh state from the system. `now` is seconds since the epoch.
    fn sample(&mut self, now: f64);
    /// Like `sample`, told which of this source's metrics the collecting group
    /// wants. Sources whose rates must not be disturbed by other groups (gmond's
    /// per-metric statics in libmetrics) override this.
    fn sample_for(&mut self, now: f64, _names: &[&str]) {
        self.sample(now);
    }
    /// The latest value for one of `names()`; None if unavailable this round.
    fn value(&self, name: &str) -> Option<Reading>;
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct CollectorsCfg {
    #[serde(default)]
    pub group: Vec<GroupCfg>,
    /// Per-source parameters, as in each .pyconf `param` block.
    #[serde(default)]
    pub params: std::collections::BTreeMap<String, toml::Table>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct GroupCfg {
    #[serde(default)]
    pub collect_once: bool,
    #[serde(default)]
    pub collect_every: u32,
    pub time_threshold: u32,
    pub metric: Vec<MetricSel>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct MetricSel {
    pub name: Option<String>,
    pub name_match: Option<String>,
    pub value_threshold: Option<f64>,
}

use crate::config::{Config, HostCfg};
use crate::daemon::State;
use crate::store::{USEC, now_micros};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Collector modules a configuration can enable, with descriptions (used by
/// `rgmond docs`). `build_sources` constructs exactly these.
pub const MODULES: &[(&str, &str)] = &[
    ("cpu_stats", "Port of gmond's cpu_stats.py: context switches, interrupts, forks, blocked processes and softirq rates from /proc/stat."),
    ("diskfree", "Port of diskfree.py: free space, absolute and percentage, for each local mount."),
    ("diskstat", "Port of diskstat.py: per-disk reads, writes, merges, bytes and I/O time from /proc/diskstats."),
    ("entropy", "Port of entropy.py: the kernel's available entropy."),
    ("mem_stats", "Port of mem_stats.py: selected /proc/meminfo fields in bytes."),
    ("multi_interface", "Port of multi_interface.py: per-interface byte, packet, error and drop rates, read over rtnetlink (RTM_GETLINK, IFLA_STATS64) instead of /proc/net/dev."),
    ("netstats", "Port of netstats.py: TCP, UDP and IP counters from /proc/net/netstat and /proc/net/snmp as rates and percentages."),
    ("procstat", "Port of procstat.py: CPU and memory use of a process group selected by an awk-style regular expression or pid file."),
    ("vm_stats", "Port of vm_stats.py: paging and fault rates from /proc/vmstat."),
    ("bpf", "Metrics from eBPF tracepoint programs (see below). Not part of gmond."),
    ("pressure", "Pressure stall information: the share of time tasks waited for CPU, memory, I/O or IRQ. Not part of gmond."),
    ("units", "Per-systemd-unit CPU, memory and task counts from cgroup v2. Not part of gmond."),
];

fn params(cfg: &CollectorsCfg, module: &str) -> toml::Table {
    cfg.params.get(module).cloned().unwrap_or_default()
}

/// Construct every source this config uses. A module is enabled when it has a
/// `[collectors.params.<module>]` table (possibly empty); core is always on.
pub fn build_sources(cfg: &Config, host: &HostCfg, started: u32) -> anyhow::Result<Vec<Box<dyn Source>>> {
    let c = &cfg.collectors;
    let mut v: Vec<Box<dyn Source>> = vec![Box::new(core::Core::new(started, host.location.clone()))];
    for module in c.params.keys() {
        let p = params(c, module);
        let s: Box<dyn Source> = match module.as_str() {
            "cpu_stats" => Box::new(cpu_stats::CpuStats::new(&p)?),
            "diskfree" => Box::new(diskfree::Diskfree::new(&p)?),
            "diskstat" => Box::new(diskstat::Diskstat::new(&p)?),
            "entropy" => Box::new(entropy::Entropy::new(&p)?),
            "mem_stats" => Box::new(mem_stats::MemStats::new(&p)?),
            "multi_interface" => Box::new(multi_interface::MultiInterface::from_params(&p)?),
            "netstats" => Box::new(netstats::Netstats::new()?),
            "procstat" => Box::new(procstat::Procstat::new(&p)?),
            "vm_stats" => Box::new(vm_stats::VmStats::new(&p)?),
            // New in rgmond. A failure here (no BPF privileges, no PSI) must
            // not stop the gmond-compatible metrics, so it only warns.
            "bpf" | "pressure" | "units" => {
                let made: anyhow::Result<Box<dyn Source>> = match module.as_str() {
                    "bpf" => bpf::Bpf::new(&p).map(|s| Box::new(s) as Box<dyn Source>),
                    "pressure" => pressure::Pressure::new(&p).map(|s| Box::new(s) as Box<dyn Source>),
                    _ => units::Units::new(&p).map(|s| Box::new(s) as Box<dyn Source>),
                };
                match made {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!("collector {module} disabled: {e:#}");
                        continue;
                    }
                }
            }
            other => anyhow::bail!(
                "unknown collector module {other:?} (known: {})",
                MODULES.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
            ),
        };
        log::info!("collector {} provides {} metrics", s.name(), s.names().len());
        v.push(s);
    }
    Ok(v)
}

/// Start the local collectors: one task running the collection-group loop.
pub fn spawn(
    cfg: Arc<Config>,
    host: HostCfg,
    state: State,
    mut resend: mpsc::UnboundedReceiver<String>,
) -> anyhow::Result<()> {
    let started = (now_micros() / USEC) as u32;
    let sources = build_sources(&cfg, &host, started)?;
    let host_ip = host.ip.clone();
    let mut sched = sched::Scheduler::new(sources, &cfg.collectors.group, host, cfg.globals.send_metadata_interval)?;
    if cfg.globals.shadow {
        let names = sched.names();
        log::info!("shadow mode: ignoring received copies of our {} local metrics", names.len());
        state.lock().unwrap().shadow_filter = Some((host_ip, names));
    }
    tokio::spawn(async move {
        loop {
            let now = now_micros();
            let mut out = vec![];
            let next = sched.tick(now, &mut out);
            sched.deliver(out, now, &mut state.lock().unwrap().store);
            let wait = std::time::Duration::from_micros((next - now_micros()).max(0) as u64);
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                Some(name) = resend.recv() => sched.request_metadata(&name),
            }
        }
    });
    Ok(())
}
