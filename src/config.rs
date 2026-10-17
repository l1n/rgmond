//! rgmond configuration (TOML). One file per instance, mirroring one gmond.conf.

use crate::xml::Cluster;
use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub cluster: ClusterCfg,
    #[serde(default)]
    pub globals: Globals,
    /// Identity this daemon reports its own metrics under. Absent = aggregator only.
    pub host: Option<HostCfg>,
    #[serde(default)]
    pub udp_recv: Vec<Listen>,
    #[serde(default)]
    pub tcp_accept: Vec<Listen>,
    #[serde(default)]
    pub collectors: crate::collect::CollectorsCfg,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct ClusterCfg {
    pub name: Option<String>,
    pub owner: Option<String>,
    pub latlong: Option<String>,
    pub url: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct Globals {
    pub host_tmax: u32,
    pub host_dmax: u32,
    pub cleanup_threshold: u32,
    pub allow_extra_data: bool,
    pub send_metadata_interval: u32,
    pub tags: String,
    pub max_udp_msg_len: usize,
    /// Shadow mode, for running beside C gmond: ignore received packets for our
    /// own host and our locally collected metric names (C gmond's copies of
    /// them), while still accepting everything else (gmetric senders).
    pub shadow: bool,
    /// Drop to this user (and its primary group) once sockets are bound and
    /// BPF programs are attached, if started as root -- gmond's `setuid`.
    pub user: Option<String>,
}

impl Default for Globals {
    fn default() -> Self {
        // gmond's built-in defaults
        Globals {
            host_tmax: 20,
            host_dmax: 0,
            cleanup_threshold: 300,
            allow_extra_data: true,
            send_metadata_interval: 0,
            tags: String::new(),
            max_udp_msg_len: crate::proto::MAX_UDP_MSG_LEN,
            shadow: false,
            user: None,
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct HostCfg {
    /// NAME attribute in the XML (gmetad keys RRD directories on it).
    pub name: String,
    /// IP attribute in the XML.
    pub ip: String,
    pub location: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    /// Address to bind, e.g. "0.0.0.0" or "::".
    pub bind: String,
    pub port: u16,
}

impl Config {
    pub fn load(path: &str) -> Result<Config> {
        let s = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
        toml::from_str(&s).with_context(|| format!("parsing {path}"))
    }

    pub fn cluster(&self) -> Cluster {
        let c = &self.cluster;
        Cluster { name: c.name.clone(), owner: c.owner.clone(), latlong: c.latlong.clone(), url: c.url.clone() }
    }
}
