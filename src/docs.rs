//! Generates README.md and docs/metrics.md from the code, so the documentation
//! cannot drift from what the program does. `rgmond docs readme` and
//! `rgmond docs metrics` print them; tests fail when the committed files differ.
//!
//! Prose here is written in a neutral, descriptive register: what the program
//! is and does, without evaluative or promotional language.

use crate::collect::spec::{self, MetricSpec};
use crate::config::Globals;
use std::fmt::Write;

/// Command-line forms: (synopsis, description). `usage()` prints these too.
pub const COMMANDS: &[(&str, &str)] = &[
    ("rgmond -c CONFIG", "Run the daemon with the given TOML configuration."),
    (
        "rgmond replay CONFIG PCAP XMLDIR PORT [WARMUP_SECS]",
        "Feed UDP packets captured from a gmond deployment through rgmond's metric store and compare the resulting XML with the dumps gmond served at the same moments. Used to verify protocol compatibility.",
    ),
    ("rgmond dump PCAP PORT", "Decode the gmond packets in a capture file, one per line."),
    ("rgmond docs readme|metrics", "Print this README or the metric reference, generated from the program."),
];

/// One documented configuration key.
pub struct Key {
    pub section: &'static str,
    pub key: &'static str,
    pub ty: &'static str,
    pub doc: &'static str,
}

/// Every configuration key. Checked against the configuration structs by
/// `keys_match_config_structs`, so a field cannot be added or renamed without
/// documenting it here.
pub const KEYS: &[Key] = &[
    Key { section: "cluster", key: "name", ty: "string", doc: "Cluster name in the XML `CLUSTER` element. gmetad names its RRD directories after it." },
    Key { section: "cluster", key: "owner", ty: "string", doc: "`OWNER` attribute of the `CLUSTER` element." },
    Key { section: "cluster", key: "latlong", ty: "string", doc: "`LATLONG` attribute of the `CLUSTER` element." },
    Key { section: "cluster", key: "url", ty: "string", doc: "`URL` attribute of the `CLUSTER` element." },
    Key { section: "globals", key: "host_tmax", ty: "integer", doc: "`TMAX` reported for every host, in seconds." },
    Key { section: "globals", key: "host_dmax", ty: "integer", doc: "Seconds after which a silent host is removed; 0 keeps hosts indefinitely." },
    Key { section: "globals", key: "cleanup_threshold", ty: "integer", doc: "Interval, in seconds, between sweeps that remove expired hosts and metrics." },
    Key { section: "globals", key: "allow_extra_data", ty: "boolean", doc: "Whether `EXTRA_DATA` elements (group, title, description) are included in the XML." },
    Key { section: "globals", key: "send_metadata_interval", ty: "integer", doc: "Seconds between repeated metadata for local metrics; 0 sends it only once and on request." },
    Key { section: "globals", key: "tags", ty: "string", doc: "`TAGS` attribute reported for every host." },
    Key { section: "globals", key: "max_udp_msg_len", ty: "integer", doc: "Largest UDP datagram read, in bytes." },
    Key { section: "globals", key: "shadow", ty: "boolean", doc: "Shadow mode, for running alongside gmond on a duplicated packet stream: received copies of the metrics rgmond collects locally are ignored." },
    Key { section: "globals", key: "user", ty: "string", doc: "User to switch to after sockets are bound and BPF programs are attached, when started as root." },
    Key { section: "host", key: "name", ty: "string", doc: "`NAME` of the host entry for locally collected metrics. Omit the `[host]` table to run as an aggregator only." },
    Key { section: "host", key: "ip", ty: "string", doc: "`IP` of that host entry, and the key under which it is stored. Packets from this address (such as from gmetric on the same machine) join the same entry." },
    Key { section: "host", key: "location", ty: "string", doc: "Value reported as the host's `LOCATION`." },
    Key { section: "udp_recv", key: "bind", ty: "string", doc: "Address for a UDP receive socket, such as `0.0.0.0` or `::`. IPv6 sockets are IPv6-only, so both families can share a port." },
    Key { section: "udp_recv", key: "port", ty: "integer", doc: "Port of that socket." },
    Key { section: "tcp_accept", key: "bind", ty: "string", doc: "Address on which the XML dump is served." },
    Key { section: "tcp_accept", key: "port", ty: "integer", doc: "Port on which the XML dump is served." },
    Key { section: "collectors.group", key: "collect_once", ty: "boolean", doc: "Collect the group's metrics only at startup." },
    Key { section: "collectors.group", key: "collect_every", ty: "integer", doc: "Seconds between collections." },
    Key { section: "collectors.group", key: "time_threshold", ty: "integer", doc: "Maximum seconds between sends of the group's values." },
    Key { section: "collectors.group", key: "metric", ty: "array of tables", doc: "The metrics in the group (see below)." },
    Key { section: "collectors.group.metric", key: "name", ty: "string", doc: "Exact metric name." },
    Key { section: "collectors.group.metric", key: "name_match", ty: "string", doc: "Regular expression matched against whole metric names, instead of `name`." },
    Key { section: "collectors.group.metric", key: "value_threshold", ty: "number", doc: "Send the group immediately when this metric changes by at least this amount." },
    Key { section: "collectors.params.MODULE", key: "(module-specific)", ty: "string", doc: "Enables a collector module and sets its parameters; an empty table enables it with defaults." },
];

const LEAD: &str = "\
**rgmond** is a monitoring daemon for Linux, written in Rust, that implements the \
network protocols of the [Ganglia](https://en.wikipedia.org/wiki/Ganglia_(software)) \
monitoring agent *gmond* (version 3.7). It receives metric packets over UDP in gmond's \
XDR-based format, serves the cluster state as gmond's XML document over TCP, and collects \
the same local metrics as gmond's built-in modules and its standard Python modules. \
Existing Ganglia components, including the aggregator *gmetad*, the *ganglia-web* \
front end and the *gmetric* command-line tool, interoperate with it without changes.

In addition to gmond's metrics, rgmond reports metrics derived from extended Berkeley \
Packet Filter ([eBPF](https://en.wikipedia.org/wiki/EBPF)) tracepoint programs, Linux \
[pressure stall information](https://docs.kernel.org/accounting/psi.html) and \
[cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html) accounting, under metric \
names gmond does not use.";

const DESIGN: &str = "\
## Design

rgmond runs as a single process. Its components are:

- **Receivers**, one UDP socket per `[[udp_recv]]` entry, which decode gmond metadata, \
value and metadata-request messages and apply them to the metric store using gmond's \
rules: hosts are keyed by sender address (or by the address given in a spoofed host), \
metadata and values are stored per metric, and a value without metadata prompts a \
metadata request.
- **The metric store**, which expires hosts after `host_dmax` seconds of silence and \
metrics after their own `DMAX`.
- **The XML server**, which writes the store as gmond's XML document, including its \
document type definition, to each TCP client and closes the connection.
- **Collectors**, which read local system state. Collection groups follow gmond's \
scheduling: each group is collected every `collect_every` seconds and sent when \
`time_threshold` expires, when a value moves by its `value_threshold`, or when a peer \
requests metadata. Locally collected values are written directly to the store rather \
than sent to the daemon's own UDP socket, as gmond does.

When started as root, rgmond binds its sockets and attaches its BPF programs, then \
changes to the configured `user` and keeps no capabilities. BPF programs read \
tracepoint fields at fixed offsets and use no BPF Type Format (BTF) data, so they load \
on kernels built without BTF. Before loading, each program's field offsets are compared \
with the kernel's tracepoint format descriptions; a program whose layout differs, or \
that cannot be loaded, is skipped and its metrics are not reported.";

const COMPAT: &str = "\
## Compatibility with gmond

rgmond is intended to be indistinguishable from gmond to gmetad. Metric names, types, \
units, slopes, `TMAX`/`DMAX` values and extra data are taken from gmond's own traffic \
and are listed in the metric reference. Several of gmond's behaviours are reproduced \
because they are visible in its output:

- Numeric values are formatted with the semantics of the Apache Portable Runtime's \
`apr_snprintf`, which gmond uses, rather than the C library's `printf`. The two differ \
for values exactly halfway between two representations: APR rounds `1116625.625` to \
`1116625.63` with `%.2f`, where glibc produces `1116625.62`.
- In received metric names, only `:` is replaced (by `_`), which is the effect of the \
condition in gmond's name sanitiser.
- `EXTRA_ELEMENT` entries are written in reverse order of receipt.

Two behaviours differ from gmond. Characters above code point 126 in string values are \
written as numeric character references, where gmond writes a malformed two-digit \
form. Heartbeats sent as strings, which is how gmetric sends them, set \
`GMOND_STARTED` to the number they contain, where gmond stores part of a pointer.

The program was checked against captured gmond traffic: replaying the packets through \
rgmond reproduced gmond's XML for every metric, apart from metrics gmond itself had \
not received because its operating system dropped some of the UDP packets it sent to \
itself.";

const BUILDING: &str = "\
## Building and testing

Building requires a Rust toolchain and Clang, which compiles the BPF programs in \
`bpf/rgmond.bpf.c` during the build.

    cargo build --release
    cargo test

Tests marked `#[ignore]` compare each ported Python module with the original while \
both sample the running system. They need a Python 3 copy of gmond's \
`python_modules` tree, located through the `RGMOND_PY_MODULES` environment variable \
(default `/usr/lib/ganglia/python_modules`), and are run with \
`cargo test -- --ignored`. The BPF test needs root.

README.md and docs/metrics.md are generated by the program; `cargo test` fails if \
either differs from the generated text. Regenerate them with:

    cargo run -- docs readme > README.md
    cargo run -- docs metrics > docs/metrics.md";

const LICENSE: &str = "\
## License

rgmond is distributed under the BSD 3-Clause License (see `LICENSE`). The XML document \
type definition and protocol definitions it reproduces come from Ganglia, which uses \
the same license. The BPF programs are dual-licensed under the GPL version 2 and the \
BSD 3-Clause License, as the Linux kernel requires a GPL-compatible license for them.";

fn md_escape(s: &str) -> String {
    s.replace('|', "\\|")
}

/// Field names of a struct, from its derived `Debug` output.
pub fn debug_fields(debug: &str) -> Vec<String> {
    let inner = debug.split_once('{').map(|(_, r)| r).unwrap_or("");
    let mut out = vec![];
    let mut depth = 0i32;
    let mut cur = String::new();
    for ch in inner.chars() {
        match ch {
            '{' | '[' | '(' => depth += 1,
            '}' | ']' | ')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && ch == ':' {
            out.push(cur.trim().trim_start_matches(',').trim().to_string());
            cur.clear();
        } else if depth == 0 && ch == ',' {
            cur.clear();
        } else {
            cur.push(ch);
        }
    }
    out
}

/// Field values of a struct's `Debug` output, in order.
fn debug_values(debug: &str) -> Vec<String> {
    let inner = debug.split_once('{').map(|(_, r)| r).unwrap_or("").trim_end_matches('}');
    let mut out = vec![];
    let mut depth = 0i32;
    let mut cur = String::new();
    let mut in_val = false;
    for ch in inner.chars() {
        match ch {
            '{' | '[' | '(' => depth += 1,
            '}' | ']' | ')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && ch == ':' && !in_val {
            in_val = true;
            cur.clear();
        } else if depth == 0 && ch == ',' {
            out.push(cur.trim().to_string());
            cur.clear();
            in_val = false;
        } else if in_val {
            cur.push(ch);
        }
    }
    if in_val {
        out.push(cur.trim().to_string());
    }
    out
}

fn globals_defaults() -> Vec<(String, String)> {
    let d = format!("{:?}", Globals::default());
    debug_fields(&d)
        .into_iter()
        .zip(debug_values(&d))
        .map(|(k, v)| {
            let v = match v.as_str() {
                "None" => "unset".to_string(),
                "\"\"" => "empty".to_string(),
                _ => format!("`{}`", v.trim_matches('"')),
            };
            (k, v)
        })
        .collect()
}

fn usage_section() -> String {
    let mut s = String::from("## Usage\n\n| Command | Description |\n| --- | --- |\n");
    for (cmd, doc) in COMMANDS {
        let _ = writeln!(s, "| `{}` | {} |", md_escape(cmd), md_escape(doc));
    }
    s
}

fn config_section() -> String {
    let defaults = globals_defaults();
    let mut s = String::from(
        "## Configuration\n\nEach instance reads one TOML file. The tables and keys are:\n\n\
         | Table | Key | Type | Default | Description |\n| --- | --- | --- | --- | --- |\n",
    );
    for k in KEYS {
        let def = if k.section == "globals" {
            defaults.iter().find(|(n, _)| n == k.key).map(|(_, v)| v.clone()).unwrap_or_default()
        } else {
            String::new()
        };
        let _ = writeln!(s, "| `{}` | `{}` | {} | {} | {} |", k.section, k.key, k.ty, def, md_escape(k.doc));
    }
    s.push_str(
        "\n`[[udp_recv]]`, `[[tcp_accept]]`, `[[collectors.group]]` and `[[collectors.group.metric]]` \
         are arrays of tables. The `rgmond-import-gmond-conf` script (`tools/convert_conf.py`) \
         translates a gmond configuration, including its Python module files, into the \
         `[collectors]` part of this format.\n",
    );
    s
}

fn collectors_section() -> String {
    let mut s = String::from(
        "## Collectors\n\nThe `core` collector, which provides gmond's built-in metrics, is always enabled. \
         Other modules are enabled by a `[collectors.params.MODULE]` table.\n\n\
         | Module | Description |\n| --- | --- |\n",
    );
    for (name, doc) in crate::collect::MODULES {
        let _ = writeln!(s, "| `{name}` | {} |", md_escape(doc));
    }
    s.push_str("\nThe `bpf` module provides these features, selected by its `features` parameter:\n\n| Feature | Kernel events | Description |\n| --- | --- | --- |\n");
    for (name, events, doc) in crate::collect::bpf::feature_docs() {
        let _ = writeln!(s, "| `{name}` | {} | {} |", events.join(", "), md_escape(doc));
    }
    s
}

fn group_of(m: &MetricSpec) -> &str {
    m.extra.iter().find(|(k, _)| k == "GROUP").map(|(_, v)| v.as_str()).unwrap_or("")
}

fn desc_of(m: &MetricSpec) -> String {
    m.extra.iter().find(|(k, _)| k == "DESC").map(|(_, v)| v.replace("{mount}", "MOUNT").replace("{}", "X")).unwrap_or_default()
}

fn metrics_summary() -> String {
    // group -> (definitions, any from gmond, any new in rgmond)
    let mut groups: std::collections::BTreeMap<String, (usize, bool, bool)> = Default::default();
    for (m, new) in spec::documented() {
        let e = groups.entry(group_of(&m).to_string()).or_insert((0, false, false));
        e.0 += 1;
        if new { e.2 = true } else { e.1 = true }
    }
    let mut s = String::from(
        "## Metrics\n\nMetric definitions by group. Entries whose names contain `{}` are \
         families with one metric per device, interface, mount, port, process or unit. \
         The full list is in [docs/metrics.md](docs/metrics.md).\n\n\
         | Group | Definitions | Origin |\n| --- | --- | --- |\n",
    );
    for (g, (n, old, new)) in groups {
        let origin = match (old, new) {
            (true, true) => "gmond, rgmond",
            (false, true) => "rgmond",
            _ => "gmond",
        };
        let _ = writeln!(s, "| {g} | {n} | {origin} |");
    }
    s
}

pub fn readme() -> String {
    let mut s = String::from("# rgmond\n\n<!-- Generated by `rgmond docs readme` from src/docs.rs and the code it reads. Do not edit. -->\n\n");
    for part in [LEAD.to_string(), DESIGN.to_string(), COMPAT.to_string(), usage_section(), config_section(), collectors_section(), metrics_summary(), BUILDING.to_string(), LICENSE.to_string()] {
        s.push_str(part.trim_end());
        s.push_str("\n\n");
    }
    s.trim_end().to_string() + "\n"
}

pub fn metrics() -> String {
    let mut s = String::from(
        "# rgmond metric reference\n\n<!-- Generated by `rgmond docs metrics` from src/collect/spec*.toml. Do not edit. -->\n\n\
         Metadata rgmond sends for each metric. In names, `{}` stands for a device, interface, \
         mount, port, process or unit name; in descriptions it is shown as X, and MOUNT is the \
         mount point. Metrics of origin *gmond* reproduce gmond 3.7's metadata; metrics of \
         origin *rgmond* are additions.\n\n\
         | Name | Group | Type | Units | Origin | Description |\n| --- | --- | --- | --- | --- | --- |\n",
    );
    let mut all = spec::documented();
    all.sort_by(|(a, _), (b, _)| (group_of(a), &a.name).cmp(&(group_of(b), &b.name)));
    for (m, new) in all {
        let _ = writeln!(
            s,
            "| `{}` | {} | {} | {} | {} | {} |",
            m.name,
            group_of(&m),
            m.type_,
            md_escape(m.units.trim()),
            if new { "rgmond" } else { "gmond" },
            md_escape(&desc_of(&m))
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClusterCfg, HostCfg, Listen};

    fn fields_of(section: &str) -> Vec<&'static str> {
        KEYS.iter().filter(|k| k.section == section).map(|k| k.key).collect()
    }

    #[test]
    fn keys_match_config_structs() {
        let cases: Vec<(&str, String)> = vec![
            ("cluster", format!("{:?}", ClusterCfg::default())),
            ("globals", format!("{:?}", Globals::default())),
            ("host", format!("{:?}", HostCfg { name: String::new(), ip: String::new(), location: None })),
            ("udp_recv", format!("{:?}", Listen { bind: String::new(), port: 0 })),
            ("tcp_accept", format!("{:?}", Listen { bind: String::new(), port: 0 })),
            (
                "collectors.group",
                format!("{:?}", crate::collect::GroupCfg { collect_once: false, collect_every: 0, time_threshold: 0, metric: vec![] }),
            ),
            (
                "collectors.group.metric",
                format!("{:?}", crate::collect::MetricSel { name: None, name_match: None, value_threshold: None }),
            ),
        ];
        for (section, debug) in cases {
            let mut want = debug_fields(&debug);
            let mut have: Vec<String> = fields_of(section).iter().map(|s| s.to_string()).collect();
            want.sort();
            have.sort();
            assert_eq!(have, want, "documented keys of [{section}] differ from the struct");
        }
    }

    #[test]
    fn readme_is_current() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/README.md");
        let committed = std::fs::read_to_string(path).unwrap_or_default();
        assert!(committed == readme(), "README.md is stale: run `cargo run -- docs readme > README.md`");
    }

    #[test]
    fn metrics_doc_is_current() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/metrics.md");
        let committed = std::fs::read_to_string(path).unwrap_or_default();
        assert!(committed == metrics(), "docs/metrics.md is stale: run `cargo run -- docs metrics > docs/metrics.md`");
    }
}
