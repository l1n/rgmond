//! The XML dump gmond serves on its tcp_accept_channel (process_tcp_accept_channel).

use crate::printf::{self, Arg};
use crate::proto::{Value, slope_to_str};
use crate::store::{Host, Micros, Store, USEC, ValEntry, display_name};
use crate::xdr::latin1_encode;

pub const DTD: &str = include_str!("dtd.txt");
pub const GANGLIA_VERSION: &str = "3.7.2";

pub struct Cluster {
    pub name: Option<String>,
    pub owner: Option<String>,
    pub latlong: Option<String>,
    pub url: Option<String>,
}

pub struct XmlParams<'a> {
    pub cluster: &'a Cluster,
    pub tags: &'a str,
    pub host_tmax: u32,
    pub host_dmax: u32,
    pub allow_extra_data: bool,
}

/// gmond's xml_escape. For bytes outside 32..=126 gmond writes "&#" + two
/// digits computed as (ch/10, ch%10), which is only right below 100 and
/// produces garbage (from a sign-extended char) above 127. We write a correct
/// decimal entity instead; byte-identical for every control character.
pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if (c as u32) < 32 => out.push_str(&format!("&#{:02};", c as u32)),
            c if (c as u32) > 126 => out.push_str(&format!("&#{};", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// gmetric_value_to_str: strings are escaped, numbers go through the packet's fmt.
pub fn value_to_str(v: &ValEntry) -> String {
    match &v.value {
        Value::Str(s) => {
            let mut e = xml_escape(s);
            e.truncate(1024 - 7);
            e
        }
        Value::UShort(x) => printf::format(&v.fmt, Arg::UInt(*x as u64)),
        Value::Short(x) => printf::format(&v.fmt, Arg::Int(*x as i64)),
        Value::UInt(x) => printf::format(&v.fmt, Arg::UInt(*x as u64)),
        Value::Int(x) => printf::format(&v.fmt, Arg::Int(*x as i64)),
        Value::Float(x) => printf::format(&v.fmt, Arg::Float(*x as f64)),
        Value::Double(x) => printf::format(&v.fmt, Arg::Float(*x)),
    }
}

fn opt(v: &Option<String>) -> &str {
    v.as_deref().unwrap_or("unspecified")
}

fn host_xml(out: &mut String, h: &Host, p: &XmlParams, now: Micros) {
    out.push_str(&format!(
        "<HOST NAME=\"{}\" IP=\"{}\" TAGS=\"{}\" REPORTED=\"{}\" TN=\"{}\" TMAX=\"{}\" DMAX=\"{}\" LOCATION=\"{}\" GMOND_STARTED=\"{}\">\n",
        h.name,
        h.ip,
        p.tags,
        (h.last_heard / USEC) as i32,
        ((now - h.last_heard) / USEC) as i32,
        p.host_tmax,
        p.host_dmax,
        opt(&h.location),
        h.gmond_started,
    ));
    // gmond walks a hash table; any order is equivalent to gmetad. Sort for stable output.
    let mut names: Vec<&String> = h.metrics.keys().collect();
    names.sort();
    for name in names {
        let m = &h.metrics[name];
        let Some(v) = h.values.get(name) else { continue };
        let shown = display_name(&m.id);
        if shown.eq_ignore_ascii_case("heartbeat") || shown.eq_ignore_ascii_case("location") {
            continue;
        }
        out.push_str(&format!(
            "<METRIC NAME=\"{}\" VAL=\"{}\" TYPE=\"{}\" UNITS=\"{}\" TN=\"{}\" TMAX=\"{}\" DMAX=\"{}\" SLOPE=\"{}\">\n",
            shown,
            value_to_str(v),
            m.meta.type_,
            m.meta.units,
            ((now - v.last_heard) / USEC) as i32,
            m.meta.tmax,
            m.meta.dmax,
            slope_to_str(m.meta.slope),
        ));
        if p.allow_extra_data {
            out.push_str("<EXTRA_DATA>\n");
            for (k, val) in m.meta.extra.iter().rev() {
                out.push_str(&format!("<EXTRA_ELEMENT NAME=\"{k}\" VAL=\"{val}\"/>\n"));
            }
            out.push_str("</EXTRA_DATA>\n");
        }
        out.push_str("</METRIC>\n");
    }
    out.push_str("</HOST>\n");
}

/// Render the full dump as gmond would, encoded as ISO-8859-1 bytes.
pub fn render(store: &Store, p: &XmlParams, now: Micros) -> Vec<u8> {
    let mut out = String::with_capacity(64 * 1024);
    out.push_str(DTD);
    out.push_str(&format!("<GANGLIA_XML VERSION=\"{GANGLIA_VERSION}\" SOURCE=\"gmond\">\n"));
    let c = p.cluster;
    let cluster_tag = c.name.is_some() || c.owner.is_some() || c.latlong.is_some() || c.url.is_some();
    if cluster_tag {
        out.push_str(&format!(
            "<CLUSTER NAME=\"{}\" LOCALTIME=\"{}\" OWNER=\"{}\" LATLONG=\"{}\" URL=\"{}\">\n",
            opt(&c.name),
            (now / USEC) as i32,
            opt(&c.owner),
            opt(&c.latlong),
            opt(&c.url),
        ));
    }
    let mut hosts: Vec<&Host> = store.hosts.values().collect();
    hosts.sort_by(|a, b| (&a.name, &a.ip).cmp(&(&b.name, &b.ip)));
    for h in hosts {
        host_xml(&mut out, h, p, now);
    }
    if cluster_tag {
        out.push_str("</CLUSTER>\n");
    }
    out.push_str("</GANGLIA_XML>\n");
    latin1_encode(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_matches_gmond_for_ascii_and_controls() {
        assert_eq!(xml_escape("a<b>&\"'\t"), "a&lt;b&gt;&amp;&quot;&apos;&#09;");
    }
}
