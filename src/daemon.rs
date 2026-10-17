//! The running daemon: UDP receivers, the XML server, cleanup, and local collectors.

use crate::config::{Config, Listen};
use crate::proto::Msg;
use crate::store::{Followup, Store, now_micros};
use crate::xml::{self, XmlParams};
use anyhow::{Context, Result};
use log::{debug, info, warn};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;

pub struct Shared {
    pub store: Store,
    dns: HashMap<String, Option<String>>,
    /// Shadow mode: (our host key, names we collect) whose received copies are dropped.
    pub shadow_filter: Option<(String, std::collections::HashSet<String>)>,
}

pub type State = Arc<Mutex<Shared>>;

fn addr(l: &Listen) -> Result<SocketAddr> {
    let ip: IpAddr = l.bind.parse().with_context(|| format!("bad bind address {:?}", l.bind))?;
    Ok(SocketAddr::new(ip, l.port))
}

fn socket(a: SocketAddr, ty: Type, proto: Protocol) -> Result<Socket> {
    let s = Socket::new(Domain::for_address(a), ty, Some(proto))?;
    // Only for TCP (restart while old connections sit in TIME_WAIT). On UDP,
    // SO_REUSEADDR would let a second daemon bind the same port and silently
    // take over unicast datagrams meant for the first.
    if ty == Type::STREAM {
        s.set_reuse_address(true)?;
    }
    if a.is_ipv6() {
        // gmond binds separate inet4 and inet6 channels on the same port.
        s.set_only_v6(true)?;
    }
    s.set_nonblocking(true)?;
    s.bind(&a.into()).with_context(|| format!("binding {a}"))?;
    Ok(s)
}

/// gmond's apr_sockaddr_ip_buffer_get: v4-mapped v6 addresses print as plain v4.
pub fn ip_string(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(|v| v.to_string()).unwrap_or_else(|| v6.to_string()),
        v4 => v4.to_string(),
    }
}

fn resolve(dns: &mut HashMap<String, Option<String>>, ip: &str) -> Option<String> {
    dns.entry(ip.to_string())
        .or_insert_with(|| ip.parse::<IpAddr>().ok().and_then(|a| dns_lookup::lookup_addr(&a).ok()))
        .clone()
}

async fn udp_loop(sock: UdpSocket, state: State, max_len: usize, resend: mpsc::UnboundedSender<String>) {
    let mut buf = vec![0u8; max_len];
    loop {
        let (n, from) = match sock.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                warn!("udp recv: {e}");
                continue;
            }
        };
        let msg = match Msg::decode(&buf[..n]) {
            Ok(m) => m,
            Err(e) => {
                debug!("ignoring packet from {from}: {e}");
                continue;
            }
        };
        let ip = ip_string(from.ip());
        let follow = {
            let mut g = state.lock().unwrap();
            if let Some((host, names)) = &g.shadow_filter {
                let id = msg.id();
                if !id.spoof && &ip == host && names.contains(&crate::store::sanitize_metric_name(&id.name, false)) {
                    continue;
                }
            }
            let Shared { store, dns, .. } = &mut *g;
            store.handle(msg, &ip, now_micros(), &mut |ip| resolve(dns, ip))
        };
        match follow {
            Followup::ResendMetadata(name) => {
                let _ = resend.send(name);
            }
            // gmond would send this to its udp_send_channels. rgmond has no send
            // channels; gmetric re-sends metadata with every value, so nothing is lost.
            Followup::RequestMetadata(_) | Followup::None => {}
        }
    }
}

async fn tcp_loop(l: TcpListener, state: State, cfg: Arc<Config>) {
    let cluster = cfg.cluster();
    loop {
        let (mut conn, from) = match l.accept().await {
            Ok(c) => c,
            Err(e) => {
                warn!("tcp accept: {e}");
                continue;
            }
        };
        let g = &cfg.globals;
        let params = XmlParams {
            cluster: &cluster,
            tags: &g.tags,
            host_tmax: g.host_tmax,
            host_dmax: g.host_dmax,
            allow_extra_data: g.allow_extra_data,
        };
        let body = xml::render(&state.lock().unwrap().store, &params, now_micros());
        tokio::spawn(async move {
            if let Err(e) = conn.write_all(&body).await {
                debug!("writing XML to {from}: {e}");
            }
            let _ = conn.shutdown().await;
        });
    }
}

pub async fn run(cfg: Config) -> Result<()> {
    let cfg = Arc::new(cfg);
    let state: State =
        Arc::new(Mutex::new(Shared { store: Store::default(), dns: HashMap::new(), shadow_filter: None }));
    let (resend_tx, resend_rx) = mpsc::unbounded_channel();

    for l in &cfg.udp_recv {
        let a = addr(l)?;
        let s = socket(a, Type::DGRAM, Protocol::UDP)?;
        let sock = UdpSocket::from_std(s.into())?;
        info!("listening for metrics on udp {a}");
        tokio::spawn(udp_loop(sock, state.clone(), cfg.globals.max_udp_msg_len, resend_tx.clone()));
    }
    for l in &cfg.tcp_accept {
        let a = addr(l)?;
        let s = socket(a, Type::STREAM, Protocol::TCP)?;
        s.listen(128)?;
        let lst = TcpListener::from_std(s.into())?;
        info!("serving XML on tcp {a}");
        tokio::spawn(tcp_loop(lst, state.clone(), cfg.clone()));
    }

    {
        let state = state.clone();
        let every = cfg.globals.cleanup_threshold.max(1) as u64;
        let dmax = cfg.globals.host_dmax;
        tokio::spawn(async move {
            let mut t = tokio::time::interval(std::time::Duration::from_secs(every));
            loop {
                t.tick().await;
                state.lock().unwrap().store.cleanup(now_micros(), dmax);
            }
        });
    }

    if let Some(host) = &cfg.host {
        crate::collect::spawn(cfg.clone(), host.clone(), state.clone(), resend_rx)?;
    } else {
        drop(resend_rx);
    }
    if let Some(user) = &cfg.globals.user {
        drop_privileges(user)?;
    }

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    info!("shutting down");
    Ok(())
}

/// setgroups/setgid/setuid to `user` when running as root. Attached BPF
/// programs and already-open map and socket descriptors keep working; the
/// process keeps no capabilities afterwards.
fn drop_privileges(user: &str) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        info!("not root; staying uid {}", unsafe { libc::geteuid() });
        return Ok(());
    }
    let cname = std::ffi::CString::new(user)?;
    let pw = unsafe { libc::getpwnam(cname.as_ptr()) };
    anyhow::ensure!(!pw.is_null(), "no such user {user:?}");
    let (uid, gid) = unsafe { ((*pw).pw_uid, (*pw).pw_gid) };
    unsafe {
        anyhow::ensure!(libc::setgroups(1, &gid) == 0, "setgroups: {}", std::io::Error::last_os_error());
        anyhow::ensure!(libc::setgid(gid) == 0, "setgid: {}", std::io::Error::last_os_error());
        anyhow::ensure!(libc::setuid(uid) == 0, "setuid: {}", std::io::Error::last_os_error());
        anyhow::ensure!(libc::setuid(0) != 0, "still able to regain root after dropping privileges");
    }
    info!("dropped privileges to {user} (uid {uid}, gid {gid})");
    Ok(())
}
