mod collect;
mod config;
mod daemon;
mod docs;
mod pcap;
mod printf;
mod proto;
mod replay;
mod store;
mod xdr;
mod xml;

use anyhow::{Result, bail};

fn usage() -> ! {
    eprintln!("usage:");
    for (cmd, doc) in docs::COMMANDS {
        eprintln!("  {cmd}\n      {doc}");
    }
    std::process::exit(2)
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("replay") if args.len() >= 5 => {
            let cfg = config::Config::load(&args[1])?;
            let g = &cfg.globals;
            let ra = replay::ReplayArgs {
                pcap: args[2].clone(),
                xml_dir: args[3].clone(),
                port: args[4].parse()?,
                params: (cfg.cluster(), g.tags.clone(), g.host_tmax, g.host_dmax),
                warmup_secs: args.get(5).map(|s| s.parse()).transpose()?.unwrap_or(240),
            };
            let (n, bad, first) = replay::run(&ra)?;
            for l in &first {
                println!("{l}");
            }
            println!("compared {n} snapshots, {bad} with unexplained differences");
            if bad > 0 || n == 0 {
                bail!("replay mismatch");
            }
            Ok(())
        }
        Some("docs") if args.len() == 2 && matches!(args[1].as_str(), "readme" | "metrics") => {
            print!("{}", if args[1] == "readme" { docs::readme() } else { docs::metrics() });
            Ok(())
        }
        Some("dump") if args.len() == 3 => {
            // One line per decoded packet: ts, source ip, then the message as Debug.
            for p in pcap::read(&args[1])? {
                if p.dst_port.to_string() != args[2] {
                    continue;
                }
                match proto::Msg::decode(&p.payload) {
                    Ok(m) => println!("{}\t{}\t{:?}", p.ts_micros, daemon::ip_string(p.src), m),
                    Err(e) => println!("{}\t{}\tUNDECODABLE {e}", p.ts_micros, daemon::ip_string(p.src)),
                }
            }
            Ok(())
        }
        Some("-c") if args.len() == 2 => {
            let cfg = config::Config::load(&args[1])?;
            tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(daemon::run(cfg))
        }
        _ => usage(),
    }
}
