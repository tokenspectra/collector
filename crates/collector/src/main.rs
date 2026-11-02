//! `collector`: run Flow assembly over capture files or a live dumpcap ring.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use collector::output::JsonlSink;
use collector::run::run;
use collector::{AssemblerConfig, FileSource, PacketSource, RingConfig, RingSource};

#[derive(Parser)]
#[command(about = "TokenSpectra Collector")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Assemble Flows from .pcap/.pcapng files, read in the order given.
    Files {
        /// Window (Slice) length in seconds.
        #[arg(short, long, default_value_t = 10)]
        window_s: u32,
        /// Output directory for the JSONL tables.
        #[arg(short, long, default_value = "ts-captures")]
        out: PathBuf,
        files: Vec<PathBuf>,
    },
    /// Capture live with a dumpcap ring buffer and assemble Flows.
    Ring {
        /// Window (Slice) length in seconds; also dumpcap's `-b interval`.
        #[arg(short, long, default_value_t = 10)]
        window_s: u32,
        #[arg(short, long)]
        interface: String,
        /// Directory for dumpcap's ring files [default: <tmp>/tokenspectra-ring-<interface>].
        #[arg(short = 'd', long)]
        ring_dir: Option<PathBuf>,
        /// Stop after this many seconds.
        #[arg(short = 't', long)]
        duration_s: Option<u32>,
        /// Capture filter (dumpcap `-f`).
        #[arg(short, long)]
        filter: Option<String>,
        #[arg(long, default_value = "dumpcap")]
        dumpcap: PathBuf,
        /// Output directory for the JSONL tables.
        #[arg(short, long, default_value = "ts-captures")]
        out: PathBuf,
    },
}

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("collector: {e}");
            ExitCode::FAILURE
        }
    }
}

fn real_main() -> Result<(), Box<dyn std::error::Error>> {
    let (mut source, window_s, out): (Box<dyn PacketSource>, u32, PathBuf) = match Cli::parse().cmd {
        Cmd::Files { window_s, out, files } => (Box::new(FileSource::new(files)), window_s, out),
        Cmd::Ring {
            window_s,
            interface,
            ring_dir,
            duration_s,
            filter,
            dumpcap,
            out,
        } => {
            let ring_dir = ring_dir
                .unwrap_or_else(|| std::env::temp_dir().join(format!("tokenspectra-ring-{interface}")));
            std::fs::create_dir_all(&ring_dir)?;
            let mut cfg = RingConfig::new(interface, window_s, ring_dir);
            cfg.autostop_s = duration_s;
            cfg.dumpcap = dumpcap;
            if let Some(f) = filter {
                cfg.extra_args = vec!["-f".into(), f];
            }
            (Box::new(RingSource::spawn(&cfg)?), window_s, out)
        }
    };
    if window_s == 0 {
        return Err("window must be positive".into());
    }
    std::fs::create_dir_all(&out)?;
    let mut sink = JsonlSink::create(&out)?;
    let summary = run(
        source.as_mut(),
        u64::from(window_s) * 1_000_000_000,
        AssemblerConfig::default(),
        &mut sink,
    )?;
    sink.finish()?;
    eprintln!(
        "collector: {} packets, {} windows -> {}",
        summary.packets,
        summary.windows,
        out.display()
    );
    Ok(())
}
