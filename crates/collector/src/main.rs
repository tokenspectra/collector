//! `collector`: run Flow assembly over capture files or a live dumpcap ring.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use collector::observe::{log_summary, StatsSink};
use collector::output::JsonlSink;
use collector::run::run;
use collector::ship::{self, Ingest, Shipper};
use collector::stats::{serve_metrics, Registry};
use collector::store::{StoreConfig, StoreSink};
use collector::{AssemblerConfig, DecoderConfig, FileSource, PacketSource, RingConfig, RingSource};

#[derive(Parser)]
#[command(about = "TokenSpectra Collector")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Don't keep HTTP bodies under <out>/bodies/; hashes and tables stay the same.
    #[arg(long, global = true)]
    no_bodies: bool,
    /// More log detail: -v for DEBUG (one line per Request Workunit and
    /// Flow), -vv for TRACE (reassembly).
    #[arg(short, long, action = ArgAction::Count, global = true)]
    verbose: u8,
    /// Less: -q for WARN, -qq for ERROR only.
    #[arg(short, long, action = ArgAction::Count, global = true, conflicts_with = "verbose")]
    quiet: u8,
    /// Log level; overrides -v/-q. RUST_LOG, when set, overrides both.
    #[arg(long, global = true, value_enum)]
    log_level: Option<Level>,
    /// Log line format on stdout.
    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,
    /// Serve Prometheus metrics at http://<addr>/metrics, e.g. 127.0.0.1:9464.
    #[arg(long, global = true)]
    metrics_addr: Option<String>,
    /// Object store root for L0 chunks, packs and Parquet index tables
    /// [default: <out>/store].
    #[arg(long, global = true)]
    store: Option<PathBuf>,
    /// The control plane's ingest, e.g. http://127.0.0.1:8090/ingest/windows:
    /// each window's manifest is POSTed there as the window is sealed.
    /// Without it, manifests stay in <out>/manifests.jsonl for `collector ship`.
    #[arg(long, global = true)]
    ingest: Option<String>,
    /// Seconds the shipper has, in all, to ship what is left at the end of
    /// a run, including a request in flight (lookup, connect, upload or
    /// response); lines it does not get to stay in the log.
    #[arg(long, global = true, default_value_t = 30)]
    ship_wait_s: u64,
    /// The `{site}` part of object keys.
    #[arg(long, global = true, default_value = "local")]
    site: String,
    /// The `{collector}` part of object keys.
    #[arg(long, global = true, default_value = "local")]
    collector_id: String,
    /// Capture Rate: share of Request Workunits whose packets L0 chunks keep
    /// in full (0 to 1). The rest are truncated; every byte is still hashed.
    #[arg(long, global = true, default_value_t = 1.0)]
    capture_rate: f64,
    /// 64 hex digits: the key each window's Capture Rate secret is derived
    /// from, until the control plane hands out secrets. Needed when
    /// --capture-rate is below 1.
    #[arg(long, global = true)]
    capture_key: Option<String>,
    /// Captured bytes left in a truncated packet.
    #[arg(long, global = true, default_value_t = 128)]
    truncate_to: u32,
    /// Captured bytes of alarm packets (unexplained, tls, opaque, grpc, UDP)
    /// kept in full per Flow per Slice; later ones are truncated.
    #[arg(long, global = true, default_value_t = 16 << 20)]
    alarm_cap: u64,
}

#[derive(Clone, Copy, ValueEnum)]
enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum LogFormat {
    Text,
    Json,
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
    /// Rebuild `by-exchange/` in an output directory from its `http.jsonl`
    /// and `bodies/`.
    Views {
        #[arg(default_value = "ts-captures")]
        out: PathBuf,
    },
    /// POST the manifests in an output directory's log that are not shipped
    /// yet to --ingest.
    Ship {
        #[arg(default_value = "ts-captures")]
        out: PathBuf,
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
        /// Kernel capture buffer in MiB (dumpcap `-B`); raise it if dumpcap
        /// reports drops on bursty traffic.
        #[arg(short = 'B', long)]
        buffer_mib: Option<u32>,
        #[arg(long, default_value = "dumpcap")]
        dumpcap: PathBuf,
        /// Output directory for the JSONL tables.
        #[arg(short, long, default_value = "ts-captures")]
        out: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(&cli);
    match real_main(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// Logs go to stdout. They are diagnostics, never part of the outputs.
fn init_logging(cli: &Cli) {
    let level = cli.log_level.unwrap_or(match (cli.verbose, cli.quiet) {
        (0, 0) => Level::Info,
        (1, _) => Level::Debug,
        (_, 0) => Level::Trace,
        (_, 1) => Level::Warn,
        _ => Level::Error,
    });
    let level = match level {
        Level::Error => "error",
        Level::Warn => "warn",
        Level::Info => "info",
        Level::Debug => "debug",
        Level::Trace => "trace",
    };
    let filter = match std::env::var("RUST_LOG") {
        Ok(v) if !v.trim().is_empty() => EnvFilter::new(v),
        _ => EnvFilter::new(level),
    };
    let fmt = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stdout)
        .with_target(false);
    match cli.log_format {
        LogFormat::Text => fmt.with_ansi(std::io::stdout().is_terminal()).init(),
        LogFormat::Json => fmt.json().flatten_event(true).init(),
    }
}

/// A 32-byte key from 64 hex digits.
fn parse_key(hex: &str) -> Result<[u8; 32], String> {
    let bad = || "--capture-key must be 64 hex digits".to_string();
    if hex.len() != 64 || !hex.is_ascii() {
        return Err(bad());
    }
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
    }
    Ok(key)
}

fn real_main(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let decoder_cfg = DecoderConfig {
        keep_bodies: !cli.no_bodies,
        ..DecoderConfig::default()
    };
    let mut dumpcap_pid = None;
    let ingest = cli.ingest.as_deref().map(Ingest::parse).transpose()?;
    let (mut source, window_s, out): (Box<dyn PacketSource>, u32, PathBuf) = match cli.cmd {
        Cmd::Files { window_s, out, files } => (Box::new(FileSource::new(files)), window_s, out),
        Cmd::Views { out } => {
            let s = collector::views::write(&out)?;
            info!(links = s.links, merged = s.merged, out = %out.display(), "views written");
            return Ok(());
        }
        Cmd::Ship { out } => {
            let ingest = ingest.ok_or("`collector ship` needs --ingest")?;
            let s = ship::ship_pending(&out, &ingest, Duration::from_secs(10))?;
            // No deadline here, so the count is always known.
            info!(
                sent = s.sent,
                pending = s.pending.unwrap_or_default(),
                "manifests shipped"
            );
            return Ok(());
        }
        Cmd::Ring {
            window_s,
            interface,
            ring_dir,
            duration_s,
            filter,
            buffer_mib,
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
                cfg.extra_args.extend(["-f".into(), f]);
            }
            if let Some(b) = buffer_mib {
                cfg.extra_args.extend(["-B".into(), b.to_string()]);
            }
            let ring = RingSource::spawn(&cfg)?;
            dumpcap_pid = ring.pid();
            (Box::new(ring), window_s, out)
        }
    };
    if window_s == 0 {
        return Err("window must be positive".into());
    }
    let window_ns = u64::from(window_s) * 1_000_000_000;
    let mut store_cfg = StoreConfig::new(window_ns);
    store_cfg.site = cli.site.clone();
    store_cfg.collector = cli.collector_id.clone();
    store_cfg.capture.rate = cli.capture_rate;
    store_cfg.capture.truncate_to = cli.truncate_to;
    store_cfg.capture.alarm_cap_bytes = cli.alarm_cap;
    store_cfg.capture.key = cli.capture_key.as_deref().map(parse_key).transpose()?;
    if !(0.0..=1.0).contains(&cli.capture_rate) {
        return Err("--capture-rate must be between 0 and 1".into());
    }
    if cli.capture_rate < 1.0 && store_cfg.capture.key.is_none() {
        return Err("--capture-rate below 1 needs --capture-key: the draw must be unpredictable".into());
    }
    std::fs::create_dir_all(&out)?;
    let store_dir = cli.store.clone().unwrap_or_else(|| out.join("store"));
    std::fs::create_dir_all(&store_dir)?;
    let object_store = Arc::new(collector::store::local(&store_dir)?);
    let registry = Registry::new();
    if let Some(addr) = &cli.metrics_addr {
        let bound = serve_metrics(addr.as_str(), registry.clone())
            .map_err(|e| format!("--metrics-addr {addr}: {e}"))?;
        info!(url = %format_args!("http://{bound}/metrics"), "serving metrics");
    }
    #[cfg(unix)]
    let _triggers = match collector::observe::triggers::spawn(
        registry.clone(),
        cli.log_format == LogFormat::Json,
        dumpcap_pid,
    ) {
        Ok(t) => {
            tracing::debug!(
                keys = t.keys,
                "snapshot on SIGUSR1, and on `s` or Enter with keys"
            );
            Some(t)
        }
        Err(e) => {
            warn!(error = %e, "no snapshot triggers");
            None
        }
    };
    let mut sink = JsonlSink::create(&out)?;
    let shipper = ingest
        .map(|i| Shipper::spawn(out.clone(), i, Duration::from_secs(1)))
        .transpose()?;
    let mut store = StoreSink::new(&mut sink, object_store, store_cfg, Some(registry.clone()));
    run(
        source.as_mut(),
        window_ns,
        AssemblerConfig::default(),
        decoder_cfg,
        &mut StatsSink::new(&mut store, registry.clone()),
    )?;
    let stored = store.finish()?;
    sink.finish()?;
    info!(
        store = %store_dir.display(),
        chunks = stored.chunks,
        packs = stored.packs,
        index_files = stored.index_files,
        "object store written"
    );
    // Views for people, derived from the tables and bodies just written.
    if !cli.no_bodies {
        collector::views::write(&out)?;
    }
    if let Some(shipper) = shipper {
        ship::log_outcome(&shipper.finish(Duration::from_secs(cli.ship_wait_s)), &out);
    }
    log_summary(&registry.snapshot(), &out);
    Ok(())
}
